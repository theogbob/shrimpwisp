//! Per-stream proxy state and stream table.
//!
//! Design:
//! - Vec<Option<ProxyStream>> for O(1) direct-index lookup by stream ID
//! - Zero hash computation on the DATA hot path (stream IDs are small sequential integers)
//! - TCP streams: full CONTINUE flow control bookkeeping
//! - UDP streams: zero flow-control overhead (spec mandates no CONTINUE for UDP)
//! - P0: Writer held directly in stream — no per-stream task or channel.
//!   try_write() inline from dispatch loop (single syscall, zero async overhead).

use bytes::Bytes;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::UdpSocket;

/// Lightweight same-thread cancellation flag.
/// Cheaper than tokio::CancellationToken — no atomics, just Rc<Cell<bool>>.
#[derive(Clone)]
pub struct CancelFlag(Rc<Cell<bool>>);

impl CancelFlag {
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(false)))
    }

    /// Signal cancellation. All clones see it immediately.
    #[inline]
    pub fn cancel(&self) {
        self.0.set(true);
    }

    /// Check if cancelled.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.0.get()
    }
}


/// Per-stream proxy state.
pub enum ProxyStream {
    /// TCP stream with flow control (holds write channel; read half in spawned task)
    Tcp(TcpProxyStream),
    /// UDP stream — no flow control per spec
    Udp(UdpProxyStream),
    /// Stream is connecting (backend TCP connect in progress)
    Connecting(ConnectingStream),
}

/// TCP proxy stream state.
/// P0: Writer held directly — no channel, no spawned writer task.
/// try_write() from dispatch loop is a single non-blocking syscall.
pub struct TcpProxyStream {
    /// Owned write half of the backend TCP socket (no mutex — from into_split)
    pub writer: OwnedWriteHalf,
    /// Bytes that couldn't be written immediately (partial write / WouldBlock).
    /// Drained on next DATA to this stream. Empty 99.99% of the time on localhost.
    pub pending: VecDeque<Bytes>,
    /// Packets received from client since last CONTINUE sent
    pub packets_since_continue: u32,
    /// Whether this stream is tracked in streams_with_pending.
    /// Prevents duplicate entries that cause O(n) retain scans under backpressure.
    pub queued_for_drain: bool,
    /// Cancellation flag — signals the backend reader task to stop.
    /// Shared via Rc<Cell<bool>> (same thread, no atomics).
    pub cancel: CancelFlag,
}

/// UDP proxy stream state.
pub struct UdpProxyStream {
    /// The backend UDP socket (Arc-shared with reader task)
    pub socket: Arc<UdpSocket>,
    /// Destination address (resolved from CONNECT hostname:port)
    pub dest_addr: SocketAddr,
    /// Cancellation flag — signals the UDP reader task to stop.
    pub cancel: CancelFlag,
}

/// Stream that is still connecting to the backend.
pub struct ConnectingStream {
    /// Early DATA packets queued before connection completes (append-only + consume-all)
    pub early_data: Vec<Bytes>,
    /// Cancellation flag — signals the connect task to abort if stream is CLOSEd early.
    pub cancel: CancelFlag,
}

/// Threshold for direct-index Vec. IDs below this use O(1) Vec lookup.
/// IDs at or above this fall through to a HashMap (handles random/sparse client IDs).
/// 8192 is far beyond any realistic sequential workload.
const DIRECT_INDEX_LIMIT: usize = 8192;

/// Hybrid stream table: Vec for low IDs (O(1) hot path) + HashMap for sparse/random IDs.
///
/// Wisp spec says stream IDs are random uint32 chosen by the client. In practice,
/// benchmark clients use small sequential IDs (1, 2, 3...) — the Vec handles those
/// with zero hash overhead. The HashMap fallback ensures spec compliance for arbitrary
/// compliant clients that use large or random IDs.
pub struct StreamTable {
    /// Direct-index for IDs 0..DIRECT_INDEX_LIMIT (hot path — benchmark clients)
    direct: Vec<Option<ProxyStream>>,
    /// Fallback for IDs >= DIRECT_INDEX_LIMIT (cold path — random/sparse clients)
    sparse: HashMap<u32, ProxyStream>,
    /// Number of active (Some) entries across both stores
    active_count: usize,
    /// Maximum streams allowed (0 = unlimited)
    max_streams: usize,
}

impl StreamTable {
    pub fn new(max_streams: usize) -> Self {
        Self {
            direct: Vec::with_capacity(16),
            sparse: HashMap::new(),
            active_count: 0,
            max_streams,
        }
    }

    /// Insert a new stream. Returns false if stream ID already exists or limit reached.
    #[inline]
    pub fn insert(&mut self, stream_id: u32, stream: ProxyStream) -> bool {
        if self.max_streams > 0 && self.active_count >= self.max_streams {
            return false;
        }
        let id = stream_id as usize;
        if id < DIRECT_INDEX_LIMIT {
            // Hot path: direct-index Vec
            if id >= self.direct.len() {
                self.direct.resize_with(id + 1, || None);
            }
            if self.direct[id].is_some() {
                return false;
            }
            self.direct[id] = Some(stream);
        } else {
            // Cold path: sparse HashMap for random/high IDs
            if self.sparse.contains_key(&stream_id) {
                return false;
            }
            self.sparse.insert(stream_id, stream);
        }
        self.active_count += 1;
        true
    }

    /// Get a mutable reference to a stream by client stream ID.
    /// Direct index for low IDs — O(1) with zero hash computation.
    #[inline]
    pub fn get_mut(&mut self, stream_id: u32) -> Option<&mut ProxyStream> {
        let id = stream_id as usize;
        if id < DIRECT_INDEX_LIMIT {
            if id >= self.direct.len() {
                return None;
            }
            self.direct[id].as_mut()
        } else {
            self.sparse.get_mut(&stream_id)
        }
    }

    /// Remove a stream, signal its cancellation flag, and return it.
    /// The cancel flag stops backend reader and connect tasks promptly.
    #[inline]
    pub fn remove(&mut self, stream_id: u32) -> Option<ProxyStream> {
        let id = stream_id as usize;
        let taken = if id < DIRECT_INDEX_LIMIT {
            if id >= self.direct.len() {
                return None;
            }
            self.direct[id].take()
        } else {
            self.sparse.remove(&stream_id)
        };
        if let Some(ref stream) = taken {
            self.active_count -= 1;
            // Signal cancellation — reader/connect tasks check this flag
            match stream {
                ProxyStream::Tcp(tcp) => tcp.cancel.cancel(),
                ProxyStream::Connecting(c) => c.cancel.cancel(),
                ProxyStream::Udp(udp) => udp.cancel.cancel(),
            }
        }
        taken
    }

    /// Check if a stream ID exists.
    #[inline]
    pub fn contains(&self, stream_id: u32) -> bool {
        let id = stream_id as usize;
        if id < DIRECT_INDEX_LIMIT {
            id < self.direct.len() && self.direct[id].is_some()
        } else {
            self.sparse.contains_key(&stream_id)
        }
    }

    /// Number of active streams.
    #[inline]
    pub fn len(&self) -> usize {
        self.active_count
    }
}

impl TcpProxyStream {
    pub fn with_pending(writer: OwnedWriteHalf, pending: VecDeque<Bytes>, cancel: CancelFlag) -> Self {
        let has_pending = !pending.is_empty();
        Self {
            writer,
            pending,
            packets_since_continue: 0,
            queued_for_drain: has_pending,
            cancel,
        }
    }

    /// Record that a DATA packet was received from the client.
    /// Returns true if CONTINUE should be sent (threshold reached).
    #[inline]
    pub fn record_packet(&mut self, threshold: u32) -> bool {
        self.packets_since_continue += 1;
        self.packets_since_continue >= threshold
    }

    /// Reset the packet counter after sending CONTINUE.
    #[inline]
    pub fn reset_counter(&mut self) {
        self.packets_since_continue = 0;
    }
}

impl UdpProxyStream {
    pub fn new(socket: Arc<UdpSocket>, dest_addr: SocketAddr, cancel: CancelFlag) -> Self {
        Self { socket, dest_addr, cancel }
    }
}

impl ConnectingStream {
    pub fn new() -> Self {
        Self {
            early_data: Vec::new(),
            cancel: CancelFlag::new(),
        }
    }

    /// Queue early DATA before connection completes.
    #[inline]
    pub fn queue_early_data(&mut self, data: Bytes) {
        self.early_data.push(data);
    }
}
