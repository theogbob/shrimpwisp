//! Per-connection handler — hybrid select! architecture.
//!
//! Architecture (best of both worlds):
//! - Single task holds BOTH OwnedReadHalf (via WebSocketRead) and OwnedWriteHalf
//! - select! between read_frame and write_rx.recv() — never blocks writes
//! - CONTINUEs written DIRECTLY to OwnedWriteHalf (zero channel hop)
//! - Backend DATA written immediately when write_rx fires during read_frame wait
//! - No write task, no ws_cmd channel, no task-switch latency
//! - TcpStream extracted from hyper Upgraded via downcast (no Arc<Mutex>)
//! - P0: TCP backend writes via try_write() — no per-stream task or channel

use bytes::{Buf, Bytes, BytesMut};
use fastwebsockets::{Frame, OpCode, Payload, WebSocketRead, WispFrameResult};
use std::collections::VecDeque;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::time::Instant;
use hyper_util::rt::TokioIo;

use crate::protocol::frame::*;
use crate::protocol::types::*;
use crate::proxy::stream::*;
use crate::server::ServerConfig;
use crate::server::dns::DnsCache;
use crate::server::security;
use crate::ws::upgrade::{handle_ws_upgrade, WsStream};

/// Control event from backend tasks -> main loop.
enum ControlEvent {
    /// Stream closed by backend
    StreamClosed { stream_id: u32, reason: CloseReason },
    /// TCP connect completed (owned halves — no mutex, from TcpStream::into_split)
    TcpConnected {
        stream_id: u32,
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        cancel: CancelFlag,
    },
    /// TCP connect failed
    TcpConnectFailed { stream_id: u32, reason: CloseReason },
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("WebSocket upgrade failed: {0}")]
    Upgrade(#[from] crate::ws::upgrade::WsUpgradeError),
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] fastwebsockets::WebSocketError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Connection closed by client")]
    ClientClosed,
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Writer closed")]
    WriterClosed,
}

// ============================================================================
// Macros for dual select! loop — avoid duplicating ~60 lines of shared logic.
// These expand inline so the compiler sees identical code in both paths.
// ============================================================================

/// Phase 0 + Phase 1 + Phase 2: drain pending writes, control events, backend data.
/// Shared between lean (3-branch) and full (5-branch) select loops.
macro_rules! drain_phases {
    ($swp:expr, $st:expr, $tw:expr, $crx:expr, $wrx:expr, $batch:expr,
     $cfg:expr, $wtx:expr, $ctx:expr, $bu:expr, $cfd:expr, $dead:expr) => {
        // Phase 0: Drain pending backend TCP writes
        if !$swp.is_empty() {
            $dead.clear();
            $swp.retain(|&sid| {
                if let Some(ProxyStream::Tcp(tcp)) = $st.get_mut(sid) {
                    if !tcp.pending.is_empty() {
                        if drain_pending(tcp) {
                            $dead.push(sid);
                            tcp.queued_for_drain = false;
                            return false;
                        }
                        if tcp.pending.is_empty() {
                            tcp.queued_for_drain = false;
                            return false;
                        }
                        return true; // still pending, keep tracking
                    }
                    tcp.queued_for_drain = false;
                }
                false
            });
            for sid in $dead.iter().copied() {
                $st.remove(sid);
                let close = build_close_frame(sid, CloseReason::NetworkError);
                let _ = write_ws_binary_frame(&mut $tw, &close).await;
            }
        }
        // Phase 1: Drain control events
        loop {
            match $crx.try_recv() {
                Ok(event) => {
                    handle_control_event(
                        event, &mut $st, &$cfg,
                        &mut $tw, &$wtx, &$ctx,
                        &mut $swp,
                    ).await?;
                    if !$bu && $st.len() >= 2 {
                        upgrade_client_socket_buffers($cfd);
                        $bu = true;
                    }
                }
                Err(_) => break,
            }
        }
        // Phase 2: Drain pending backend DATA with write coalescing
        $batch.clear();
        while let Ok(data) = $wrx.try_recv() {
            $batch.push(data);
        }
        if !$batch.is_empty() {
            write_ws_frames_batched(&mut $tw, &$batch).await
                .map_err(|_| ConnectionError::WriterClosed)?;
            $batch.clear(); // Release Bytes immediately — don't hold ~690KB of dead allocs across select! await
        }
    };
}

/// Handle inbound WS frame result. Returns true if connection should break.
macro_rules! handle_inbound {
    ($result:expr, $st:expr, $bs:expr, $th:expr, $pc:expr, $swp:expr,
     $tw:expr, $cfg:expr, $ctx:expr, $wtx:expr, $dns:expr, $pa:expr, $cs:expr) => {{
        match $result {
            Ok(WispFrameResult::Wisp { packet_type, stream_id, mut payload }) => {
                if packet_type == PACKET_DATA {
                    if let Some(dead_id) = handle_data_zerocopy(
                        &mut $st, $bs, $th,
                        stream_id, &mut payload, &mut $pc,
                        &mut $swp,
                    ) {
                        let close = build_close_frame(dead_id, CloseReason::NetworkError);
                        let _ = write_ws_binary_frame(&mut $tw, &close).await;
                    }
                    false
                } else if packet_type == PACKET_CONNECT {
                    $cs.streams_opened += 1;
                    match parse_connect_payload(&payload) {
                        Some(connect) => {
                            handle_connect(
                                &mut $st, &$cfg, &mut $tw,
                                &$ctx, &$wtx, stream_id, connect, $pa,
                                &$dns,
                            ).await;
                        }
                        None => {
                            let close = build_close_frame(stream_id, CloseReason::InvalidInfo);
                            let _ = write_ws_binary_frame(&mut $tw, &close).await;
                        }
                    }
                    false
                } else if packet_type == PACKET_CLOSE {
                    if stream_id == STREAM_ID_CONTROL {
                        let _ = write_ws_close_frame(&mut $tw).await;
                        true
                    } else {
                        $st.remove(stream_id);
                        false
                    }
                } else {
                    false
                }
            }
            Ok(WispFrameResult::Control(frame)) => {
                match frame.opcode {
                    OpCode::Close => {
                        let _ = write_ws_close_frame(&mut $tw).await;
                        true // break
                    }
                    OpCode::Ping => {
                        let _ = write_ws_pong_frame(&mut $tw, &frame.payload).await;
                        false
                    }
                    OpCode::Pong => {
                        $cs.awaiting_pong = false;
                        $cs.last_pong = Instant::now();
                        false
                    }
                    _ => false,
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "WebSocket error");
                true // break
            }
        }
    }};
}

/// Handle write_rx.recv() batch.
macro_rules! handle_write_batch {
    ($data:expr, $batch:expr, $tw:expr, $wrx:expr) => {
        match $data {
            Some(first) => {
                $batch.clear();
                $batch.push(first);
                while let Ok(more) = $wrx.try_recv() {
                    $batch.push(more);
                }
                write_ws_frames_batched(&mut $tw, &$batch).await
                    .map_err(|_| ConnectionError::WriterClosed)?;
                $batch.clear();
            }
            None => break,
        }
    };
}

/// Handle control_rx.recv() with drain.
macro_rules! handle_control_branch {
    ($event:expr, $st:expr, $cfg:expr, $tw:expr, $wtx:expr, $ctx:expr,
     $swp:expr, $bu:expr, $cfd:expr, $crx:expr) => {
        if let Some(event) = $event {
            handle_control_event(
                event, &mut $st, &$cfg,
                &mut $tw, &$wtx, &$ctx,
                &mut $swp,
            ).await?;
            if !$bu && $st.len() >= 2 {
                upgrade_client_socket_buffers($cfd);
                $bu = true;
            }
            loop {
                match $crx.try_recv() {
                    Ok(ev) => {
                        handle_control_event(
                            ev, &mut $st, &$cfg,
                            &mut $tw, &$wtx, &$ctx,
                            &mut $swp,
                        ).await?;
                    }
                    Err(_) => break,
                }
            }
        }
    };
}

/// Per-connection QoL state — kept in a single struct to minimize
/// the async future's state machine size. Without this, each field is a
/// separate live-across-await variable that bloats the future by ~40 bytes each,
/// memcpy'd on every select! poll cycle (~65K/sec at full throughput).
struct ConnState {
    conn_start: Instant,
    streams_opened: u32,
    client_ip: std::net::IpAddr,
    idle_enabled: bool,
    idle_duration: Duration,
    ping_enabled: bool,
    ping_interval_secs: u64,
    pong_timeout: Duration,
    awaiting_pong: bool,
    last_pong: Instant,
}

/// Handle a single Wisp connection end-to-end.
/// Hybrid select! architecture: single task, zero-hop CONTINUEs, non-blocking writes.
pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: Rc<ServerConfig>,
    dns_cache: Rc<std::cell::RefCell<DnsCache>>,
    trusted_proxies: &[ipnet::IpNet],
) -> Result<(), ConnectionError> {
    // ── QoL state in a single struct (minimizes future state machine size) ──
    let now = Instant::now(); // single clock_gettime for both conn_start and last_pong
    let mut cs = ConnState {
        conn_start: now,
        streams_opened: 0,
        client_ip: peer_addr.ip(),
        idle_enabled: config.idle_timeout_secs > 0,
        idle_duration: Duration::from_secs(if config.idle_timeout_secs > 0 { config.idle_timeout_secs } else { 365 * 24 * 3600 }),
        ping_enabled: config.ws_ping_interval_secs > 0,
        ping_interval_secs: config.ws_ping_interval_secs,
        pong_timeout: Duration::from_secs(config.ws_pong_timeout_secs),
        awaiting_pong: false,
        last_pong: now, // reuse same Instant — saves one clock_gettime
    };

    // ─── Step 1: WebSocket upgrade ───
    let upgrade_result = match handle_ws_upgrade(stream, Rc::clone(&config)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(peer = %peer_addr, error = %e, "WebSocket upgrade failed");
            return Err(ConnectionError::Upgrade(e));
        }
    };
    let mut ws = upgrade_result.ws;
    let is_v2 = upgrade_result.is_v2;

    // Extract real IP from upgrade headers if configured
    if config.real_ip_enabled && !config.real_ip_headers.is_empty() {
        if security::is_trusted_proxy(&peer_addr.ip(), trusted_proxies) {
            if let Some(real_ip) = security::extract_real_ip(
                &upgrade_result.headers,
                &config.real_ip_headers,
            ) {
                tracing::debug!(
                    peer = %peer_addr,
                    real_ip = %real_ip,
                    "Using real IP from proxy header"
                );
                cs.client_ip = real_ip;
            }
        }
    }

    tracing::debug!(peer = %peer_addr, client_ip = %cs.client_ip, v2 = is_v2, "WebSocket connected");

    // ─── Step 2: Wisp handshake (uses full WS — before split) ───
    ws.set_writev(true);
    ws.set_writev_threshold(0);

    let mut deferred_frame: Option<BytesMut> = None;

    if is_v2 {
        // Build server INFO — no extensions advertised by default.
        // UDP (0x01) and auth (0x02) extensions NOT advertised because existing
        // Wisp clients (wisp-mux, wisp-js) reject connections with unknown extensions.
        // Auth is enforced server-side by checking client INFO extensions when auth is configured.
        let info_frame = build_server_info_frame(&[]);
        ws.write_frame(Frame::binary(Payload::Borrowed(&info_frame))).await?;

        let first_payload = read_ws_binary_handshake(&mut ws).await?;
        // S6: Validate client INFO frame properly:
        // - Must be at least WISP_HEADER_SIZE + 2 bytes (header + major + minor)
        // - First byte must be PACKET_INFO
        // - Stream ID must be 0 (control)
        let is_valid_info = first_payload.len() >= WISP_HEADER_SIZE + 2
            && first_payload[0] == PACKET_INFO
            && u32::from_le_bytes([first_payload[1], first_payload[2], first_payload[3], first_payload[4]]) == STREAM_ID_CONTROL;

        if is_valid_info {
            let client_major = first_payload[WISP_HEADER_SIZE];
            if client_major != WISP_VERSION_MAJOR {
                tracing::warn!(peer = %peer_addr, client_major, "Incompatible Wisp version");
                let close = build_close_frame(STREAM_ID_CONTROL, CloseReason::IncompatibleExtensions);
                ws.write_frame(Frame::binary(Payload::Borrowed(&close))).await?;
                return Err(ConnectionError::Protocol("Incompatible Wisp version".into()));
            }

            // Multi-user auth check — once per connection, zero hot-path overhead
            if config.is_auth_required() {
                let client_extensions = parse_client_info_extensions(&first_payload);
                let auth_ext = client_extensions.iter().find(|e| e.id == 0x02);

                let authed = match auth_ext {
                    Some(ext) => verify_auth(&ext.payload, &config),
                    None => false,
                };

                if !authed {
                    tracing::warn!(peer = %peer_addr, client_ip = %cs.client_ip, "Auth failed — wrong or missing credentials");
                    let close = build_close_frame(STREAM_ID_CONTROL, CloseReason::AuthInvalidCredentials);
                    ws.write_frame(Frame::binary(Payload::Borrowed(&close))).await?;
                    return Err(ConnectionError::Protocol("Auth failed".into()));
                }
                tracing::debug!(peer = %peer_addr, client_ip = %cs.client_ip, "Auth OK");
            }

            let cont = build_initial_continue_frame(config.buffer_size);
            ws.write_frame(Frame::binary(Payload::Borrowed(&cont))).await?;
        } else {
            // Not a valid INFO — if auth required, reject
            if config.is_auth_required() {
                tracing::warn!(peer = %peer_addr, "Auth required but client sent no INFO");
                let close = build_close_frame(STREAM_ID_CONTROL, CloseReason::AuthRequired);
                ws.write_frame(Frame::binary(Payload::Borrowed(&close))).await?;
                return Err(ConnectionError::Protocol("Auth required".into()));
            }
            let cont = build_initial_continue_frame(config.buffer_size);
            ws.write_frame(Frame::binary(Payload::Borrowed(&cont))).await?;
            deferred_frame = Some(first_payload);
        }
    } else {
        // Non-v2 client — if auth is required, reject immediately.
        // Prevents auth bypass by omitting Sec-WebSocket-Protocol header.
        // (mrrowisp has the same vulnerability — requiresV2() exists but is never enforced)
        if config.is_auth_required() {
            tracing::warn!(peer = %peer_addr, "Auth required but client connected without v2 protocol");
            let close = build_close_frame(STREAM_ID_CONTROL, CloseReason::AuthRequired);
            ws.write_frame(Frame::binary(Payload::Borrowed(&close))).await?;
            return Err(ConnectionError::Protocol("Auth required, v2 protocol mandatory".into()));
        }
        let cont = build_initial_continue_frame(config.buffer_size);
        ws.write_frame(Frame::binary(Payload::Borrowed(&cont))).await?;
    }

    // ─── Step 3: Extract raw TcpStream from WS (zero-mutex split) ───
    let (tokio_io, mut ws_read_half, _ws_write_half) = ws.into_parts();
    let upgraded = tokio_io.into_inner();
    let parts = upgraded.downcast::<TokioIo<TcpStream>>()
        .map_err(|_| ConnectionError::Protocol("TcpStream downcast failed".into()))?;

    // Prepend any buffered bytes from HTTP upgrade to WS read buffer
    if !parts.read_buf.is_empty() {
        ws_read_half.prepend_bytes(&parts.read_buf);
    }

    let tcp_stream = parts.io.into_inner();

    // Dynamic buffer tuning: start with OS defaults (fast single-stream).
    // Upgrade to 1MB when multiplexing (stream count >= 2) — see Phase 1 in loop.
    let client_raw_fd = tcp_stream.as_raw_fd();

    // --prod mode: enable SO_ZEROCOPY on client socket.
    // On real NICs (VPS): kernel DMAs directly from userspace pages — no copy_from_user.
    // On loopback (benchmarks): kernel changes write codepath — actively hurts. Don't use.
    if config.prod_mode {
        unsafe {
            let val: libc::c_int = 1;
            libc::setsockopt(
                client_raw_fd,
                libc::SOL_SOCKET,
                libc::SO_ZEROCOPY,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let (tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Create WebSocketRead — auto_pong/auto_close off (we handle manually)
    let mut ws_reader = WebSocketRead::new(tcp_read, ws_read_half);
    ws_reader.set_auto_close(false);
    ws_reader.set_auto_pong(false);
    if config.max_frame_size > 0 {
        ws_reader.set_max_message_size(config.max_frame_size);
    }

    // ─── Step 4: Channels ───
    let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(4096);           // backend DATA
    let (control_tx, mut control_rx) = mpsc::channel::<ControlEvent>(256); // control events

    // ─── Step 5: State ───
    let mut stream_table = StreamTable::new(config.max_streams);
    let mut pending_continues: Vec<(u32, u32)> = Vec::with_capacity(16);
    let mut streams_with_pending: Vec<u32> = Vec::with_capacity(16); // pre-alloc avoids first-push heap alloc
    let mut buffers_upgraded = false;
    // Precomputed config — avoid Rc deref + arithmetic on every DATA packet
    let cfg_buf_size = config.buffer_size;
    let cfg_threshold = config.continue_threshold();

    // Adaptive yield: 64 frames on 6+ physical cores, 32 on fewer.
    // High-core machines benefit from larger batches (less drain/select overhead).
    // Low-core machines need frequent yields to prevent backend reader starvation.
    let yield_limit: u32 = {
        let cores = core_affinity::get_core_ids().map(|c| c.len()).unwrap_or(4);
        if cores >= 12 { 64 } else { 32 }
    };

    // Process deferred frame (already BytesMut — zero-copy from parser)
    if let Some(mut buf) = deferred_frame {
        process_inbound_frame(
            &mut buf, &mut stream_table, &config,
            &mut tcp_write, &control_tx, &write_tx,
            &mut pending_continues, &mut streams_with_pending, peer_addr,
            cfg_buf_size, cfg_threshold, &dns_cache,
        ).await?;
        if !pending_continues.is_empty() {
            flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
        }
    }

    // ─── Step 6: Dual select! loop ───
    // Two variants to avoid bloating the future state machine when timers are disabled.
    // The lean path (default/benchmark) uses a 3-branch select! — identical to the
    // original pre-QoL code with zero additional overhead (no Pin<Sleep> in the future).
    // The full path (--prod with timers) adds idle timeout + WS ping/pong branches.
    let mut batch: Vec<Bytes> = Vec::with_capacity(64);
    let mut dead_streams: Vec<u32> = Vec::new(); // hoisted — reused with .clear()

    if cs.idle_enabled || cs.ping_enabled {
        // ═══ FULL PATH: 5-branch select! with timers (--prod mode) ═══
        let idle_timeout = tokio::time::sleep(cs.idle_duration);
        tokio::pin!(idle_timeout);
        let ping_sleep = tokio::time::sleep(Duration::from_secs(
            if cs.ping_enabled { cs.ping_interval_secs } else { 365 * 24 * 3600 }
        ));
        tokio::pin!(ping_sleep);

        let mut frames_since_yield: u32 = 0;
        'conn_full: loop {
            // ── Tight inner loop: drain ALL buffered inbound frames ──
            while let Some(result) = ws_reader.try_read_wisp_frame() {
                if cs.idle_enabled {
                    idle_timeout.as_mut().reset(Instant::now() + cs.idle_duration);
                }
                if handle_inbound!(result, stream_table, cfg_buf_size, cfg_threshold,
                                   pending_continues, streams_with_pending, tcp_write,
                                   config, control_tx, write_tx, dns_cache, peer_addr, cs) {
                    if !pending_continues.is_empty() {
                        let _ = flush_continues_direct(&mut tcp_write, &mut pending_continues).await;
                    }
                    break 'conn_full; // exit BOTH inner while AND outer connection loop
                }
                frames_since_yield += 1;
                if frames_since_yield >= yield_limit {
                    frames_since_yield = 0;
                    if !pending_continues.is_empty() {
                        flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
                    }
                    break; // exit inner loop only → drain_phases + select! for fairness
                }
            }
            if !pending_continues.is_empty() {
                flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
            }

            drain_phases!(streams_with_pending, stream_table, tcp_write,
                          control_rx, write_rx, batch, config, write_tx, control_tx,
                          buffers_upgraded, client_raw_fd, dead_streams);

            tokio::select! {
                biased;

                result = ws_reader.read_wisp_frame() => {
                    if cs.idle_enabled {
                        idle_timeout.as_mut().reset(Instant::now() + cs.idle_duration);
                    }
                    if handle_inbound!(result, stream_table, cfg_buf_size, cfg_threshold,
                                       pending_continues, streams_with_pending, tcp_write,
                                       config, control_tx, write_tx, dns_cache, peer_addr, cs) {
                        break;
                    }
                    if !pending_continues.is_empty() {
                        flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
                    }
                    frames_since_yield += 1;
                }

                data = write_rx.recv() => {
                    handle_write_batch!(data, batch, tcp_write, write_rx);
                }

                event = control_rx.recv() => {
                    handle_control_branch!(event, stream_table, config, tcp_write, write_tx,
                                           control_tx, streams_with_pending, buffers_upgraded,
                                           client_raw_fd, control_rx);
                }

                () = &mut idle_timeout => {
                    tracing::debug!(client = %cs.client_ip, "Idle timeout reached");
                    break;
                }

                () = &mut ping_sleep => {
                    if cs.ping_enabled {
                        if cs.awaiting_pong && cs.last_pong.elapsed() > cs.pong_timeout {
                            tracing::debug!(client = %cs.client_ip, "Pong timeout — closing");
                            break;
                        }
                        let _ = write_ws_ping_frame(&mut tcp_write).await;
                        cs.awaiting_pong = true;
                        ping_sleep.as_mut().reset(Instant::now() + Duration::from_secs(cs.ping_interval_secs));
                    }
                }
            }
        }
    } else {
        // ═══ LEAN PATH: 3-branch select! — zero timer overhead (default/benchmark) ═══
        // No Pin<Sleep> in the future state machine. Identical structure to pre-QoL code.
        // BATCH INBOUND: process ALL buffered frames in a tight loop before drain/select.
        // This eliminates per-frame drain_phases overhead in multiplexed connections —
        // the key bottleneck for wisp-mux 5x10 (10 streams sharing one select! loop).
        let mut frames_since_yield: u32 = 0;
        'conn_lean: loop {
            // ── Tight inner loop: drain ALL buffered inbound frames ──
            // No drain_phases, no select! overhead between frames.
            // The 160KB WS buffer can hold ~2-3 frames of 65KB — process them all.
            while let Some(result) = ws_reader.try_read_wisp_frame() {
                if handle_inbound!(result, stream_table, cfg_buf_size, cfg_threshold,
                                   pending_continues, streams_with_pending, tcp_write,
                                   config, control_tx, write_tx, dns_cache, peer_addr, cs) {
                    if !pending_continues.is_empty() {
                        let _ = flush_continues_direct(&mut tcp_write, &mut pending_continues).await;
                    }
                    break 'conn_lean; // exit BOTH inner while AND outer connection loop
                }
                // Adaptive yield: 64 frames on high-core machines, 32 on low-core.
                // Prevents unconstrained() starvation when few connections share
                // one worker (SO_REUSEPORT on low-core machines).
                frames_since_yield += 1;
                if frames_since_yield >= yield_limit {
                    frames_since_yield = 0;
                    if !pending_continues.is_empty() {
                        flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
                    }
                    break; // exit inner loop → drain_phases + select! gives other tasks a chance
                }
            }
            // Flush any pending CONTINUEs from the tight loop
            if !pending_continues.is_empty() {
                flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
            }

            // ── drain_phases + select!: only runs when buffer is empty ──
            drain_phases!(streams_with_pending, stream_table, tcp_write,
                          control_rx, write_rx, batch, config, write_tx, control_tx,
                          buffers_upgraded, client_raw_fd, dead_streams);

            tokio::select! {
                biased;

                result = ws_reader.read_wisp_frame() => {
                    if handle_inbound!(result, stream_table, cfg_buf_size, cfg_threshold,
                                       pending_continues, streams_with_pending, tcp_write,
                                       config, control_tx, write_tx, dns_cache, peer_addr, cs) {
                        break;
                    }
                    if !pending_continues.is_empty() {
                        flush_continues_direct(&mut tcp_write, &mut pending_continues).await?;
                    }
                    frames_since_yield += 1;
                }

                data = write_rx.recv() => {
                    handle_write_batch!(data, batch, tcp_write, write_rx);
                }

                event = control_rx.recv() => {
                    handle_control_branch!(event, stream_table, config, tcp_write, write_tx,
                                           control_tx, streams_with_pending, buffers_upgraded,
                                           client_raw_fd, control_rx);
                }
            }
        }
    }

    // Connection close logging
    tracing::info!(
        client = %cs.client_ip,
        duration_ms = cs.conn_start.elapsed().as_millis() as u64,
        streams = cs.streams_opened,
        "connection closed"
    );
    Ok(())
}

// ============================================================================
// Raw WS frame writers (server -> client, never masked per RFC 6455)
// ============================================================================

/// Write a raw WS binary frame. Small frames use write_all (one syscall).
/// Large frames use writev (header + payload in one syscall).
#[inline]
async fn write_ws_binary_frame(writer: &mut OwnedWriteHalf, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len();

    // Fast path: small frames (CONTINUE=9, CLOSE=6) — stack buffer + single write_all
    if len <= 125 {
        let mut buf = [0u8; 127];
        buf[0] = 0x82; // FIN + Binary
        buf[1] = len as u8;
        buf[2..2 + len].copy_from_slice(payload);
        return writer.write_all(&buf[..2 + len]).await;
    }

    // Large frames: writev (header + payload in one syscall)
    let mut hdr = [0u8; 10];
    hdr[0] = 0x82;
    let hdr_len = if len <= 65535 {
        hdr[1] = 126;
        hdr[2] = (len >> 8) as u8;
        hdr[3] = len as u8;
        4
    } else {
        hdr[1] = 127;
        hdr[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        10
    };

    let bufs = &[IoSlice::new(&hdr[..hdr_len]), IoSlice::new(payload)];
    let total = hdr_len + len;
    let mut n = writer.write_vectored(bufs).await?;

    if n == total {
        return Ok(());
    }
    if n == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
    }

    // Partial write fallback (rare on localhost with 1MB buffers)
    while n < hdr_len {
        let wrote = writer.write_vectored(
            &[IoSlice::new(&hdr[n..hdr_len]), IoSlice::new(payload)]
        ).await?;
        if wrote == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        n += wrote;
    }
    if n < total {
        writer.write_all(&payload[n - hdr_len..]).await?;
    }

    Ok(())
}

/// Batch-write multiple pre-framed WS binary messages in a single writev syscall.
/// Each Bytes in the batch is already a complete WS binary frame (header + Wisp header + payload)
/// produced by backend_tcp_reader's pre-framing. No per-frame header construction needed.
///
/// Like mrrowisp's net.Buffers pattern — N frames in one syscall instead of N syscalls,
/// but even simpler because each frame is already a single contiguous slice.
#[inline]
async fn write_ws_frames_batched(
    writer: &mut OwnedWriteHalf,
    frames: &[Bytes],
) -> std::io::Result<()> {
    if frames.is_empty() {
        return Ok(());
    }
    if frames.len() == 1 {
        return writer.write_all(&frames[0]).await;
    }

    // Cap at 1024 frames per writev call (Linux UIO_MAXIOV = 1024).
    // Each pre-framed message is ONE IoSlice (not two like before), so full limit available.
    const MAX_BATCH_FRAMES: usize = 1024;
    if frames.len() > MAX_BATCH_FRAMES {
        for chunk in frames.chunks(MAX_BATCH_FRAMES) {
            write_ws_frames_preframed_inner(writer, chunk).await?;
        }
        return Ok(());
    }

    write_ws_frames_preframed_inner(writer, frames).await
}

/// Inner batched write for pre-framed data — caller guarantees frames.len() <= 1024 (IOV_MAX).
/// Each frame is a complete WS binary message: one IoSlice per frame, direct writev.
#[inline]
async fn write_ws_frames_preframed_inner(
    writer: &mut OwnedWriteHalf,
    frames: &[Bytes],
) -> std::io::Result<()> {
    // Stack-allocated IoSlice for small batches (covers 99% of cases).
    // Avoids heap Vec allocation on every batch write — saves ~50-150 MiB/s under 5x10.
    let mut stack_slices = [IoSlice::new(&[]); 64];
    let use_stack = frames.len() <= 64;

    let mut total = 0usize;
    if use_stack {
        for (i, frame) in frames.iter().enumerate() {
            stack_slices[i] = IoSlice::new(frame);
            total += frame.len();
        }
    }

    let slices: &[IoSlice<'_>] = if use_stack {
        &stack_slices[..frames.len()]
    } else {
        // Rare: >64 frames in one batch — fall back to heap Vec
        // (This allocation only happens under extreme burst, not steady-state)
        let heap_slices: Vec<IoSlice<'_>> = frames.iter().map(|f| {
            total += f.len();
            IoSlice::new(f)
        }).collect();
        // SAFETY: we need to return a reference, but heap_slices is local.
        // Instead, just do the write inline for the heap case and return.
        let n = writer.write_vectored(&heap_slices).await?;
        if n == total { return Ok(()); }
        if n == 0 { return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)); }
        // Partial write fallback for heap case
        let mut consumed = 0usize;
        let mut start_frame = 0;
        for frame in frames {
            if consumed + frame.len() <= n { consumed += frame.len(); start_frame += 1; } else { break; }
        }
        if start_frame < frames.len() && n > consumed {
            writer.write_all(&frames[start_frame][n - consumed..]).await?;
            start_frame += 1;
        }
        for frame in &frames[start_frame..] { writer.write_all(frame).await?; }
        return Ok(());
    };

    // Single writev for ALL frames (stack-allocated slices)
    let n = writer.write_vectored(slices).await?;

    if n == total {
        return Ok(());
    }
    if n == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
    }

    // Partial write: find which frames completed, write remainder
    let mut consumed = 0usize;
    let mut start_frame = 0;
    for frame in frames {
        if consumed + frame.len() <= n {
            consumed += frame.len();
            start_frame += 1;
        } else {
            break;
        }
    }

    // Handle partially-written frame
    if start_frame < frames.len() && n > consumed {
        let offset = n - consumed;
        writer.write_all(&frames[start_frame][offset..]).await?;
        start_frame += 1;
    }

    // Write remaining complete frames individually
    for frame in &frames[start_frame..] {
        writer.write_all(frame).await?;
    }

    Ok(())
}

/// Write a WS pong frame. Stack buffer — no heap allocation.
#[inline]
async fn write_ws_pong_frame(writer: &mut OwnedWriteHalf, payload: &[u8]) -> std::io::Result<()> {
    // RFC 6455: control frame payload must be <= 125 bytes
    let payload = &payload[..payload.len().min(125)];
    let len = payload.len();
    let mut buf = [0u8; 127]; // Max: 2 header + 125 payload
    buf[0] = 0x8A; // FIN + Pong
    buf[1] = len as u8;
    buf[2..2 + len].copy_from_slice(payload);
    writer.write_all(&buf[..2 + len]).await
}

/// Write a WS ping frame (empty payload). Opcode 0x89.
#[inline]
async fn write_ws_ping_frame(writer: &mut OwnedWriteHalf) -> std::io::Result<()> {
    writer.write_all(&[0x89, 0x00]).await
}

/// Write a WS close frame (empty payload).
#[inline]
async fn write_ws_close_frame(writer: &mut OwnedWriteHalf) -> std::io::Result<()> {
    writer.write_all(&[0x88, 0x00]).await
}


// ============================================================================
// Inbound frame processing
// ============================================================================

/// Process a single inbound Wisp frame. Returns true if connection should close.
/// TCP writes inline via try_write. Control frames written directly to tcp_write.
#[inline]
async fn process_inbound_frame(
    payload: &mut BytesMut,
    stream_table: &mut StreamTable,
    config: &ServerConfig,
    tcp_write: &mut OwnedWriteHalf,
    control_tx: &mpsc::Sender<ControlEvent>,
    write_tx: &mpsc::Sender<Bytes>,
    pending_continues: &mut Vec<(u32, u32)>,
    streams_with_pending: &mut Vec<u32>,
    peer_addr: SocketAddr,
    buf_size: u32,
    threshold: u32,
    dns_cache: &Rc<std::cell::RefCell<DnsCache>>,
) -> Result<bool, ConnectionError> {
    if config.max_frame_size > 0 && payload.len() > config.max_frame_size {
        return Ok(false);
    }
    if payload.len() < WISP_HEADER_SIZE {
        return Ok(false);
    }

    let packet_type = payload[0];
    let stream_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);

    match packet_type {
        PACKET_DATA => {
            // Advance past 5-byte Wisp header, then borrow-first try_write.
            // freeze() only on cold path (WouldBlock/partial) — skips Bytes refcount for 99.99% of DATA.
            payload.advance(WISP_HEADER_SIZE);
            if let Some(dead_id) = handle_data_zerocopy(stream_table, buf_size, threshold, stream_id, payload, pending_continues, streams_with_pending) {
                // Backend socket died (BrokenPipe/ConnectionReset) — send CLOSE to client
                let close = build_close_frame(dead_id, CloseReason::NetworkError);
                let _ = write_ws_binary_frame(tcp_write, &close).await;
            }
        }
        PACKET_CONNECT => {
            match parse_wisp_frame(payload) {
                Some(WispFrame::Connect { stream_id, payload: connect }) => {
                    handle_connect(stream_table, config, tcp_write, control_tx, write_tx, stream_id, connect, peer_addr, dns_cache).await;
                }
                _ => {
                    // Malformed CONNECT — spec requires CLOSE response
                    let close = build_close_frame(stream_id, CloseReason::InvalidInfo);
                    let _ = write_ws_binary_frame(tcp_write, &close).await;
                }
            }
        }
        PACKET_CLOSE => {
            if stream_id == STREAM_ID_CONTROL {
                return Ok(true);
            }
            stream_table.remove(stream_id);
        }
        PACKET_CONTINUE => {}
        _ => {}
    }

    Ok(false)
}

/// Handle DATA — BORROW-FIRST, NON-BLOCKING.
/// Fast path: try_write from &[u8] borrow — no Bytes allocation (99.99% of calls).
/// Cold path: WouldBlock/partial -> freeze() only the unwritten remainder into pending.
/// Returns Some(stream_id) if the backend socket died (fatal write error) — caller should send CLOSE.
/// Takes precomputed config values to avoid Rc deref on every DATA packet.
#[inline]
fn handle_data_zerocopy(
    stream_table: &mut StreamTable,
    buf_size: u32,
    threshold: u32,
    stream_id: u32,
    data: &mut BytesMut,
    pending_continues: &mut Vec<(u32, u32)>,
    streams_with_pending: &mut Vec<u32>,
) -> Option<u32> {
    let stream = match stream_table.get_mut(stream_id) {
        Some(s) => s,
        None => return None,
    };

    match stream {
        ProxyStream::Tcp(tcp) => {
            if tcp_try_write(tcp, data) {
                // Backend socket dead — remove stream, signal caller to send CLOSE
                stream_table.remove(stream_id);
                return Some(stream_id);
            }
            // C1: Track streams with pending data so Phase 0 can drain them.
            // Use queued_for_drain flag to prevent duplicate entries — without this,
            // every DATA to a blocked stream pushes another entry, causing O(n) retain scans.
            if !tcp.pending.is_empty() && !tcp.queued_for_drain {
                tcp.queued_for_drain = true;
                streams_with_pending.push(stream_id);
            }
            if tcp.record_packet(threshold) {
                pending_continues.push((stream_id, buf_size));
                tcp.reset_counter();
            }
        }
        ProxyStream::Udp(udp) => {
            let _ = udp.socket.try_send_to(&data[..], udp.dest_addr);
        }
        ProxyStream::Connecting(connecting) => {
            // Cap early-data queue at 128 items regardless of buffer_size.
            // buffer_size controls CONTINUE flow credits (can be 65535),
            // but early-data is pre-connect buffering — 128 * ~64KB = ~8MB max.
            if connecting.early_data.len() < 128 {
                connecting.queue_early_data(data.split().freeze());
            }
        }
    }
    None
}

/// Direct non-blocking write to backend TCP socket — BORROW-FIRST.
/// Fast path (99.99%): try_write from &[u8] borrow, succeeds fully -> zero Bytes allocation.
/// Cold path: partial/WouldBlock -> freeze() only the unwritten remainder into pending VecDeque.
/// Returns true if the backend socket is dead (fatal error — not WouldBlock).
#[inline]
fn tcp_try_write(tcp: &mut TcpProxyStream, data: &mut BytesMut) -> bool {
    if !tcp.pending.is_empty() {
        if drain_pending(tcp) {
            return true; // backend dead
        }
        if !tcp.pending.is_empty() {
            tcp.pending.push_back(std::mem::take(data).freeze());
            return false;
        }
    }

    let len = data.len();
    match tcp.writer.try_write(&data[..]) {
        Ok(n) if n == len => false, // Full write — no Bytes created, no refcount
        Ok(n) => {
            // Partial: freeze only the unwritten remainder
            data.advance(n);
            tcp.pending.push_back(std::mem::take(data).freeze());
            false
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            tcp.pending.push_back(std::mem::take(data).freeze());
            false
        }
        Err(_) => true, // Fatal error — BrokenPipe, ConnectionReset, etc.
    }
}

/// Try to drain all pending writes for a stream.
/// Cold path: pending is non-empty <0.01% of the time on localhost.
/// When multiple chunks are pending (backpressure), uses writev to coalesce them
/// into a single syscall — matching mrrowisp's batched ingress writer pattern.
/// Returns true if a fatal error occurred (BrokenPipe, ConnectionReset, etc.).
#[cold]
fn drain_pending(tcp: &mut TcpProxyStream) -> bool {
    if tcp.pending.len() <= 1 {
        // Single chunk — use simple try_write (avoids IoSlice construction)
        if let Some(chunk) = tcp.pending.front() {
            match tcp.writer.try_write(chunk) {
                Ok(n) if n == chunk.len() => {
                    tcp.pending.pop_front();
                }
                Ok(n) => {
                    let remaining = tcp.pending.pop_front().unwrap().slice(n..);
                    tcp.pending.push_front(remaining);
                    return false;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return false;
                }
                Err(_) => {
                    tcp.pending.clear();
                    return true;
                }
            }
        }
        return false;
    }

    // Multiple chunks — writev them in one syscall.
    // Cap IoSlice count at 1024 (Linux UIO_MAXIOV). Unlikely to exceed with
    // VecDeque<Bytes> from partial writes, but defensive.
    let slice_count = tcp.pending.len().min(1024);
    let slices: Vec<IoSlice<'_>> = tcp.pending.iter()
        .take(slice_count)
        .map(|chunk| IoSlice::new(chunk))
        .collect();
    let total: usize = slices.iter().map(|s| s.len()).sum();

    match tcp.writer.try_write_vectored(&slices) {
        Ok(n) if n == total && slice_count == tcp.pending.len() => {
            // Wrote everything — fast clear
            tcp.pending.clear();
        }
        Ok(n) if n > 0 => {
            // Partial write — consume n bytes worth of chunks from front
            let mut remaining = n;
            while remaining > 0 {
                if let Some(front) = tcp.pending.front() {
                    if remaining >= front.len() {
                        remaining -= front.len();
                        tcp.pending.pop_front();
                    } else {
                        let leftover = tcp.pending.pop_front().unwrap().slice(remaining..);
                        tcp.pending.push_front(leftover);
                        remaining = 0;
                    }
                } else {
                    break;
                }
            }
        }
        Ok(_) => {
            // n == 0 — treat as WouldBlock
            return false;
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return false;
        }
        Err(_) => {
            tcp.pending.clear();
            return true;
        }
    }
    false
}

// ============================================================================
// Control events and stream management
// ============================================================================

/// Process a control event. CLOSE/CONTINUE written directly to tcp_write.
async fn handle_control_event(
    event: ControlEvent,
    stream_table: &mut StreamTable,
    config: &ServerConfig,
    tcp_write: &mut OwnedWriteHalf,
    write_tx: &mpsc::Sender<Bytes>,
    control_tx: &mpsc::Sender<ControlEvent>,
    streams_with_pending: &mut Vec<u32>,
) -> Result<(), ConnectionError> {
    match event {
        ControlEvent::StreamClosed { stream_id, reason } => {
            stream_table.remove(stream_id); // auto-cancels reader task
            let close = build_close_frame(stream_id, reason);
            let _ = write_ws_binary_frame(tcp_write, &close).await;
        }
        ControlEvent::TcpConnected { stream_id, reader, writer, cancel: _connecting_cancel } => {
            // Note: stream_table.remove() cancels the ConnectingStream's flag, which is the
            // same flag the connect task held. That's fine — the connect task is done.
            // We create a FRESH cancel flag for the new TcpProxyStream + backend reader.
            let cancel = CancelFlag::new();
            let connecting = match stream_table.remove(stream_id) {
                Some(ProxyStream::Connecting(c)) => c,
                other => {
                    if let Some(existing) = other {
                        stream_table.insert(stream_id, existing);
                    }
                    return Ok(());
                }
            };

            // P0: Flush early data directly via try_write — no channel
            let mut pending = VecDeque::new();
            let mut failed = false;
            let mut dead = false;
            for data in connecting.early_data {
                if failed {
                    pending.push_back(data);
                    continue;
                }
                match writer.try_write(&data) {
                    Ok(n) if n == data.len() => {}
                    Ok(n) => {
                        pending.push_back(data.slice(n..));
                        failed = true;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        pending.push_back(data);
                        failed = true;
                    }
                    Err(_) => {
                        // Fatal error (BrokenPipe, ConnectionReset) — backend dead at connect time
                        dead = true;
                        break;
                    }
                }
            }

            if dead {
                // Backend died during early data flush — send CLOSE, don't insert stream
                let close = build_close_frame(stream_id, CloseReason::NetworkError);
                let _ = write_ws_binary_frame(tcp_write, &close).await;
                return Ok(());
            }

            let has_pending = !pending.is_empty();
            let reader_cancel = cancel.clone();
            let tcp_stream = TcpProxyStream::with_pending(writer, pending, cancel);
            stream_table.insert(stream_id, ProxyStream::Tcp(tcp_stream));

            // C1: Register in streams_with_pending if early data couldn't fully flush
            if has_pending {
                streams_with_pending.push(stream_id);
            }

            // Direct CONTINUE write — no channel hop
            let cont = build_continue_frame(stream_id, config.buffer_size);
            let _ = write_ws_binary_frame(tcp_write, &cont).await;

            // Spawn backend TCP reader — cancel flag shared with stream table entry
            let data_tx = write_tx.clone();
            let close_tx = control_tx.clone();
            tokio::task::spawn_local(backend_tcp_reader(stream_id, reader, data_tx, close_tx, reader_cancel));
        }
        ControlEvent::TcpConnectFailed { stream_id, reason } => {
            stream_table.remove(stream_id);
            let close = build_close_frame(stream_id, reason);
            let _ = write_ws_binary_frame(tcp_write, &close).await;
        }
    }
    Ok(())
}

/// Handle CONNECT — writes CLOSE directly on error.
/// Applies blacklist/whitelist, IP policy, and DNS cache.
async fn handle_connect(
    stream_table: &mut StreamTable,
    config: &ServerConfig,
    tcp_write: &mut OwnedWriteHalf,
    control_tx: &mpsc::Sender<ControlEvent>,
    write_tx: &mpsc::Sender<Bytes>,
    stream_id: u32,
    connect: ConnectPayload,
    peer_addr: SocketAddr,
    dns_cache: &Rc<std::cell::RefCell<DnsCache>>,
) {
    if stream_id == STREAM_ID_CONTROL || stream_table.contains(stream_id) {
        let close = build_close_frame(stream_id, CloseReason::InvalidInfo);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    if connect.port == 0 {
        let close = build_close_frame(stream_id, CloseReason::InvalidInfo);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    // ── Blacklist/whitelist checks (BEFORE any network I/O) ──

    // Hostname filter
    if config.is_hostname_blocked(&connect.hostname) {
        tracing::debug!(
            peer = %peer_addr, stream_id,
            host = %connect.hostname,
            "CONNECT blocked by hostname filter"
        );
        let close = build_close_frame(stream_id, CloseReason::Blocked);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    // Port filter
    if config.is_port_blocked(connect.port) {
        tracing::debug!(
            peer = %peer_addr, stream_id,
            port = connect.port,
            "CONNECT blocked by port filter"
        );
        let close = build_close_frame(stream_id, CloseReason::Blocked);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    // Pre-resolution hostname/IP policy checks
    if security::is_hostname_blocked_pre_resolution(&connect.hostname, config) {
        let close = build_close_frame(stream_id, CloseReason::Blocked);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    tracing::debug!(
        peer = %peer_addr, stream_id,
        host = %connect.hostname, port = connect.port,
        "CONNECT {:?}", connect.stream_type
    );

    match connect.stream_type {
        StreamType::Tcp => {
            handle_tcp_connect(stream_table, config, tcp_write, control_tx, stream_id, connect, stream_table.len() >= 1, dns_cache).await;
        }
        StreamType::Udp => {
            handle_udp_connect(stream_table, config, tcp_write, control_tx, write_tx, stream_id, connect, dns_cache).await;
        }
    }
}

/// Non-blocking TCP connect — writes CLOSE directly on throttle.
/// Uses DNS cache for resolution.
async fn handle_tcp_connect(
    stream_table: &mut StreamTable,
    config: &ServerConfig,
    tcp_write: &mut OwnedWriteHalf,
    control_tx: &mpsc::Sender<ControlEvent>,
    stream_id: u32,
    connect: ConnectPayload,
    multiplexed: bool,
    dns_cache: &Rc<std::cell::RefCell<DnsCache>>,
) {
    let connecting = ConnectingStream::new();
    let connect_cancel = connecting.cancel.clone();
    if !stream_table.insert(stream_id, ProxyStream::Connecting(connecting)) {
        let close = build_close_frame(stream_id, CloseReason::Throttled);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    let tcp_nodelay = config.tcp_nodelay;
    let allow_direct_ip = config.allow_direct_ip;
    let buffers_upgraded_flag = multiplexed;
    let tcp_keepalive_secs = config.tcp_keepalive_secs;
    let tx = control_tx.clone();

    // Pre-resolve using DNS cache (on the current task, before spawning connect task).
    // This avoids spawning a task just to fail on DNS lookup, and uses the cache.
    //
    // SAFETY: We must NOT hold RefCell borrow across .await — another local task
    // could try to borrow_mut() during DNS I/O, causing a panic. Split into:
    // 1. Sync cache check (borrow + drop immediately)
    // 2. Async resolve (no borrow held)
    // 3. Sync cache insert (borrow + drop immediately)
    let resolved = dns_resolve_no_hold(&dns_cache, &connect.hostname, connect.port).await;

    let resolved_addr = match resolved {
        Ok(addr) => addr,
        Err(_) => {
            let _ = tx.send(ControlEvent::TcpConnectFailed { stream_id, reason: CloseReason::Unreachable }).await;
            return;
        }
    };

    // Post-resolution IP security check — ALWAYS run, even when allow flags are true.
    // is_ip_blocked() checks unspecified (0.0.0.0/::) unconditionally, and respects
    // allow_loopback/allow_direct_ip/allow_private_ips flags for other categories.
    if security::is_ip_blocked(&resolved_addr.ip(), config) {
        let _ = tx.send(ControlEvent::TcpConnectFailed { stream_id, reason: CloseReason::Blocked }).await;
        return;
    }

    // Direct IP check: if hostname is a raw IP and direct IPs are blocked
    if !allow_direct_ip && security::is_raw_ip(&connect.hostname) {
        let _ = tx.send(ControlEvent::TcpConnectFailed { stream_id, reason: CloseReason::Blocked }).await;
        return;
    }

    tokio::task::spawn_local(async move {
        // Check if stream was already CLOSEd before connect completes
        if connect_cancel.is_cancelled() {
            return;
        }

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(resolved_addr),
        ).await;

        match result {
            Ok(Ok(socket)) => {
                tracing::debug!(stream_id, "TCP connected");
                if tcp_nodelay {
                    let _ = socket.set_nodelay(true);
                }
                // Backend socket buffers: OS defaults for single-stream (low latency),
                // 1MB for multiplexed connections (burst absorption).
                if buffers_upgraded_flag {
                    let sock = socket2::SockRef::from(&socket);
                    let _ = sock.set_recv_buffer_size(1 << 20);
                    let _ = sock.set_send_buffer_size(1 << 20);
                }
                // TCP keepalive on backend sockets (one setsockopt, zero ongoing overhead)
                if tcp_keepalive_secs > 0 {
                    let sock = socket2::SockRef::from(&socket);
                    let _ = sock.set_keepalive(true);
                    let keepalive_dur = Duration::from_secs(tcp_keepalive_secs);
                    let _ = sock.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(keepalive_dur));
                }
                // P0: into_split — no mutex, OwnedWriteHalf has try_write
                let (reader, writer) = socket.into_split();
                let _ = tx.send(ControlEvent::TcpConnected { stream_id, reader, writer, cancel: connect_cancel }).await;
            }
            Ok(Err(e)) => {
                let reason = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    CloseReason::Refused
                } else {
                    CloseReason::Unreachable
                };
                let _ = tx.send(ControlEvent::TcpConnectFailed { stream_id, reason }).await;
            }
            Err(_) => {
                let _ = tx.send(ControlEvent::TcpConnectFailed { stream_id, reason: CloseReason::TimedOut }).await;
            }
        }
    });
}

/// Maximum WS binary frame header size: 1 (opcode) + 1 (length indicator) + 8 (extended length) = 10.
const WS_MAX_HEADER_SIZE: usize = 10;

/// Reserved prefix in pre-framed buffers: WS header (max 10) + Wisp DATA header (5) = 15.
const PREFRAME_RESERVE: usize = WS_MAX_HEADER_SIZE + WISP_HEADER_SIZE;

/// Backend TCP reader — sends outbound DATA through mpsc channel.
/// Pre-frames: each buffer sent through the channel is a complete WS binary frame
/// (WS header + Wisp DATA header + payload) ready for direct writev — no header
/// construction needed on the write side.
///
/// Buffer layout (Vec<u8> with capacity PREFRAME_RESERVE + 65536):
///   [0..10]  = reserved for WS header (variable 2/4/10 bytes, right-aligned)
///   [10..15] = Wisp DATA header (type=0x02, stream_id LE)
///   [15..]   = payload from backend read
///
/// After read of N bytes, the WS header is written backward from offset 10,
/// and the final frame is buf[frame_start .. 15 + N].
///
/// Uses Vec<u8> instead of BytesMut — fixed allocation, no reserve/split/compact
/// overhead. Bytes::from(Vec<u8>) is zero-copy (takes ownership of the allocation).
async fn backend_tcp_reader(
    stream_id: u32,
    mut reader: OwnedReadHalf,
    write_tx: mpsc::Sender<Bytes>,
    close_tx: mpsc::Sender<ControlEvent>,
    cancel: CancelFlag,
) {
    // Pre-build the 5-byte Wisp DATA header (constant for this stream)
    let wisp_header = build_data_header(stream_id);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Allocate a fresh Vec with reserved prefix space.
        // jemalloc tcache makes this near-free for the fixed size class.
        let buf_capacity = PREFRAME_RESERVE + 65536;
        let mut buf = Vec::with_capacity(buf_capacity);

        // SAFETY: set_len WITHOUT zeroing. This is sound because:
        // - [0..10]: WS header region — written by us before any read
        // - [10..15]: Wisp header — written by copy_from_slice below
        // - [15..15+n]: payload — written by kernel read() before we access
        // - [15+n..cap]: truncated away, never accessed
        // The old `resize(cap, 0)` was zero-filling 65KB per read — ~4GB/sec
        // of wasted memory bandwidth at full throughput.
        unsafe { buf.set_len(buf_capacity); }

        // Write Wisp DATA header at fixed offset [10..15]
        buf[WS_MAX_HEADER_SIZE..PREFRAME_RESERVE].copy_from_slice(&wisp_header);

        // Read payload starting at offset 15 into the initialized region
        match reader.read(&mut buf[PREFRAME_RESERVE..]).await {
            Ok(0) => {
                if !cancel.is_cancelled() {
                    let _ = close_tx
                        .send(ControlEvent::StreamClosed { stream_id, reason: CloseReason::Voluntary })
                        .await;
                }
                break;
            }
            Ok(n) => {
                if cancel.is_cancelled() {
                    break;
                }

                // Truncate buf to actual frame size (prefix + payload bytes read)
                buf.truncate(PREFRAME_RESERVE + n);

                // Compute WS binary frame header and frame start offset.
                // WS payload = Wisp header (5) + TCP payload (n)
                let ws_payload_len = WISP_HEADER_SIZE + n;

                let (ws_hdr_len, frame_start) = if ws_payload_len <= 125 {
                    // 2-byte WS header: [0x82, len]
                    let start = PREFRAME_RESERVE - WISP_HEADER_SIZE - 2; // = 8
                    buf[start] = 0x82; // FIN + Binary
                    buf[start + 1] = ws_payload_len as u8;
                    (2usize, start)
                } else if ws_payload_len <= 65535 {
                    // 4-byte WS header: [0x82, 126, len_hi, len_lo]
                    let start = PREFRAME_RESERVE - WISP_HEADER_SIZE - 4; // = 6
                    buf[start] = 0x82;
                    buf[start + 1] = 126;
                    buf[start + 2] = (ws_payload_len >> 8) as u8;
                    buf[start + 3] = ws_payload_len as u8;
                    (4usize, start)
                } else {
                    // 10-byte WS header: [0x82, 127, 8-byte BE length]
                    let start = 0;
                    buf[start] = 0x82;
                    buf[start + 1] = 127;
                    buf[start + 2..start + 10].copy_from_slice(&(ws_payload_len as u64).to_be_bytes());
                    (10usize, start)
                };

                // The complete frame is buf[frame_start .. PREFRAME_RESERVE + n].
                // Convert to Bytes + slice. The .slice() costs 2 atomic refcount ops per frame,
                // but that's ~10ns total — far cheaper than memmove alternatives.
                let _ = ws_hdr_len;
                let frame_bytes = Bytes::from(buf);
                let frame = frame_bytes.slice(frame_start..);

                // try_send avoids future/poll machinery when channel has capacity (99%+ of calls).
                // Only fall back to .await on Full (rare backpressure).
                match write_tx.try_send(frame) {
                    Ok(()) => {},
                    Err(mpsc::error::TrySendError::Full(f)) => {
                        if write_tx.send(f).await.is_err() { break; }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
                continue; // buf ownership transferred; loop allocates a new one
            }
            Err(_) => {
                if !cancel.is_cancelled() {
                    let _ = close_tx
                        .send(ControlEvent::StreamClosed { stream_id, reason: CloseReason::NetworkError })
                        .await;
                }
                break;
            }
        }
    }
}

/// UDP connect + reader — writes CLOSE directly on error.
/// Uses DNS cache for hostname resolution.
async fn handle_udp_connect(
    stream_table: &mut StreamTable,
    config: &ServerConfig,
    tcp_write: &mut OwnedWriteHalf,
    control_tx: &mpsc::Sender<ControlEvent>,
    write_tx: &mpsc::Sender<Bytes>,
    stream_id: u32,
    connect: ConnectPayload,
    dns_cache: &Rc<std::cell::RefCell<DnsCache>>,
) {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            let close = build_close_frame(stream_id, CloseReason::NetworkError);
            let _ = write_ws_binary_frame(tcp_write, &close).await;
            return;
        }
    };

    // Resolve via DNS cache (no RefCell borrow held across .await)
    let dest_addr: SocketAddr = match dns_resolve_no_hold(dns_cache, &connect.hostname, connect.port).await {
        Ok(addr) => addr,
        Err(_) => {
            let close = build_close_frame(stream_id, CloseReason::Unreachable);
            let _ = write_ws_binary_frame(tcp_write, &close).await;
            return;
        }
    };

    // Post-resolution blocked IP check — always run
    if security::is_ip_blocked(&dest_addr.ip(), config) {
        let close = build_close_frame(stream_id, CloseReason::Blocked);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    let socket = std::sync::Arc::new(socket);
    let udp_cancel = CancelFlag::new();
    let udp_stream = UdpProxyStream::new(socket.clone(), dest_addr, udp_cancel.clone());
    if !stream_table.insert(stream_id, ProxyStream::Udp(udp_stream)) {
        let close = build_close_frame(stream_id, CloseReason::Throttled);
        let _ = write_ws_binary_frame(tcp_write, &close).await;
        return;
    }

    // UDP reader — cancel flag shared with stream table entry.
    // Pre-frames each datagram as a complete WS binary message (same format as TCP reader)
    // so write_ws_frames_batched can writev them directly.
    let data_tx = write_tx.clone();
    let close_tx = control_tx.clone();
    let reader_cancel = udp_cancel;
    tokio::task::spawn_local(async move {
        let wisp_header = build_data_header(stream_id);
        let mut recv_buf = vec![0u8; 65535];
        loop {
            if reader_cancel.is_cancelled() {
                break;
            }
            match socket.recv_from(&mut recv_buf).await {
                Ok((n, _)) => {
                    if reader_cancel.is_cancelled() {
                        break;
                    }
                    // Pre-frame: build complete WS binary frame in one contiguous buffer
                    let ws_payload_len = WISP_HEADER_SIZE + n;
                    let (ws_hdr_len, frame_start) = if ws_payload_len <= 125 {
                        (2usize, PREFRAME_RESERVE - WISP_HEADER_SIZE - 2) // 8
                    } else if ws_payload_len <= 65535 {
                        (4usize, PREFRAME_RESERVE - WISP_HEADER_SIZE - 4) // 6
                    } else {
                        (10usize, 0usize)
                    };
                    let frame_len = ws_hdr_len + WISP_HEADER_SIZE + n;
                    let mut buf = vec![0u8; frame_start + frame_len];
                    // WS header
                    buf[frame_start] = 0x82; // FIN + Binary
                    if ws_payload_len <= 125 {
                        buf[frame_start + 1] = ws_payload_len as u8;
                    } else if ws_payload_len <= 65535 {
                        buf[frame_start + 1] = 126;
                        buf[frame_start + 2] = (ws_payload_len >> 8) as u8;
                        buf[frame_start + 3] = ws_payload_len as u8;
                    } else {
                        buf[frame_start + 1] = 127;
                        buf[frame_start + 2..frame_start + 10].copy_from_slice(&(ws_payload_len as u64).to_be_bytes());
                    }
                    // Wisp DATA header
                    buf[frame_start + ws_hdr_len..frame_start + ws_hdr_len + WISP_HEADER_SIZE]
                        .copy_from_slice(&wisp_header);
                    // Payload
                    buf[frame_start + ws_hdr_len + WISP_HEADER_SIZE..].copy_from_slice(&recv_buf[..n]);
                    // Slice off unused prefix and send
                    let frame = Bytes::from(buf).slice(frame_start..);
                    if data_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    if !reader_cancel.is_cancelled() {
                        let _ = close_tx
                            .send(ControlEvent::StreamClosed { stream_id, reason: CloseReason::NetworkError })
                            .await;
                    }
                    break;
                }
            }
        }
    });
}

/// Flush pending CONTINUEs in a single write_all — batch N syscalls into 1.
/// Each CONTINUE is 9-byte wisp payload -> 11-byte WS frame (2 hdr + 9 payload).
/// With 10+ streams, this saves significant kernel-crossing overhead.
#[inline]
async fn flush_continues_direct(
    tcp_write: &mut OwnedWriteHalf,
    pending: &mut Vec<(u32, u32)>,
) -> Result<(), ConnectionError> {
    if pending.len() == 1 {
        // Single CONTINUE — use fast path (stack buffer)
        let frame = build_continue_frame(pending[0].0, pending[0].1);
        pending.clear();
        return write_ws_binary_frame(tcp_write, &frame).await
            .map_err(|_| ConnectionError::WriterClosed);
    }
    // Batch: build all CONTINUEs into one buffer, single write_all.
    // Stack buffer for <=16 streams (common case, matches pending_continues capacity).
    // Each CONTINUE is 11 bytes WS-framed (2 hdr + 9 payload). 16 * 11 = 176 bytes.
    let count = pending.len();
    if count <= 16 {
        let mut buf = [0u8; 176];
        let mut pos = 0;
        for &(stream_id, remaining) in pending.iter() {
            let frame = build_continue_frame(stream_id, remaining);
            buf[pos] = 0x82;
            buf[pos + 1] = 9;
            buf[pos + 2..pos + 11].copy_from_slice(&frame);
            pos += 11;
        }
        pending.clear();
        tcp_write.write_all(&buf[..pos]).await
            .map_err(|_| ConnectionError::WriterClosed)
    } else {
        // Fallback: heap alloc for >16 streams (rare)
        let mut buf = Vec::with_capacity(count * 11);
        for &(stream_id, remaining) in pending.iter() {
            let frame = build_continue_frame(stream_id, remaining);
            buf.push(0x82);
            buf.push(9);
            buf.extend_from_slice(&frame);
        }
        pending.clear();
        tcp_write.write_all(&buf).await
            .map_err(|_| ConnectionError::WriterClosed)
    }
}

/// Upgrade client socket buffers to 1MB for multiplexed connections.
/// Called once when stream count reaches 2+ (cold path, one setsockopt).
#[inline]
fn upgrade_client_socket_buffers(fd: std::os::unix::io::RawFd) {
    let borrowed = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
    let sock = socket2::SockRef::from(&borrowed);
    let _ = sock.set_recv_buffer_size(1 << 20);
    let _ = sock.set_send_buffer_size(1 << 20);
}

// ============================================================================
// DNS resolution helper (RefCell-safe)
// ============================================================================

/// Resolve hostname via DNS cache WITHOUT holding RefCell borrow across .await.
/// Prevents runtime panic when concurrent local tasks try to resolve simultaneously.
///
/// Strategy:
/// 1. borrow_mut → check cache (sync) → drop borrow
/// 2. if cache miss → async resolve (no borrow held)
/// 3. borrow_mut → insert result → drop borrow
async fn dns_resolve_no_hold(
    dns_cache: &Rc<std::cell::RefCell<DnsCache>>,
    hostname: &str,
    port: u16,
) -> Result<SocketAddr, crate::server::dns::DnsError> {
    // Fast path: hostname is already an IP address — skip DNS + cache entirely
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // Step 1: Check cache (sync, borrow dropped immediately)
    {
        let cache = dns_cache.borrow();
        if let Some(cached) = cache.get_cached(hostname) {
            return Ok(SocketAddr::new(cached, port));
        }
    } // borrow dropped here

    // Step 2: Async resolve via OS resolver (no RefCell borrow held)
    // tokio::net::lookup_host (getaddrinfo) — zero extra dependencies.
    let ipv4_first = dns_cache.borrow().ipv4_first();
    let lookup_str = format!("{}:{}", hostname, port);
    let sock_addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&lookup_str)
        .await
        .map_err(|e| crate::server::dns::DnsError::ResolveFailed(format!("{}: {}", hostname, e)))?
        .collect();
    if sock_addrs.is_empty() {
        return Err(crate::server::dns::DnsError::NoAddresses(hostname.to_string()));
    }
    let mut addrs: Vec<std::net::IpAddr> = sock_addrs.into_iter().map(|a| a.ip()).collect();
    addrs.dedup();
    if ipv4_first {
        addrs.sort_by_key(|a| match a { std::net::IpAddr::V4(_) => 0, std::net::IpAddr::V6(_) => 1 });
    }

    // Step 3: Insert into cache (sync, borrow dropped immediately)
    let first_ip = {
        let mut cache = dns_cache.borrow_mut();
        cache.insert_resolved(hostname, addrs)
    };

    Ok(SocketAddr::new(first_ip, port))
}

// ============================================================================
// Auth helpers
// ============================================================================

/// Parse extensions from a raw client INFO payload.
/// Layout: [wisp_header(5)] [major(1)] [minor(1)] [extensions...]
/// Each extension: [id(1)] [length(4 LE)] [payload(length)]
fn parse_client_info_extensions(payload: &[u8]) -> Vec<ExtensionEntry> {
    const EXT_OFFSET: usize = WISP_HEADER_SIZE + 2; // skip header + version bytes
    if payload.len() <= EXT_OFFSET {
        return Vec::new();
    }
    let mut data = &payload[EXT_OFFSET..];
    let mut extensions = Vec::new();
    while data.len() >= 5 {
        let id = data[0];
        let length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        data = &data[5..];
        if data.len() < length {
            break;
        }
        extensions.push(ExtensionEntry {
            id,
            payload: data[..length].to_vec(),
        });
        data = &data[length..];
    }
    extensions
}

/// Verify auth credentials from client INFO extension 0x02.
/// Supports multi-user auth with bcrypt and plaintext passwords.
///
/// Auth payload format: [password_bytes] (legacy single-password)
/// or: [username_len:u8][username][password] (multi-user)
fn verify_auth(auth_payload: &[u8], config: &ServerConfig) -> bool {
    // Try multi-user auth first (if users map is non-empty)
    if !config.auth_users.is_empty() {
        // Try to parse as multi-user format: [username_len:u8][username][password]
        if auth_payload.len() >= 2 {
            let username_len = auth_payload[0] as usize;
            if auth_payload.len() >= 1 + username_len + 1 {
                let username = match std::str::from_utf8(&auth_payload[1..1 + username_len]) {
                    Ok(u) => u,
                    Err(_) => return false,
                };
                let password_bytes = &auth_payload[1 + username_len..];

                if let Some(stored) = config.auth_users.get(username) {
                    return verify_password(password_bytes, stored);
                }
                // Unknown username — run dummy bcrypt to prevent timing-based username enumeration.
                // An attacker comparing response times for known vs unknown users would otherwise
                // see ~0ms for unknown (instant HashMap miss) vs ~100ms for known (bcrypt verify).
                // Hash must be a valid 60-char $2b$12$ string so bcrypt does full cost-12 work.
                let _ = bcrypt::verify("dummy", "$2b$12$LJ3m4ys3Lg7Eqhvlfn.JduGDBWCR0FDVcnXlMBGqpYqnqYfHJBCam");
                return false;
            }
        }

        // Fallback: try as raw password against "default" user
        if let Some(stored) = config.auth_users.get("default") {
            return verify_password(auth_payload, stored);
        }

        return false;
    }

    // Legacy single-password auth (--password flag, no username)
    if let Some(ref required_pw) = config.auth_password {
        use subtle::ConstantTimeEq;
        // Constant-time: ct_eq returns 0 if lengths differ, no early bail
        return auth_payload.ct_eq(required_pw.as_bytes()).into();
    }

    false
}

/// Verify a password against a stored value (bcrypt hash or plaintext).
fn verify_password(password_bytes: &[u8], stored: &str) -> bool {
    let password_str = match std::str::from_utf8(password_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // bcrypt hash (starts with $2b$ or $2a$)
    if stored.starts_with("$2b$") || stored.starts_with("$2a$") {
        return bcrypt::verify(password_str, stored).unwrap_or(false);
    }

    // Plaintext (deprecated — use subtle::ConstantTimeEq for vetted constant-time comparison)
    use subtle::ConstantTimeEq;
    password_str.as_bytes().ct_eq(stored.as_bytes()).into()
}

/// Read a binary WS frame — used during handshake only.
/// Returns BytesMut directly (zero-copy from parser buffer) instead of Vec<u8>.
#[inline]
async fn read_ws_binary_handshake(ws: &mut WsStream) -> Result<BytesMut, ConnectionError> {
    loop {
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Binary => return Ok(frame.payload.into_bytes_mut()),
            OpCode::Close => return Err(ConnectionError::ClientClosed),
            OpCode::Ping => {
                ws.write_frame(Frame::pong(frame.payload)).await?;
            }
            _ => continue,
        }
    }
}
