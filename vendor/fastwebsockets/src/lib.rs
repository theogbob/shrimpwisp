// Copyright 2023 Divy Srivastava <dj.srivastava23@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! _fastwebsockets_ is a minimal, fast WebSocket server implementation.
//!
//! [https://github.com/denoland/fastwebsockets](https://github.com/denoland/fastwebsockets)
//!
//! Passes the _Autobahn|TestSuite_ and fuzzed with LLVM's _libfuzzer_.
//!
//! You can use it as a raw websocket frame parser and deal with spec compliance yourself, or you can use it as a full-fledged websocket server.
//!
//! # Example
//!
//! ```
//! use tokio::net::TcpStream;
//! use fastwebsockets::{WebSocket, OpCode, Role};
//! use anyhow::Result;
//!
//! async fn handle(
//!   socket: TcpStream,
//! ) -> Result<()> {
//!   let mut ws = WebSocket::after_handshake(socket, Role::Server);
//!   ws.set_writev(false);
//!   ws.set_auto_close(true);
//!   ws.set_auto_pong(true);
//!
//!   loop {
//!     let frame = ws.read_frame().await?;
//!     match frame.opcode {
//!       OpCode::Close => break,
//!       OpCode::Text | OpCode::Binary => {
//!         ws.write_frame(frame).await?;
//!       }
//!       _ => {}
//!     }
//!   }
//!   Ok(())
//! }
//! ```
//!
//! ## Fragmentation
//!
//! By default, fastwebsockets will give the application raw frames with FIN set. Other
//! crates like tungstenite which will give you a single message with all the frames
//! concatenated.
//!
//! For concanated frames, use `FragmentCollector`:
//! ```
//! use fastwebsockets::{FragmentCollector, WebSocket, Role};
//! use tokio::net::TcpStream;
//! use anyhow::Result;
//!
//! async fn handle(
//!   socket: TcpStream,
//! ) -> Result<()> {
//!   let mut ws = WebSocket::after_handshake(socket, Role::Server);
//!   let mut ws = FragmentCollector::new(ws);
//!   let incoming = ws.read_frame().await?;
//!   // Always returns full messages
//!   assert!(incoming.fin);
//!   Ok(())
//! }
//! ```
//!
//! _permessage-deflate is not supported yet._
//!
//! ## HTTP Upgrades
//!
//! Enable the `upgrade` feature to do server-side upgrades and client-side
//! handshakes.
//!
//! This feature is powered by [hyper](https://docs.rs/hyper).
//!
//! ```
//! use fastwebsockets::upgrade::upgrade;
//! use http_body_util::Empty;
//! use hyper::{Request, body::{Incoming, Bytes}, Response};
//! use anyhow::Result;
//!
//! async fn server_upgrade(
//!   mut req: Request<Incoming>,
//! ) -> Result<Response<Empty<Bytes>>> {
//!   let (response, fut) = upgrade(&mut req)?;
//!
//!   tokio::spawn(async move {
//!     let ws = fut.await;
//!     // Do something with the websocket
//!   });
//!
//!   Ok(response)
//! }
//! ```
//!
//! Use the `handshake` module for client-side handshakes.
//!
//! ```
//! use fastwebsockets::handshake;
//! use fastwebsockets::FragmentCollector;
//! use hyper::{Request, body::Bytes, upgrade::Upgraded, header::{UPGRADE, CONNECTION}};
//! use http_body_util::Empty;
//! use hyper_util::rt::TokioIo;
//! use tokio::net::TcpStream;
//! use std::future::Future;
//! use anyhow::Result;
//!
//! async fn connect() -> Result<FragmentCollector<TokioIo<Upgraded>>> {
//!   let stream = TcpStream::connect("localhost:9001").await?;
//!
//!   let req = Request::builder()
//!     .method("GET")
//!     .uri("http://localhost:9001/")
//!     .header("Host", "localhost:9001")
//!     .header(UPGRADE, "websocket")
//!     .header(CONNECTION, "upgrade")
//!     .header(
//!       "Sec-WebSocket-Key",
//!       fastwebsockets::handshake::generate_key(),
//!     )
//!     .header("Sec-WebSocket-Version", "13")
//!     .body(Empty::<Bytes>::new())?;
//!
//!   let (ws, _) = handshake::client(&SpawnExecutor, req, stream).await?;
//!   Ok(FragmentCollector::new(ws))
//! }
//!
//! // Tie hyper's executor to tokio runtime
//! struct SpawnExecutor;
//!
//! impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
//! where
//!   Fut: Future + Send + 'static,
//!   Fut::Output: Send + 'static,
//! {
//!   fn execute(&self, fut: Fut) {
//!     tokio::task::spawn(fut);
//!   }
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod close;
mod error;
mod fragment;
mod frame;
/// Client handshake.
#[cfg(feature = "upgrade")]
#[cfg_attr(docsrs, doc(cfg(feature = "upgrade")))]
pub mod handshake;
mod mask;
/// HTTP upgrades.
#[cfg(feature = "upgrade")]
#[cfg_attr(docsrs, doc(cfg(feature = "upgrade")))]
pub mod upgrade;

use bytes::Buf;

use bytes::BytesMut;
#[cfg(feature = "unstable-split")]
use std::future::Future;

use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

pub use crate::close::CloseCode;
pub use crate::error::WebSocketError;
pub use crate::fragment::FragmentCollector;
#[cfg(feature = "unstable-split")]
pub use crate::fragment::FragmentCollectorRead;
pub use crate::frame::Frame;
pub use crate::frame::OpCode;
pub use crate::frame::Payload;
pub use crate::mask::unmask;

#[derive(Copy, Clone, PartialEq)]
pub enum Role {
  Server,
  Client,
}

pub struct WriteHalf {
  role: Role,
  closed: bool,
  vectored: bool,
  auto_apply_mask: bool,
  writev_threshold: usize,
  write_buffer: Vec<u8>,
}

pub struct ReadHalf {
  pub(crate) role: Role,
  pub(crate) auto_apply_mask: bool,
  /// When true, auto-close frames are generated as obligated sends.
  pub auto_close: bool,
  /// When true, pong frames are generated as obligated sends.
  pub auto_pong: bool,
  pub(crate) writev_threshold: usize,
  pub(crate) max_message_size: usize,
  pub(crate) buffer: BytesMut,
}

#[cfg(feature = "unstable-split")]
pub struct WebSocketRead<S> {
  stream: S,
  read_half: ReadHalf,
}

#[cfg(feature = "unstable-split")]
pub struct WebSocketWrite<S> {
  stream: S,
  write_half: WriteHalf,
}

#[cfg(feature = "unstable-split")]
/// Create a split `WebSocketRead`/`WebSocketWrite` pair from a stream that has already completed the WebSocket handshake.
pub fn after_handshake_split<R, W>(
  read: R,
  write: W,
  role: Role,
) -> (WebSocketRead<R>, WebSocketWrite<W>)
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  (
    WebSocketRead {
      stream: read,
      read_half: ReadHalf::after_handshake(role),
    },
    WebSocketWrite {
      stream: write,
      write_half: WriteHalf::after_handshake(role),
    },
  )
}

#[cfg(feature = "unstable-split")]
impl<'f, S> WebSocketRead<S> {
  /// Construct a WebSocketRead from a stream and existing read state.
  /// Used when splitting a WebSocket after handshake.
  #[inline]
  pub fn new(stream: S, read_half: ReadHalf) -> Self {
    Self { stream, read_half }
  }

  /// Consumes the `WebSocketRead` and returns the underlying stream.
  #[inline]
  pub(crate) fn into_parts_internal(self) -> (S, ReadHalf) {
    (self.stream, self.read_half)
  }

  pub fn set_writev_threshold(&mut self, threshold: usize) {
    self.read_half.writev_threshold = threshold;
  }

  /// Proactive buffer compaction — call after consuming a frame while tail bytes
  /// are still L1-cache-hot. The memmove of hot data is ~5-10x faster than
  /// waiting for the next reserve() when data may be L2/L3-cold.
  #[inline]
  pub fn try_compact_buffer(&mut self) {
    let buf = &mut self.read_half.buffer;
    // Only compact if there's meaningful dead prefix to reclaim.
    // BytesMut::reserve(0) with capacity check triggers internal compaction
    // when the dead prefix (offset) >= live data (len).
    if buf.capacity() < 65536 && !buf.is_empty() {
      // Tail exists but capacity is low — compaction will help next read
      buf.reserve(65536);
    } else if buf.is_empty() && buf.capacity() < 65536 {
      // Buffer is empty but capacity consumed by dead prefix — reset
      buf.reserve(131072);
    }
  }

  /// Sets whether to automatically close the connection when a close frame is received. When set to `false`, the application will have to manually send close frames.
  ///
  /// Default: `true`
  pub fn set_auto_close(&mut self, auto_close: bool) {
    self.read_half.auto_close = auto_close;
  }

  /// Sets whether to automatically send a pong frame when a ping frame is received.
  ///
  /// Default: `true`
  pub fn set_auto_pong(&mut self, auto_pong: bool) {
    self.read_half.auto_pong = auto_pong;
  }

  /// Sets the maximum message size in bytes. If a message is received that is larger than this, the connection will be closed.
  ///
  /// Default: 64 MiB
  pub fn set_max_message_size(&mut self, max_message_size: usize) {
    self.read_half.max_message_size = max_message_size;
  }

  /// Sets whether to automatically apply the mask to the frame payload.
  ///
  /// Default: `true`
  pub fn set_auto_apply_mask(&mut self, auto_apply_mask: bool) {
    self.read_half.auto_apply_mask = auto_apply_mask;
  }

  /// Reads a frame from the stream.
  pub async fn read_frame<R, E>(
    &mut self,
    send_fn: &mut impl FnMut(Frame<'f>) -> R,
  ) -> Result<Frame, WebSocketError>
  where
    S: AsyncRead + Unpin,
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    R: Future<Output = Result<(), E>>,
  {
    loop {
      let (res, obligated_send) =
        self.read_half.read_frame_inner(&mut self.stream).await;
      if let Some(frame) = obligated_send {
        let res = send_fn(frame).await;
        res.map_err(|e| WebSocketError::SendError(e.into()))?;
      }
      if let Some(frame) = res? {
        break Ok(frame);
      }
    }
  }

  /// Fused Wisp+WS parser — single pass from wire to Wisp-level result.
  ///
  /// For Binary frames: parses WS header, unmasks in-place, peeks the 5-byte
  /// Wisp header (type + stream_id), and returns `WispDataResult::Data` with
  /// the raw payload BytesMut (Wisp header already consumed via advance).
  ///
  /// For non-Binary frames (Close/Ping/Pong): returns the Frame as-is so the
  /// caller can handle control frames normally.
  ///
  /// This eliminates: Frame struct construction, Payload enum dispatch,
  /// into_bytes_mut() conversion, and the second Wisp header parse that
  /// connection.rs would otherwise do.
  pub async fn read_wisp_frame(
    &mut self,
  ) -> Result<WispFrameResult<'_>, WebSocketError>
  where
    S: AsyncRead + Unpin,
  {
    loop {
      let (res, obligated_send) =
        self.read_half.read_frame_inner(&mut self.stream).await;
      // Obligated sends (auto_pong/auto_close): if enabled, the inner parser
      // produces a frame that MUST be sent back (e.g., Pong). Since we can't
      // send without a writer, return it as a Control frame so the caller can
      // handle it. This preserves the obligation instead of silently dropping.
      if let Some(send_frame) = obligated_send {
        // Return the obligated frame as Control — caller is responsible for sending.
        // Also return any actual frame from `res` on the next iteration.
        return Ok(WispFrameResult::Control(send_frame));
      }
      let frame = match res? {
        Some(f) => f,
        None => continue,
      };

      match frame.opcode {
        OpCode::Binary => {
          let mut payload = frame.payload.into_bytes_mut();
          if payload.len() >= 5 {
            let wisp_type = payload[0];
            let stream_id = u32::from_le_bytes([
              payload[1], payload[2], payload[3], payload[4],
            ]);
            payload.advance(5);
            return Ok(WispFrameResult::Wisp {
              packet_type: wisp_type,
              stream_id,
              payload,
            });
          }
          // Too short for Wisp header — return as raw binary
          return Ok(WispFrameResult::Wisp {
            packet_type: 0,
            stream_id: 0,
            payload,
          });
        }
        _ => return Ok(WispFrameResult::Control(frame)),
      }
    }
  }

  /// Non-blocking attempt to read a Wisp frame from ALREADY BUFFERED data.
  /// Returns None if no complete frame is buffered (caller should use async read_wisp_frame).
  /// This eliminates per-frame select!/drain overhead in multiplexed connections by processing
  /// all buffered frames in a tight loop before returning to the async select! point.
  pub fn try_read_wisp_frame(&mut self) -> Option<Result<WispFrameResult<'_>, WebSocketError>> {
    // Read these before mutable borrow of read_half via try_parse_frame_buffered
    let should_unmask = self.read_half.role == Role::Server && self.read_half.auto_apply_mask;
    match self.read_half.try_parse_frame_buffered() {
      Some(Ok(mut frame)) => {
        if should_unmask {
          frame.unmask();
        }
        match frame.opcode {
          OpCode::Binary => {
            let mut payload = frame.payload.into_bytes_mut();
            if payload.len() >= 5 {
              let wisp_type = payload[0];
              let stream_id = u32::from_le_bytes([
                payload[1], payload[2], payload[3], payload[4],
              ]);
              payload.advance(5);
              Some(Ok(WispFrameResult::Wisp { packet_type: wisp_type, stream_id, payload }))
            } else {
              Some(Ok(WispFrameResult::Wisp { packet_type: 0, stream_id: 0, payload }))
            }
          }
          _ => Some(Ok(WispFrameResult::Control(frame))),
        }
      }
      Some(Err(e)) => Some(Err(e)),
      None => None,
    }
  }
}

/// Result from the fused Wisp+WS parser.
/// Avoids Frame construction + Payload enum dispatch + into_bytes_mut for the
/// DATA hot path (99%+ of frames).
pub enum WispFrameResult<'f> {
  /// Binary frame with Wisp header already parsed and consumed.
  /// `payload` has the 5-byte Wisp header already advanced past.
  Wisp {
    packet_type: u8,
    stream_id: u32,
    payload: BytesMut,
  },
  /// Non-binary control frame (Close, Ping, Pong, Text).
  Control(Frame<'f>),
}

#[cfg(feature = "unstable-split")]
impl<'f, S> WebSocketWrite<S> {
  /// Sets whether to use vectored writes. This option does not guarantee that vectored writes will be always used.
  ///
  /// Default: `true`
  pub fn set_writev(&mut self, vectored: bool) {
    self.write_half.vectored = vectored;
  }

  pub fn set_writev_threshold(&mut self, threshold: usize) {
    self.write_half.writev_threshold = threshold;
  }

  /// Sets whether to automatically apply the mask to the frame payload.
  ///
  /// Default: `true`
  pub fn set_auto_apply_mask(&mut self, auto_apply_mask: bool) {
    self.write_half.auto_apply_mask = auto_apply_mask;
  }

  pub fn is_closed(&self) -> bool {
    self.write_half.closed
  }

  pub async fn write_frame(
    &mut self,
    frame: Frame<'f>,
  ) -> Result<(), WebSocketError>
  where
    S: AsyncWrite + Unpin,
  {
    self.write_half.write_frame(&mut self.stream, frame).await
  }

  pub async fn flush(&mut self) -> Result<(), WebSocketError>
  where
    S: AsyncWrite + Unpin,
  {
    flush(&mut self.stream).await
  }
}

#[inline]
async fn flush<S>(stream: &mut S) -> Result<(), WebSocketError>
where
  S: AsyncWrite + Unpin,
{
  stream.flush().await.map_err(WebSocketError::IoError)
}

/// WebSocket protocol implementation over an async stream.
pub struct WebSocket<S> {
  stream: S,
  write_half: WriteHalf,
  read_half: ReadHalf,
}

impl<'f, S> WebSocket<S> {
  /// Creates a new `WebSocket` from a stream that has already completed the WebSocket handshake.
  ///
  /// Use the `upgrade` feature to handle server upgrades and client handshakes.
  ///
  /// # Example
  ///
  /// ```
  /// use tokio::net::TcpStream;
  /// use fastwebsockets::{WebSocket, OpCode, Role};
  /// use anyhow::Result;
  ///
  /// async fn handle_client(
  ///   socket: TcpStream,
  /// ) -> Result<()> {
  ///   let mut ws = WebSocket::after_handshake(socket, Role::Server);
  ///   // ...
  ///   Ok(())
  /// }
  /// ```
  pub fn after_handshake(stream: S, role: Role) -> Self
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    Self {
      stream,
      write_half: WriteHalf::after_handshake(role),
      read_half: ReadHalf::after_handshake(role),
    }
  }

  /// Split a [`WebSocket`] into a [`WebSocketRead`] and [`WebSocketWrite`] half. Note that the split version does not
  /// handle fragmented packets and you may wish to create a [`FragmentCollectorRead`] over top of the read half that
  /// is returned.
  #[cfg(feature = "unstable-split")]
  pub fn split<R, W>(
    self,
    split_fn: impl Fn(S) -> (R, W),
  ) -> (WebSocketRead<R>, WebSocketWrite<W>)
  where
    S: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
  {
    let (stream, read, write) = self.into_parts_internal();
    let (r, w) = split_fn(stream);
    (
      WebSocketRead {
        stream: r,
        read_half: read,
      },
      WebSocketWrite {
        stream: w,
        write_half: write,
      },
    )
  }

  /// Consumes the `WebSocket` and returns the underlying stream.
  #[inline]
  pub fn into_inner(self) -> S {
    // self.write_half.into_inner().stream
    self.stream
  }

  /// Consumes the `WebSocket` and returns the underlying stream, read state, and write state.
  /// Allows constructing a split reader/writer while preserving internal buffer state.
  #[inline]
  pub fn into_parts(self) -> (S, ReadHalf, WriteHalf) {
    (self.stream, self.read_half, self.write_half)
  }

  /// Consumes the `WebSocket` and returns the underlying stream.
  #[inline]
  pub(crate) fn into_parts_internal(self) -> (S, ReadHalf, WriteHalf) {
    (self.stream, self.read_half, self.write_half)
  }

  /// Sets whether to use vectored writes. This option does not guarantee that vectored writes will be always used.
  ///
  /// Default: `true`
  pub fn set_writev(&mut self, vectored: bool) {
    self.write_half.vectored = vectored;
  }

  pub fn set_writev_threshold(&mut self, threshold: usize) {
    self.read_half.writev_threshold = threshold;
    self.write_half.writev_threshold = threshold;
  }

  /// Sets whether to automatically close the connection when a close frame is received. When set to `false`, the application will have to manually send close frames.
  ///
  /// Default: `true`
  pub fn set_auto_close(&mut self, auto_close: bool) {
    self.read_half.auto_close = auto_close;
  }

  /// Sets whether to automatically send a pong frame when a ping frame is received.
  ///
  /// Default: `true`
  pub fn set_auto_pong(&mut self, auto_pong: bool) {
    self.read_half.auto_pong = auto_pong;
  }

  /// Sets the maximum message size in bytes. If a message is received that is larger than this, the connection will be closed.
  ///
  /// Default: 64 MiB
  pub fn set_max_message_size(&mut self, max_message_size: usize) {
    self.read_half.max_message_size = max_message_size;
  }

  /// Sets whether to automatically apply the mask to the frame payload.
  ///
  /// Default: `true`
  pub fn set_auto_apply_mask(&mut self, auto_apply_mask: bool) {
    self.read_half.auto_apply_mask = auto_apply_mask;
    self.write_half.auto_apply_mask = auto_apply_mask;
  }

  pub fn is_closed(&self) -> bool {
    self.write_half.closed
  }

  /// Writes a frame to the stream.
  ///
  /// # Example
  ///
  /// ```
  /// use fastwebsockets::{WebSocket, Frame, OpCode};
  /// use tokio::net::TcpStream;
  /// use anyhow::Result;
  ///
  /// async fn send(
  ///   ws: &mut WebSocket<TcpStream>
  /// ) -> Result<()> {
  ///   let mut frame = Frame::binary(vec![0x01, 0x02, 0x03].into());
  ///   ws.write_frame(frame).await?;
  ///   Ok(())
  /// }
  /// ```
  pub async fn write_frame(
    &mut self,
    frame: Frame<'f>,
  ) -> Result<(), WebSocketError>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    self.write_half.write_frame(&mut self.stream, frame).await?;
    Ok(())
  }

  /// Write pre-framed raw bytes directly to the underlying stream, bypassing
  /// WS frame construction entirely. Use for batch-writing pre-built WS frames.
  /// P1: Single write_all for all batched outbound frames.
  #[inline]
  pub async fn write_raw(&mut self, data: &[u8]) -> Result<(), WebSocketError>
  where
    S: AsyncWrite + Unpin,
  {
    use tokio::io::AsyncWriteExt;
    self.stream.write_all(data).await.map_err(WebSocketError::IoError)
  }

  /// Flushes the data from the underlying stream.
  ///
  /// if the underlying stream is buffered (i.e: TlsStream<TcpStream>), it is needed to call flush
  /// to be sure that the written frame are correctly pushed down to the bottom stream/channel.
  ///
  pub async fn flush(&mut self) -> Result<(), WebSocketError>
  where
    S: AsyncWrite + Unpin,
  {
    flush(&mut self.stream).await
  }

  /// Reads a frame from the stream.
  ///
  /// This method will unmask the frame payload. For fragmented frames, use `FragmentCollector::read_frame`.
  ///
  /// Text frames payload is guaranteed to be valid UTF-8.
  ///
  /// # Example
  ///
  /// ```
  /// use fastwebsockets::{OpCode, WebSocket, Frame};
  /// use tokio::net::TcpStream;
  /// use anyhow::Result;
  ///
  /// async fn echo(
  ///   ws: &mut WebSocket<TcpStream>
  /// ) -> Result<()> {
  ///   let frame = ws.read_frame().await?;
  ///   match frame.opcode {
  ///     OpCode::Text | OpCode::Binary => {
  ///       ws.write_frame(frame).await?;
  ///     }
  ///     _ => {}
  ///   }
  ///   Ok(())
  /// }
  /// ```
  pub async fn read_frame(&mut self) -> Result<Frame<'f>, WebSocketError>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    loop {
      let (res, obligated_send) =
        self.read_half.read_frame_inner(&mut self.stream).await;
      let is_closed = self.write_half.closed;
      if let Some(frame) = obligated_send {
        if !is_closed {
          self.write_half.write_frame(&mut self.stream, frame).await?;
        }
      }
      if let Some(frame) = res? {
        if is_closed && frame.opcode != OpCode::Close {
          return Err(WebSocketError::ConnectionClosed);
        }
        break Ok(frame);
      }
    }
  }
}

const MAX_HEADER_SIZE: usize = 14;

impl ReadHalf {
  pub fn after_handshake(role: Role) -> Self {
    // OPT-14: 128KB initial buffer — avoids reallocation for large frames.
    // 256KB was tested but regressed mux(5x10) by ~10%: fills entire L2 cache
    // 160KB: large enough that reserve(65569) doesn't trigger memmove compaction
    // on every frame (128KB left only 65517 tail capacity — 52 bytes short).
    // At 160KB, compaction triggers every 2nd frame instead of every frame.
    // Still fits in L2 (160KB = 62.5% of 256KB Coffee Lake L2) — unlike 256KB
    // which filled entire L2 and evicted stream table + other hot data.
    let buffer = BytesMut::with_capacity(163840);

    Self {
      role,
      auto_apply_mask: true,
      auto_close: true,
      auto_pong: true,
      writev_threshold: 1024,
      max_message_size: 64 << 20,
      buffer,
    }
  }

  /// Prepend buffered bytes from HTTP upgrade to the internal read buffer.
  /// Used when extracting TcpStream from Upgraded for full-duplex split.
  pub fn prepend_bytes(&mut self, bytes: &[u8]) {
    if !bytes.is_empty() {
      let existing_len = self.buffer.len();
      let mut new_buf = BytesMut::with_capacity(bytes.len() + existing_len);
      new_buf.extend_from_slice(bytes);
      new_buf.extend_from_slice(&self.buffer);
      self.buffer = new_buf;
    }
  }

  /// Attempt to read a single frame from from the incoming stream, returning any send obligations if
  /// `auto_close` or `auto_pong` are enabled. Callers to this function are obligated to send the
  /// frame in the latter half of the tuple if one is specified, unless the write half of this socket
  /// has been closed.
  ///
  /// XXX: Do not expose this method to the public API.
  pub(crate) async fn read_frame_inner<'f, S>(
    &mut self,
    stream: &mut S,
  ) -> (Result<Option<Frame<'f>>, WebSocketError>, Option<Frame<'f>>)
  where
    S: AsyncRead + Unpin,
  {
    let mut frame = match self.parse_frame_header(stream).await {
      Ok(frame) => frame,
      Err(e) => return (Err(e), None),
    };

    if self.role == Role::Server && self.auto_apply_mask {
      frame.unmask()
    };

    match frame.opcode {
      OpCode::Close if self.auto_close => {
        match frame.payload.len() {
          0 => {}
          1 => return (Err(WebSocketError::InvalidCloseFrame), None),
          _ => {
            let code = close::CloseCode::from(u16::from_be_bytes(
              frame.payload[0..2].try_into().unwrap(),
            ));

            #[cfg(feature = "simd")]
            if simdutf8::basic::from_utf8(&frame.payload[2..]).is_err() {
              return (Err(WebSocketError::InvalidUTF8), None);
            };

            #[cfg(not(feature = "simd"))]
            if std::str::from_utf8(&frame.payload[2..]).is_err() {
              return (Err(WebSocketError::InvalidUTF8), None);
            };

            if !code.is_allowed() {
              return (
                Err(WebSocketError::InvalidCloseCode),
                Some(Frame::close(1002, &frame.payload[2..])),
              );
            }
          }
        };

        let obligated_send = Frame::close_raw(frame.payload.to_owned().into());
        (Ok(Some(frame)), Some(obligated_send))
      }
      OpCode::Ping if self.auto_pong => {
        (Ok(None), Some(Frame::pong(frame.payload)))
      }
      OpCode::Text => {
        if frame.fin && !frame.is_utf8() {
          (Err(WebSocketError::InvalidUTF8), None)
        } else {
          (Ok(Some(frame)), None)
        }
      }
      _ => (Ok(Some(frame)), None),
    }
  }

  /// Cancel-safe frame parser.
  ///
  /// All `.await` points (read_buf calls) happen BEFORE any bytes are consumed
  /// from the buffer. Consumption (advance, split_to) only happens in Phase 3,
  /// which has no `.await` points. This makes the parser safe to use in
  /// `tokio::select!` — if the future is dropped mid-parse, the buffer is
  /// unchanged and the next call starts cleanly.
  async fn parse_frame_header<'a, S>(
    &mut self,
    stream: &mut S,
  ) -> Result<Frame<'a>, WebSocketError>
  where
    S: AsyncRead + Unpin,
  {
    macro_rules! eof {
      ($n:expr) => {{
        if $n == 0 {
          return Err(WebSocketError::UnexpectedEOF);
        }
      }};
    }

    // ── Phase 1: Peek at header to determine frame size (no consumption) ──

    // Need at least 2 bytes for basic header
    while self.buffer.remaining() < 2 {
      eof!(stream.read_buf(&mut self.buffer).await?);
    }

    // Peek (don't consume) first 2 bytes
    let byte0 = self.buffer[0];
    let byte1 = self.buffer[1];

    let fin = byte0 & 0b10000000 != 0;
    let rsv1 = byte0 & 0b01000000 != 0;
    let rsv2 = byte0 & 0b00100000 != 0;
    let rsv3 = byte0 & 0b00010000 != 0;

    // RSV bits check — reject ALL RSV bits unless an extension is negotiated.
    // permessage-deflate is not implemented, so RSV1 must also be rejected.
    if rsv1 || rsv2 || rsv3 {
      return Err(WebSocketError::ReservedBitsNotZero);
    }

    let opcode = frame::OpCode::try_from(byte0 & 0b00001111)?;
    let masked = byte1 & 0b10000000 != 0;

    // RFC 6455 §5.1: server MUST reject unmasked client frames
    if self.role == Role::Server && !masked {
      return Err(WebSocketError::UnmaskedClientFrame);
    }

    let length_code = byte1 & 0x7F;

    let extra: usize = match length_code {
      126 => 2,
      127 => 8,
      _ => 0,
    };
    let mask_size: usize = if masked { 4 } else { 0 };
    let header_size = 2 + extra + mask_size;

    // Wait for full header (still peek-only, nothing consumed)
    while self.buffer.remaining() < header_size {
      eof!(stream.read_buf(&mut self.buffer).await?);
    }

    // Peek at extended length (don't consume)
    let payload_len: usize = match extra {
      0 => usize::from(length_code),
      2 => u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize,
      #[cfg(any(target_pointer_width = "64", target_pointer_width = "128"))]
      8 => u64::from_be_bytes([
        self.buffer[2], self.buffer[3], self.buffer[4], self.buffer[5],
        self.buffer[6], self.buffer[7], self.buffer[8], self.buffer[9],
      ]) as usize,
      #[cfg(any(
        target_pointer_width = "8",
        target_pointer_width = "16",
        target_pointer_width = "32"
      ))]
      8 => match usize::try_from(u64::from_be_bytes([
        self.buffer[2], self.buffer[3], self.buffer[4], self.buffer[5],
        self.buffer[6], self.buffer[7], self.buffer[8], self.buffer[9],
      ])) {
        Ok(length) => length,
        Err(_) => return Err(WebSocketError::FrameTooLarge),
      },
      _ => unreachable!(),
    };

    // Peek at mask (don't consume)
    let mask = if masked {
      let m = 2 + extra;
      Some([self.buffer[m], self.buffer[m + 1], self.buffer[m + 2], self.buffer[m + 3]])
    } else {
      None
    };

    // Validation (before consuming anything)
    if frame::is_control(opcode) && !fin {
      return Err(WebSocketError::ControlFrameFragmented);
    }

    // RFC 6455 §5.5: ALL control frames must have payload ≤ 125 bytes
    if frame::is_control(opcode) && payload_len > 125 {
      return Err(WebSocketError::ControlFrameTooLarge);
    }

    if payload_len > self.max_message_size {
      return Err(WebSocketError::FrameTooLarge);
    }

    // ── Phase 2: Wait for complete frame (still peek-only) ──

    let total_size = header_size + payload_len;
    // Reserve extra for next frame header to avoid a read syscall next time
    self.buffer.reserve(total_size + MAX_HEADER_SIZE);
    while self.buffer.remaining() < total_size {
      eof!(stream.read_buf(&mut self.buffer).await?);
    }

    // ── Phase 3: Consume entire frame at once (NO await points) ──

    // Skip header bytes
    self.buffer.advance(header_size);
    // Extract payload
    let payload = self.buffer.split_to(payload_len);
    let frame = Frame::new(fin, opcode, mask, Payload::Bytes(payload));
    Ok(frame)
  }

  /// Synchronous (non-async) attempt to parse a complete frame from the buffer.
  /// Returns None if not enough data is buffered. Never does I/O.
  /// Used by try_read_wisp_frame for batch inbound processing.
  pub fn try_parse_frame_buffered(&mut self) -> Option<Result<Frame<'_>, WebSocketError>> {
    use bytes::Buf;

    // Need at least 2 bytes for basic header
    if self.buffer.remaining() < 2 {
      return None;
    }

    let byte0 = self.buffer[0];
    let byte1 = self.buffer[1];

    let fin = byte0 & 0b10000000 != 0;
    let rsv1 = byte0 & 0b01000000 != 0;
    let rsv2 = byte0 & 0b00100000 != 0;
    let rsv3 = byte0 & 0b00010000 != 0;

    if rsv1 || rsv2 || rsv3 {
      return Some(Err(WebSocketError::ReservedBitsNotZero));
    }

    let opcode = match frame::OpCode::try_from(byte0 & 0b00001111) {
      Ok(op) => op,
      Err(e) => return Some(Err(e)),
    };
    let masked = byte1 & 0b10000000 != 0;

    if self.role == Role::Server && !masked {
      return Some(Err(WebSocketError::UnmaskedClientFrame));
    }

    let length_code = byte1 & 0x7F;
    let extra: usize = match length_code { 126 => 2, 127 => 8, _ => 0 };
    let mask_size: usize = if masked { 4 } else { 0 };
    let header_size = 2 + extra + mask_size;

    if self.buffer.remaining() < header_size {
      return None; // not enough header data buffered
    }

    let payload_len: usize = match extra {
      0 => usize::from(length_code),
      2 => u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize,
      8 => u64::from_be_bytes([
        self.buffer[2], self.buffer[3], self.buffer[4], self.buffer[5],
        self.buffer[6], self.buffer[7], self.buffer[8], self.buffer[9],
      ]) as usize,
      _ => unreachable!(),
    };

    let mask = if masked {
      let m = 2 + extra;
      Some([self.buffer[m], self.buffer[m + 1], self.buffer[m + 2], self.buffer[m + 3]])
    } else {
      None
    };

    if frame::is_control(opcode) && !fin {
      return Some(Err(WebSocketError::ControlFrameFragmented));
    }
    if frame::is_control(opcode) && payload_len > 125 {
      return Some(Err(WebSocketError::ControlFrameTooLarge));
    }
    if payload_len > self.max_message_size {
      return Some(Err(WebSocketError::FrameTooLarge));
    }

    let total_size = header_size + payload_len;
    if self.buffer.remaining() < total_size {
      return None; // not enough payload data buffered
    }

    // Consume the frame (no await points — same as Phase 3 of parse_frame_header)
    self.buffer.advance(header_size);
    let payload = self.buffer.split_to(payload_len);
    let frame = Frame::new(fin, opcode, mask, Payload::Bytes(payload));
    Some(Ok(frame))
  }
}

impl WriteHalf {
  pub fn after_handshake(role: Role) -> Self {
    Self {
      role,
      closed: false,
      auto_apply_mask: true,
      vectored: true,
      writev_threshold: 1024,
      write_buffer: Vec::with_capacity(2),
    }
  }

  /// Writes a frame to the provided stream.
  pub async fn write_frame<'a, S>(
    &'a mut self,
    stream: &mut S,
    mut frame: Frame<'a>,
  ) -> Result<(), WebSocketError>
  where
    S: AsyncWrite + Unpin,
  {
    if self.role == Role::Client && self.auto_apply_mask {
      frame.mask();
    }

    if frame.opcode == OpCode::Close {
      self.closed = true;
    } else if self.closed {
      return Err(WebSocketError::ConnectionClosed);
    }

    if self.vectored && frame.payload.len() > self.writev_threshold {
      frame.writev(stream).await?;
    } else {
      let text = frame.write(&mut self.write_buffer);
      stream.write_all(text).await?;
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const _: () = {
    const fn assert_unsync<S>() {
      // Generic trait with a blanket impl over `()` for all types.
      trait AmbiguousIfImpl<A> {
        // Required for actually being able to reference the trait.
        fn some_item() {}
      }

      impl<T: ?Sized> AmbiguousIfImpl<()> for T {}

      // Used for the specialized impl when *all* traits in
      // `$($t)+` are implemented.
      #[allow(dead_code)]
      struct Invalid;

      impl<T: ?Sized + Sync> AmbiguousIfImpl<Invalid> for T {}

      // If there is only one specialized trait impl, type inference with
      // `_` can be resolved and this can compile. Fails to compile if
      // `$x` implements `AmbiguousIfImpl<Invalid>`.
      let _ = <S as AmbiguousIfImpl<_>>::some_item;
    }
    assert_unsync::<WebSocket<tokio::net::TcpStream>>();
  };
}
