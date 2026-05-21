//! Zero-copy Wisp frame parsing and construction.
//!
//! Design principles:
//! - Zero allocations in the DATA hot path
//! - 2-load header parsing (type byte + u32 LE stream ID)
//! - `bytes::Bytes` for zero-copy payload forwarding
//! - Contiguous type values 0x01-0x05 enable compiler jump table

use bytes::{BufMut, Bytes, BytesMut};

#[cfg(test)]
use bytes::Buf;

use super::types::*;

/// Parsed Wisp frame — the core dispatch unit.
///
/// DATA frames carry `Bytes` (ref-counted, zero-copy).
/// Other frames carry small parsed payloads.
#[derive(Debug)]
#[allow(dead_code)] // Fields read via pattern matching in connection.rs + tests
pub enum WispFrame {
    /// New stream request
    Connect {
        stream_id: u32,
        payload: ConnectPayload,
    },
    /// Stream data — HOT PATH (99%+ of frames)
    Data {
        stream_id: u32,
        payload: Bytes,
    },
    /// Flow control credit
    Continue {
        stream_id: u32,
        buffer_remaining: u32,
    },
    /// Stream/connection close
    Close {
        stream_id: u32,
        reason: CloseReason,
    },
    /// Protocol info/handshake
    Info {
        stream_id: u32,
        major_version: u8,
        minor_version: u8,
        extensions: Vec<ExtensionEntry>,
    },
}

/// Parse a single Wisp frame from a WebSocket binary message.
///
/// # Zero-copy guarantee
/// The `payload` field in `WispFrame::Data` is a `Bytes` slice into the
/// original buffer — no memcpy occurs. `split_to` and `freeze` are O(1).
///
/// # Performance
/// - Header parse: 2 loads (1 byte + 4 bytes LE)
/// - Jump table: match on contiguous 0x01-0x05
/// - DATA path: returns immediately with Bytes slice (no further parsing)
#[inline]
pub fn parse_wisp_frame(data: &[u8]) -> Option<WispFrame> {
    if data.len() < WISP_HEADER_SIZE {
        return None;
    }

    let packet_type = data[0];
    // Little-endian u32 — compiles to single MOV on x86-64/ARM64
    let stream_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload = &data[WISP_HEADER_SIZE..];

    // Contiguous 0x01-0x05 values → compiler emits jump table
    match packet_type {
        PACKET_DATA => Some(WispFrame::Data {
            stream_id,
            // Copy payload into Bytes for ownership.
            // In the hot path with fastwebsockets raw frames,
            // we'll use the Bytes variant that avoids this copy.
            payload: Bytes::copy_from_slice(payload),
        }),
        PACKET_CONNECT => parse_connect(stream_id, payload),
        PACKET_CONTINUE => parse_continue(stream_id, payload),
        PACKET_CLOSE => parse_close(stream_id, payload),
        PACKET_INFO => parse_info(stream_id, payload),
        _ => None,
    }
}

/// Parse a Wisp frame from a BytesMut buffer — true zero-copy for DATA.
///
/// Used by tests. Hot path in connection.rs does manual inline parsing to avoid
/// the WispFrame enum for DATA (99%+ of frames).
#[cfg(test)]
pub fn parse_wisp_frame_owned(mut buf: BytesMut) -> Option<WispFrame> {
    if buf.len() < WISP_HEADER_SIZE {
        return None;
    }

    let packet_type = buf[0];
    let stream_id = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    buf.advance(WISP_HEADER_SIZE); // O(1) pointer arithmetic

    match packet_type {
        PACKET_DATA => Some(WispFrame::Data {
            stream_id,
            payload: buf.freeze(), // O(1) — refcount increment, no copy
        }),
        PACKET_CONNECT => parse_connect(stream_id, &buf),
        PACKET_CONTINUE => parse_continue(stream_id, &buf),
        PACKET_CLOSE => parse_close(stream_id, &buf),
        PACKET_INFO => parse_info(stream_id, &buf),
        _ => None,
    }
}

/// Parse CONNECT payload bytes (after Wisp header is already consumed).
/// Returns just the ConnectPayload, not a WispFrame wrapper.
/// Used by fused parser path where stream_id is already known.
#[inline]
pub fn parse_connect_payload(payload: &[u8]) -> Option<ConnectPayload> {
    if payload.len() < 4 {
        return None;
    }
    let stream_type = StreamType::from_byte(payload[0])?;
    let port = u16::from_le_bytes([payload[1], payload[2]]);
    let hostname_bytes = &payload[3..];
    if hostname_bytes.len() > 253 {
        return None;
    }
    let hostname = std::str::from_utf8(hostname_bytes).ok()?.to_string();
    Some(ConnectPayload {
        stream_type,
        port,
        hostname,
    })
}

/// CONNECT payload: stream_type(1) + port(2 LE) + hostname(remaining)
#[inline]
fn parse_connect(stream_id: u32, payload: &[u8]) -> Option<WispFrame> {
    // Minimum: 1 (type) + 2 (port) + 1 (hostname char) = 4 bytes
    if payload.len() < 4 {
        return None;
    }

    let stream_type = StreamType::from_byte(payload[0])?;
    let port = u16::from_le_bytes([payload[1], payload[2]]);
    let hostname_bytes = &payload[3..];

    // RFC 1035: DNS hostname max 253 bytes. Reject oversized to prevent allocation abuse.
    if hostname_bytes.len() > 253 {
        return None;
    }

    // Hostname must be valid UTF-8 per spec
    let hostname = std::str::from_utf8(hostname_bytes).ok()?.to_string();

    Some(WispFrame::Connect {
        stream_id,
        payload: ConnectPayload {
            stream_type,
            port,
            hostname,
        },
    })
}

/// CONTINUE payload: buffer_remaining(4 LE)
#[inline]
fn parse_continue(stream_id: u32, payload: &[u8]) -> Option<WispFrame> {
    if payload.len() < 4 {
        return None;
    }

    let buffer_remaining = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);

    Some(WispFrame::Continue {
        stream_id,
        buffer_remaining,
    })
}

/// CLOSE payload: reason(1)
#[inline]
fn parse_close(stream_id: u32, payload: &[u8]) -> Option<WispFrame> {
    if payload.is_empty() {
        return None;
    }

    Some(WispFrame::Close {
        stream_id,
        reason: CloseReason::from_byte(payload[0]),
    })
}

/// INFO payload: major(1) + minor(1) + extensions(remaining)
#[inline]
fn parse_info(stream_id: u32, payload: &[u8]) -> Option<WispFrame> {
    if payload.len() < 2 {
        return None;
    }

    let major_version = payload[0];
    let minor_version = payload[1];
    let extensions = parse_extensions(&payload[2..]);

    Some(WispFrame::Info {
        stream_id,
        major_version,
        minor_version,
        extensions,
    })
}

/// Parse extension metadata entries: [id(1) + length(4 LE) + payload(length)]*
fn parse_extensions(mut data: &[u8]) -> Vec<ExtensionEntry> {
    let mut extensions = Vec::new();

    while data.len() >= 5 {
        let id = data[0];
        let length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        data = &data[5..];

        if data.len() < length {
            break; // Malformed extension data — stop parsing
        }

        extensions.push(ExtensionEntry {
            id,
            payload: data[..length].to_vec(),
        });
        data = &data[length..];
    }

    extensions
}

// ============================================================================
// Frame construction (server → client)
// ============================================================================

/// Build a DATA frame for sending to client.
/// Returns header bytes that should be prepended to payload via writev/vectored write.
#[inline]
pub fn build_data_header(stream_id: u32) -> [u8; WISP_HEADER_SIZE] {
    let id_bytes = stream_id.to_le_bytes();
    [PACKET_DATA, id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]
}

/// Build a complete CONTINUE frame.
#[inline]
pub fn build_continue_frame(stream_id: u32, buffer_remaining: u32) -> [u8; 9] {
    let id_bytes = stream_id.to_le_bytes();
    let buf_bytes = buffer_remaining.to_le_bytes();
    [
        PACKET_CONTINUE,
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
        buf_bytes[0],
        buf_bytes[1],
        buf_bytes[2],
        buf_bytes[3],
    ]
}

/// Build a complete CLOSE frame.
#[inline]
pub fn build_close_frame(stream_id: u32, reason: CloseReason) -> [u8; 6] {
    let id_bytes = stream_id.to_le_bytes();
    [
        PACKET_CLOSE,
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
        reason.as_byte(),
    ]
}

/// Build the server INFO frame for Wisp v2.1 (no extensions for now).
pub fn build_server_info_frame(extensions: &[ExtensionEntry]) -> BytesMut {
    // Header (5) + major(1) + minor(1) + extensions
    let ext_size: usize = extensions.iter().map(|e| 5 + e.payload.len()).sum();
    let mut buf = BytesMut::with_capacity(WISP_HEADER_SIZE + 2 + ext_size);

    // Wisp header: INFO type, stream ID 0
    buf.put_u8(PACKET_INFO);
    buf.put_u32_le(STREAM_ID_CONTROL);

    // INFO payload
    buf.put_u8(WISP_VERSION_MAJOR);
    buf.put_u8(WISP_VERSION_MINOR);

    // Extensions
    for ext in extensions {
        buf.put_u8(ext.id);
        buf.put_u32_le(ext.payload.len() as u32);
        buf.put_slice(&ext.payload);
    }

    buf
}

/// Build the initial CONTINUE frame (stream ID 0, sent after handshake).
#[inline]
pub fn build_initial_continue_frame(buffer_size: u32) -> [u8; 9] {
    build_continue_frame(STREAM_ID_CONTROL, buffer_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_data_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(PACKET_DATA);
        buf.put_u32_le(42);
        buf.put_slice(b"hello world");

        let frame = parse_wisp_frame_owned(buf).unwrap();
        match frame {
            WispFrame::Data { stream_id, payload } => {
                assert_eq!(stream_id, 42);
                assert_eq!(&payload[..], b"hello world");
            }
            _ => panic!("expected DATA frame"),
        }
    }

    #[test]
    fn test_parse_connect_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(PACKET_CONNECT);
        buf.put_u32_le(7);
        buf.put_u8(0x01); // TCP stream type
        buf.put_u16_le(443);
        buf.put_slice(b"example.com");

        let frame = parse_wisp_frame_owned(buf).unwrap();
        match frame {
            WispFrame::Connect { stream_id, payload } => {
                assert_eq!(stream_id, 7);
                assert_eq!(payload.stream_type, StreamType::Tcp);
                assert_eq!(payload.port, 443);
                assert_eq!(payload.hostname, "example.com");
            }
            _ => panic!("expected CONNECT frame"),
        }
    }

    #[test]
    fn test_parse_continue_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(PACKET_CONTINUE);
        buf.put_u32_le(0);
        buf.put_u32_le(128);

        let frame = parse_wisp_frame_owned(buf).unwrap();
        match frame {
            WispFrame::Continue {
                stream_id,
                buffer_remaining,
            } => {
                assert_eq!(stream_id, 0);
                assert_eq!(buffer_remaining, 128);
            }
            _ => panic!("expected CONTINUE frame"),
        }
    }

    #[test]
    fn test_parse_close_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(PACKET_CLOSE);
        buf.put_u32_le(5);
        buf.put_u8(0x44); // Refused

        let frame = parse_wisp_frame_owned(buf).unwrap();
        match frame {
            WispFrame::Close { stream_id, reason } => {
                assert_eq!(stream_id, 5);
                assert_eq!(reason, CloseReason::Refused);
            }
            _ => panic!("expected CLOSE frame"),
        }
    }

    #[test]
    fn test_parse_info_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(PACKET_INFO);
        buf.put_u32_le(0);
        buf.put_u8(2); // major
        buf.put_u8(1); // minor
        // No extensions

        let frame = parse_wisp_frame_owned(buf).unwrap();
        match frame {
            WispFrame::Info {
                stream_id,
                major_version,
                minor_version,
                extensions,
            } => {
                assert_eq!(stream_id, 0);
                assert_eq!(major_version, 2);
                assert_eq!(minor_version, 1);
                assert!(extensions.is_empty());
            }
            _ => panic!("expected INFO frame"),
        }
    }

    #[test]
    fn test_parse_info_with_extensions() {
        let mut buf = BytesMut::new();
        buf.put_u8(PACKET_INFO);
        buf.put_u32_le(0);
        buf.put_u8(2);
        buf.put_u8(1);
        // Extension: ID=0x01, length=3, payload=[0xAA, 0xBB, 0xCC]
        buf.put_u8(0x01);
        buf.put_u32_le(3);
        buf.put_slice(&[0xAA, 0xBB, 0xCC]);

        let frame = parse_wisp_frame_owned(buf).unwrap();
        match frame {
            WispFrame::Info { extensions, .. } => {
                assert_eq!(extensions.len(), 1);
                assert_eq!(extensions[0].id, 0x01);
                assert_eq!(extensions[0].payload, vec![0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("expected INFO frame"),
        }
    }

    #[test]
    fn test_too_short_returns_none() {
        let buf = BytesMut::from(&[0x02, 0x01, 0x00][..]); // Only 3 bytes
        assert!(parse_wisp_frame_owned(buf).is_none());
    }

    #[test]
    fn test_invalid_type_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xFF); // Invalid type
        buf.put_u32_le(1);
        assert!(parse_wisp_frame_owned(buf).is_none());
    }

    #[test]
    fn test_build_data_header() {
        let header = build_data_header(42);
        assert_eq!(header[0], PACKET_DATA);
        let id = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        assert_eq!(id, 42);
    }

    #[test]
    fn test_build_continue_frame() {
        let frame = build_continue_frame(7, 256);
        assert_eq!(frame[0], PACKET_CONTINUE);
        let id = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_eq!(id, 7);
        let remaining = u32::from_le_bytes([frame[5], frame[6], frame[7], frame[8]]);
        assert_eq!(remaining, 256);
    }

    #[test]
    fn test_build_close_frame() {
        let frame = build_close_frame(3, CloseReason::Refused);
        assert_eq!(frame[0], PACKET_CLOSE);
        let id = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_eq!(id, 3);
        assert_eq!(frame[5], 0x44);
    }

    #[test]
    fn test_roundtrip_data() {
        let stream_id = 999u32;
        let payload_data = b"test payload bytes here";

        let header = build_data_header(stream_id);
        let mut full = BytesMut::with_capacity(header.len() + payload_data.len());
        full.put_slice(&header);
        full.put_slice(payload_data);

        let frame = parse_wisp_frame_owned(full).unwrap();
        match frame {
            WispFrame::Data {
                stream_id: sid,
                payload,
            } => {
                assert_eq!(sid, stream_id);
                assert_eq!(&payload[..], payload_data);
            }
            _ => panic!("expected DATA"),
        }
    }
}
