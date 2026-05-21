//! Wisp v2.1 Protocol Implementation
//!
//! Zero-copy packet parsing and construction.
//! The 5-byte header (type u8 + stream_id u32 LE) enables:
//! - 2-load parsing (no allocation)
//! - Jump table dispatch (contiguous 0x01-0x05)
//! - Direct payload forwarding (no copy for DATA packets)

pub mod frame;
pub mod types;

// Re-exports used by connection.rs (glob import)
// frame:: items used directly via `use crate::protocol::frame::*`
// types:: items used directly via `use crate::protocol::types::*`
