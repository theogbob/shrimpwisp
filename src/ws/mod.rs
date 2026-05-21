//! WebSocket handling via fastwebsockets + Hyper upgrade.
//!
//! Returns raw WebSocket (no FragmentCollector) — Wisp binary frames
//! are never fragmented, so the collector is dead overhead.
//! Ping/pong handled manually in the dispatch loop.

pub mod upgrade;

// Re-exports not needed — connection.rs uses `use crate::ws::upgrade::*` directly
