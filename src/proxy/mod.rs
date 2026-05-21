//! TCP/UDP proxy stream management.
//!
//! Each stream is independently managed within a connection's stream table.
//! TCP streams use CONTINUE flow control; UDP streams bypass it entirely.

pub mod stream;

// Re-exports not needed — connection.rs uses `use crate::proxy::stream::*` directly
