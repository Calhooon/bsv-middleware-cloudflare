//! Utility functions.

pub mod cors;

pub use cors::{cors_headers, handle_cors_preflight, CorsConfig};
