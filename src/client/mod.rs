//! Worker-compatible storage client module.
//!
//! Provides a Cloudflare Workers-compatible client for talking to
//! `storage.babbage.systems` with full BRC-103/104 authentication.
//!
//! Unlike the `StorageClient` in `bsv-wallet-toolbox` (which uses reqwest, tokio,
//! and `Peer<W, SimplifiedFetchTransport>`), this implementation uses `worker::Fetch`
//! with inline BRC-103/104 handshake and signing, making it WASM-compatible.

pub mod json_rpc;
mod storage;

pub use json_rpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
pub use storage::WorkerStorageClient;
