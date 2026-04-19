//! JSON-RPC 2.0 types for storage server communication.
//!
//! Minimal types matching the storage server's JSON-RPC protocol.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC version string.
pub const JSON_RPC_VERSION: &str = "2.0";

/// JSON-RPC request.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<Value>,
    pub id: u64,
}

impl JsonRpcRequest {
    pub fn new(id: u64, method: &str, params: Vec<Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            method: method.to_string(),
            params,
            id,
        }
    }
}

/// JSON-RPC response.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
    pub id: u64,
}

/// JSON-RPC error object.
///
/// Some servers (e.g., storage.babbage.systems) return non-standard error objects
/// with `{isError, name, message}` instead of `{code, message, data}`.
/// All fields are optional to handle both formats.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcError {
    #[serde(default)]
    pub code: Option<i32>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
    /// Non-standard: error name (e.g., "TypeError")
    #[serde(default)]
    pub name: Option<String>,
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self.message.as_deref().unwrap_or("unknown error");
        match (self.code, self.name.as_deref()) {
            (Some(code), _) => write!(f, "JSON-RPC error {}: {}", code, msg),
            (None, Some(name)) => write!(f, "JSON-RPC error ({}): {}", name, msg),
            _ => write!(f, "JSON-RPC error: {}", msg),
        }
    }
}
