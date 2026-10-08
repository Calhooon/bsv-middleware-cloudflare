//! Request/response types for BSV Auth Cloudflare middleware.
//!
//! [`AuthContext`], [`PaymentContext`] and [`BsvPayment`] are
//! `bsv_middleware_core::types`, re-exported at their 0.3 paths. What stays
//! here is bound to this runtime: the stored records and the clock.

use serde::{Deserialize, Serialize};

pub use bsv_middleware_core::types::{AuthContext, BsvPayment, PaymentContext};

/// Generic error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Status string ("error").
    pub status: &'static str,
    /// Error code.
    pub code: String,
    /// Human-readable description.
    pub description: String,
}

impl ErrorResponse {
    /// Creates a new error response.
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            status: "error",
            code: code.into(),
            description: description.into(),
        }
    }
}

/// Session data stored in KV.
///
/// This represents the server-side session state for a BRC-103/104 authenticated peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    /// The session nonce (server's nonce).
    pub session_nonce: String,
    /// The peer's identity public key (hex).
    pub peer_identity_key: String,
    /// The peer's last known nonce.
    pub peer_nonce: Option<String>,
    /// Whether the session has completed mutual authentication.
    pub is_authenticated: bool,
    /// Whether certificates are required for this session.
    pub certificates_required: bool,
    /// Whether certificates have been validated.
    pub certificates_validated: bool,
    /// Timestamp when the session was created (ms since epoch).
    // bounded: a millisecond stamp
    pub created_at: u64,
    /// Timestamp of last activity (ms since epoch).
    // bounded: a millisecond stamp
    pub last_update: u64,
}

/// The three fields the BRC-103 signatures are keyed on, for the core's
/// sign and verify functions.
impl From<&StoredSession> for bsv_middleware_core::SessionBinding {
    fn from(session: &StoredSession) -> Self {
        bsv_middleware_core::SessionBinding::new(
            session.session_nonce.clone(),
            session.peer_identity_key.clone(),
            session.peer_nonce.clone(),
        )
    }
}

impl StoredSession {
    /// Creates a new session with the given parameters.
    pub fn new(session_nonce: String, peer_identity_key: String) -> Self {
        let now = current_time_ms();
        Self {
            session_nonce,
            peer_identity_key,
            peer_nonce: None,
            is_authenticated: false,
            certificates_required: false,
            certificates_validated: false,
            created_at: now,
            last_update: now,
        }
    }

    /// Updates the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_update = current_time_ms();
    }
}

/// Payment record stored in KV.
///
/// This represents a payment received by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredPayment {
    /// Transaction ID.
    pub txid: String,
    /// Output index in the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub satoshis: u64,
    /// Sender's identity public key (hex).
    pub sender_identity_key: String,
    /// Derivation prefix used.
    pub derivation_prefix: String,
    /// Derivation suffix used.
    pub derivation_suffix: String,
    /// Timestamp when payment was received (ms since epoch).
    pub created_at: u64,
    /// Whether this output has been spent.
    pub spent: bool,
}

/// Returns current time in milliseconds since Unix epoch.
pub fn current_time_ms() -> u64 {
    js_sys::Date::now() as u64
}
