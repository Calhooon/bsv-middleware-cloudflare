//! Request/response types for BSV Auth Cloudflare middleware.

use serde::{Deserialize, Serialize};

/// Authentication context attached to authenticated requests.
///
/// This provides information about the authenticated peer to request handlers.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated peer's identity key (compressed public key hex, 66 chars).
    pub identity_key: String,
    /// Whether the request is fully authenticated.
    pub is_authenticated: bool,
}

impl AuthContext {
    /// Creates an authenticated context with the given identity key.
    pub fn authenticated(identity_key: String) -> Self {
        Self {
            identity_key,
            is_authenticated: true,
        }
    }

    /// Creates an unauthenticated context (for requests allowed without auth).
    pub fn unauthenticated() -> Self {
        Self {
            identity_key: "unknown".to_string(),
            is_authenticated: false,
        }
    }
}

/// Payment context attached to requests that include payment.
///
/// Matches Express's `req.payment = { satoshisPaid, accepted, tx }`.
#[derive(Debug, Clone)]
pub struct PaymentContext {
    /// Amount paid in satoshis.
    /// Express: `satoshisPaid`
    pub satoshis_paid: u64,
    /// Whether payment was accepted by the wallet.
    /// Express: `accepted`
    pub accepted: bool,
    /// The base64-encoded transaction (from the payment header).
    /// Express: `tx`
    pub tx: Option<String>,
}

/// BSV Payment data from x-bsv-payment header.
///
/// This structure represents the payment information sent by clients
/// in the `x-bsv-payment` header for paid requests.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BsvPayment {
    /// Derivation prefix from the 402 response.
    pub derivation_prefix: String,
    /// Derivation suffix chosen by the client.
    pub derivation_suffix: String,
    /// Base64 encoded BEEF transaction.
    pub transaction: String,
}

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub created_at: u64,
    /// Timestamp of last activity (ms since epoch).
    pub last_update: u64,
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
