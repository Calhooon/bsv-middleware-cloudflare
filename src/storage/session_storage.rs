//! Pluggable session storage abstraction for BRC-103/104 authentication.
//!
//! The [`SessionStorage`] trait lets consumers back BRC-103/104 session state
//! with any store they like (Cloudflare KV, a Durable Object SQLite database,
//! an in-memory map for tests, etc.) instead of being locked into Cloudflare KV.
//!
//! The default implementation, [`KvSessionStorage`](crate::storage::KvSessionStorage),
//! is still used by the backward-compatible [`process_auth`](crate::process_auth)
//! entry point. Consumers wanting a different backend implement this trait and
//! call [`process_auth_with_storage`](crate::process_auth_with_storage).
//!
//! The method set is exactly what the auth middleware
//! ([`process_auth_with_storage`](crate::process_auth_with_storage) and its
//! handshake helpers) requires — no more, no less.

use crate::error::Result;
use crate::types::StoredSession;
use async_trait::async_trait;

/// Pluggable backing store for BRC-103/104 authentication sessions.
///
/// Implementations must be `Send + Sync` so they can be shared across the
/// async middleware. All methods return the crate's [`Result`] type.
///
/// This trait captures exactly the operations the auth middleware performs:
/// looking up a session by nonce or by peer identity key, persisting a new
/// session during the handshake, and updating an existing session after a
/// verified message.
#[async_trait(?Send)]
pub trait SessionStorage {
    /// Retrieves a session by its (server) session nonce.
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>>;

    /// Finds an existing session for a peer identity key.
    ///
    /// Returns the most recently updated session if several exist.
    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>>;

    /// Persists a freshly created session (used during the handshake).
    ///
    /// Implementations should apply a TTL-based expiration where supported.
    async fn save_session(&self, session: &StoredSession) -> Result<()>;

    /// Updates an existing session (e.g. touch timestamp, mark certificates
    /// validated).
    async fn update_session(&self, session: &StoredSession) -> Result<()>;
}
