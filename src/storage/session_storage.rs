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
//! The method set is exactly what the middleware requires: session lookup and
//! persistence for the auth middleware
//! ([`process_auth_with_storage`](crate::process_auth_with_storage) and its
//! handshake helpers), plus single-use nonce consumption shared by the auth
//! replay protection and the payment middleware
//! ([`process_payment_with_storage`](crate::process_payment_with_storage)).

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

    /// Records `nonce` (within `scope`) as consumed, once.
    ///
    /// Returns `Ok(true)` if the nonce had not been recorded before (first
    /// use — proceed), `Ok(false)` if it was already recorded (replay —
    /// reject). Storage failures must be surfaced as `Err` so callers can
    /// fail closed; silently returning `Ok(true)` on a storage fault would
    /// disable replay protection.
    ///
    /// Used for two kinds of single-use values:
    /// - **BRC-104 per-request nonces** (`x-bsv-auth-nonce` on General
    ///   messages), scoped by the server session nonce, with
    ///   `ttl_seconds = Some(session TTL)`.
    /// - **BRC-29 payment derivation prefixes**, scoped by
    ///   [`PAYMENT_NONCE_SCOPE`](crate::middleware::payment::PAYMENT_NONCE_SCOPE),
    ///   with `ttl_seconds = None` (the prefix HMAC never expires, so the
    ///   consumption record must not either).
    ///
    /// # Consistency requirements
    ///
    /// Implementations should use an **atomic put-if-absent** where the
    /// backend supports it (e.g. `INSERT OR IGNORE` + row-count in a Durable
    /// Object SQLite database) — that yields exact at-most-once semantics.
    ///
    /// The reference TS middleware stack (`@bsv/auth-express-middleware`
    /// 1.2.3 / `@bsv/sdk` `Peer.processGeneralMessage`, and
    /// `@bsv/payment-express-middleware` 1.2.3 `verifyNonce`) performs **no**
    /// consumption tracking at all — this method is a deliberate hardening
    /// divergence (the-composer audit issues #30/#44).
    ///
    /// Backends without an atomic primitive (Cloudflare KV) may implement
    /// this as read-then-write; see
    /// [`KvSessionStorage`](crate::storage::KvSessionStorage) for the precise
    /// residual replay window that leaves.
    ///
    /// `ttl_seconds`: `Some(t)` = the record may expire after `t` seconds;
    /// `None` = retain indefinitely. Implementations may retain records
    /// longer than requested (never shorter, except backend-imposed minimums
    /// such as Cloudflare KV's 60-second TTL floor, which implementations
    /// must clamp *up* to).
    async fn try_consume_nonce(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<bool>;

    /// Best-effort release of a previously consumed nonce.
    ///
    /// The payment middleware calls this when `internalizeAction` fails with
    /// a transport/wallet **error** (as opposed to an explicit
    /// `accepted: false` rejection): the payment was not processed, so the
    /// honest client must be able to retry the same payment. Releasing never
    /// grants replay value — a released nonce still has to pass full
    /// verification and wallet internalization again to be of any use.
    async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    /// In-memory `SessionStorage` used to exercise the trait contract.
    ///
    /// `try_consume_nonce` here is genuinely atomic (single-threaded map
    /// insert), i.e. the semantics a Durable Object SQLite implementation
    /// provides in production.
    #[derive(Default)]
    struct MemorySessionStorage {
        sessions: RefCell<HashMap<String, StoredSession>>,
        nonces: RefCell<HashSet<String>>,
    }

    fn nonce_key(scope: &str, nonce: &str) -> String {
        format!("{}:{}", scope, nonce)
    }

    #[async_trait(?Send)]
    impl SessionStorage for MemorySessionStorage {
        async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
            Ok(self.sessions.borrow().get(session_nonce).cloned())
        }

        async fn get_session_by_identity(
            &self,
            identity_key_hex: &str,
        ) -> Result<Option<StoredSession>> {
            Ok(self
                .sessions
                .borrow()
                .values()
                .filter(|s| s.peer_identity_key == identity_key_hex)
                .max_by_key(|s| s.last_update)
                .cloned())
        }

        async fn save_session(&self, session: &StoredSession) -> Result<()> {
            self.sessions
                .borrow_mut()
                .insert(session.session_nonce.clone(), session.clone());
            Ok(())
        }

        async fn update_session(&self, session: &StoredSession) -> Result<()> {
            self.save_session(session).await
        }

        async fn try_consume_nonce(
            &self,
            scope: &str,
            nonce: &str,
            _ttl_seconds: Option<u64>,
        ) -> Result<bool> {
            // HashSet::insert returns true only when the value was absent —
            // atomic put-if-absent.
            Ok(self.nonces.borrow_mut().insert(nonce_key(scope, nonce)))
        }

        async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()> {
            self.nonces.borrow_mut().remove(&nonce_key(scope, nonce));
            Ok(())
        }
    }

    /// Compile-time check: the trait must stay object safe so middleware can
    /// take `&dyn SessionStorage`.
    fn _assert_object_safe(_storage: &dyn SessionStorage) {}

    #[tokio::test]
    async fn test_consume_nonce_first_use_is_fresh() {
        let storage = MemorySessionStorage::default();
        let fresh = storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        assert!(fresh, "first consumption must report fresh");
    }

    #[tokio::test]
    async fn test_consume_nonce_second_use_is_replay() {
        let storage = MemorySessionStorage::default();
        storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        let second = storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        assert!(!second, "byte-identical replay must be rejected");
    }

    #[tokio::test]
    async fn test_consume_nonce_is_scoped() {
        let storage = MemorySessionStorage::default();
        storage
            .try_consume_nonce("session-a", "nonce-1", Some(3600))
            .await
            .unwrap();
        let other_scope = storage
            .try_consume_nonce("session-b", "nonce-1", Some(3600))
            .await
            .unwrap();
        assert!(
            other_scope,
            "same nonce under a different scope is independent"
        );
    }

    #[tokio::test]
    async fn test_release_nonce_allows_reuse() {
        let storage = MemorySessionStorage::default();
        storage
            .try_consume_nonce("payment", "prefix-1", None)
            .await
            .unwrap();
        storage.release_nonce("payment", "prefix-1").await.unwrap();
        let again = storage
            .try_consume_nonce("payment", "prefix-1", None)
            .await
            .unwrap();
        assert!(again, "released nonce must be consumable again");
    }

    #[tokio::test]
    async fn test_release_unknown_nonce_is_noop() {
        let storage = MemorySessionStorage::default();
        // Must not error on releasing a nonce that was never consumed.
        storage.release_nonce("payment", "unknown").await.unwrap();
    }
}
