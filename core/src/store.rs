//! The single-use stores as traits: a host implements them over its own
//! backend (a KV namespace, a Durable Object, a SQL table, a map in a test).
//!
//! Two shapes, one idea: an atomic put-if-absent.
//!
//! - [`PaymentNonceStore`]: scoped single-use values (a BRC-104 per-request
//!   nonce under its session, a BRC-29 derivation prefix under
//!   [`PAYMENT_NONCE_SCOPE`]), consumed ONCE, released best-effort when the
//!   step they guarded failed before taking effect.
//! - [`ClaimStore`]: an unscoped claim keyed by one string, recorded with the
//!   claiming agent, for hosts that run their own payment flow (a payment
//!   nonce claimed after verification and before internalize) or need an
//!   idempotency key (a refund issued at most once per payment).
//!
//! Both fail closed by contract: a storage fault is `Err`, never `Ok(true)`,
//! so an outage can never disable replay protection. What a host does with
//! the `Err` (refuse, or fall back to another guard) is its policy.

use std::fmt;
use std::future::Future;

/// Nonce scope under which consumed BRC-29 payment derivation prefixes are
/// recorded in a [`PaymentNonceStore`].
pub const PAYMENT_NONCE_SCOPE: &str = "payment-derivation-prefix";

/// A storage fault. The store could not say whether the value was fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(String);

impl StoreError {
    /// A storage fault with its reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// The reason.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// A store of consumed single-use values, scoped.
pub trait PaymentNonceStore {
    /// Records `nonce` (within `scope`) as consumed, once.
    ///
    /// `Ok(true)`: first use, proceed. `Ok(false)`: already recorded, a
    /// replay, reject. `Err`: the store could not answer; the caller fails
    /// closed. `ttl_seconds = None` retains the record indefinitely (a
    /// derivation prefix never expires, so neither may its consumption).
    fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> impl Future<Output = Result<bool, StoreError>>;

    /// Best-effort release of a consumed value, so an honest client can
    /// retry after a step that failed before taking effect. Releasing never
    /// grants replay value: the value still has to pass every check again.
    fn release(&self, scope: &str, nonce: &str) -> impl Future<Output = Result<(), StoreError>>;
}

/// An atomic claim keyed by one string.
pub trait ClaimStore {
    /// Claim `key` for `agent` (recorded for diagnostics only).
    ///
    /// `Ok(true)`: this call won the claim. `Ok(false)`: already claimed, a
    /// concurrent or sequential duplicate. `Err`: storage fault.
    fn claim(&self, key: &str, agent: &str) -> impl Future<Output = Result<bool, StoreError>>;

    /// Release a claim (best-effort), so the same key can be claimed again.
    fn release(&self, key: &str) -> impl Future<Output = Result<(), StoreError>>;
}

/// An in-memory [`PaymentNonceStore`] and [`ClaimStore`]: a `HashSet`
/// insert, which is a genuine put-if-absent on one thread. For tests and
/// single-process hosts; a fault can be injected to exercise fail-closed
/// paths.
#[derive(Default)]
pub struct MemoryStore {
    seen: std::cell::RefCell<std::collections::HashSet<String>>,
    fail: std::cell::Cell<bool>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every call fail with a storage fault (or stop doing so).
    pub fn fail(&self, fail: bool) {
        self.fail.set(fail);
    }

    /// Whether `nonce` under `scope` is recorded as consumed.
    pub fn is_consumed(&self, scope: &str, nonce: &str) -> bool {
        self.seen.borrow().contains(&format!("{scope}:{nonce}"))
    }

    /// The number of recorded values, all scopes and claims.
    pub fn len(&self) -> usize {
        self.seen.borrow().len()
    }

    /// Whether nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.seen.borrow().is_empty()
    }

    fn put_if_absent(&self, key: String) -> Result<bool, StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected store fault"));
        }
        Ok(self.seen.borrow_mut().insert(key))
    }

    fn remove(&self, key: &str) -> Result<(), StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected store fault"));
        }
        self.seen.borrow_mut().remove(key);
        Ok(())
    }
}

impl PaymentNonceStore for MemoryStore {
    fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        _ttl_seconds: Option<u64>,
    ) -> impl Future<Output = Result<bool, StoreError>> {
        std::future::ready(self.put_if_absent(format!("{scope}:{nonce}")))
    }

    fn release(&self, scope: &str, nonce: &str) -> impl Future<Output = Result<(), StoreError>> {
        std::future::ready(self.remove(&format!("{scope}:{nonce}")))
    }
}

impl ClaimStore for MemoryStore {
    fn claim(&self, key: &str, _agent: &str) -> impl Future<Output = Result<bool, StoreError>> {
        std::future::ready(self.put_if_absent(format!("claim:{key}")))
    }

    fn release(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> {
        std::future::ready(self.remove(&format!("claim:{key}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_nonce_is_consumed_once_per_scope_and_released_on_request() {
        let store = MemoryStore::new();
        assert!(store.try_consume("s", "n", Some(60)).await.unwrap());
        assert!(!store.try_consume("s", "n", Some(60)).await.unwrap());
        assert!(store.try_consume("t", "n", None).await.unwrap(), "scoped");
        assert!(store.is_consumed("s", "n"));
        PaymentNonceStore::release(&store, "s", "n").await.unwrap();
        assert!(!store.is_consumed("s", "n"));
        assert!(store.try_consume("s", "n", None).await.unwrap());
        PaymentNonceStore::release(&store, "s", "never")
            .await
            .unwrap();
        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn a_claim_is_won_once_and_a_fault_is_never_a_win() {
        let store = MemoryStore::new();
        assert!(store.is_empty());
        assert!(store.claim("prefix-1", "agent-a").await.unwrap());
        assert!(!store.claim("prefix-1", "agent-b").await.unwrap());
        ClaimStore::release(&store, "prefix-1").await.unwrap();
        assert!(store.claim("prefix-1", "agent-b").await.unwrap());
        store.fail(true);
        assert!(store.claim("prefix-2", "a").await.is_err());
        assert!(store.try_consume("s", "n", None).await.is_err());
        assert!(ClaimStore::release(&store, "prefix-1").await.is_err());
        store.fail(false);
        assert!(store.claim("prefix-2", "a").await.unwrap());
    }

    #[test]
    fn store_error_names_its_reason() {
        let e = StoreError::new("kv 429");
        assert_eq!(e.reason(), "kv 429");
        assert_eq!(e.to_string(), "kv 429");
        assert_eq!(PAYMENT_NONCE_SCOPE, "payment-derivation-prefix");
    }
}
