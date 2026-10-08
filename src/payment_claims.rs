//! Atomic single-use payment-nonce claim on D1 (feature `d1-claims`).
//!
//! A globally consistent put-if-absent for a payment nonce, backed by a D1
//! table with `INSERT OR IGNORE`: a single engine-level atomic op (unlike a
//! Workers KV read-then-write, which has no compare-and-swap and is only
//! eventually consistent per edge). D1/SQLite is globally consistent, so one
//! claim holds across edge locations too. Schema ([`PAYMENT_CLAIMS_SCHEMA`]):
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS payment_claims (
//!     nonce TEXT PRIMARY KEY,
//!     agent TEXT,
//!     created_at INTEGER   -- unixepoch(), for a periodic TTL sweep
//! );
//! ```
//!
//! BRC-29 derivation prefixes are HMAC'd with each server's own key, so they
//! never collide across servers: one shared table is safe for a fleet.
//!
//! ## When to use this versus the crate's own single-use prefix
//!
//! [`process_payment_with_storage`](crate::process_payment_with_storage)
//! already makes every verified derivation prefix single-use: it calls
//! [`SessionStorage::try_consume_nonce`](crate::SessionStorage::try_consume_nonce)
//! under [`PAYMENT_NONCE_SCOPE`](crate::PAYMENT_NONCE_SCOPE) before
//! `internalizeAction`, keeps the prefix consumed on `accepted: false`, and
//! releases it only on an internalize *error*. How strong that is depends on
//! the backend behind the trait:
//!
//! - **Durable Object** ([`DoSessionStorage`](crate::DoSessionStorage)): an
//!   atomic put-if-absent inside one object, exact at-most-once. You do not
//!   need this module.
//! - **KV** ([`KvSessionStorage`](crate::KvSessionStorage)): read-then-write,
//!   eventually consistent, so two duplicates arriving at different edges
//!   within the propagation window can both pass. If you run the stock
//!   middleware on KV and the money at stake makes that window matter, claim
//!   here as well.
//!
//! Callers running their **own** payment flow (a custom 402 handler, a
//! pre-charge + refund model, a refund idempotency key) have no
//! `try_consume_nonce` call at all; this module is their atomic guard. Claim
//! the nonce AFTER [`verify_brc29_payment`](crate::verify_brc29_payment)
//! succeeds and BEFORE internalizing, so a rejected payment never burns a
//! claim and a concurrent duplicate serializes behind the first.
//!
//! Using both is safe: they are two independent put-if-absent records of the
//! same prefix. The first one to say "already used" rejects the request, and a
//! prefix the middleware released after an internalize error is still refused
//! by an outstanding D1 claim until [`release_payment_nonce`] clears it, which
//! only ever tightens the guarantee.
//!
//! On a storage fault both helpers surface `Err`; whether to fail open (the
//! middleware's prefix check and the upstream wallet's duplicate handling
//! remain) or fail closed is the caller's decision.

use wasm_bindgen::JsValue;
use worker::D1Database;

/// The `payment_claims` table, as one statement for a D1 migration.
pub const PAYMENT_CLAIMS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS payment_claims (\
    nonce TEXT PRIMARY KEY, \
    agent TEXT, \
    created_at INTEGER\
)";

const CLAIM_SQL: &str =
    "INSERT OR IGNORE INTO payment_claims (nonce, agent, created_at) VALUES (?, ?, unixepoch())";
const RELEASE_SQL: &str = "DELETE FROM payment_claims WHERE nonce = ?";

/// `INSERT OR IGNORE` reports a changed row only when the insert took; a
/// missing row count is treated as NOT won (never fail open on the money path).
fn claim_won(changes: Option<usize>) -> bool {
    changes.unwrap_or(0) > 0
}

/// Atomically claim `nonce` before rendering paid service.
///
/// - `Ok(true)`: this call won the claim (fresh); proceed.
/// - `Ok(false)`: the nonce was already claimed (concurrent or sequential
///   replay); reject without serving.
/// - `Err(_)`: storage fault; the caller decides fail-open vs fail-closed.
///
/// `agent` is recorded for diagnostics only.
pub async fn claim_payment_nonce(
    db: &D1Database,
    nonce: &str,
    agent: &str,
) -> std::result::Result<bool, String> {
    let stmt = db
        .prepare(CLAIM_SQL)
        .bind(&[JsValue::from_str(nonce), JsValue::from_str(agent)])
        .map_err(|e| format!("claim bind: {}", e))?;
    let res = stmt.run().await.map_err(|e| format!("claim run: {}", e))?;
    let changes = res
        .meta()
        .map_err(|e| format!("claim meta: {}", e))?
        .and_then(|m| m.changes);
    Ok(claim_won(changes))
}

/// Release a previously-won claim (best-effort). Only needed if a caller wants
/// an honest client to be able to retry with the SAME nonce after a post-claim
/// failure; servers that delete the one-time quote binding before internalize
/// don't need this (a retry gets a fresh 402/nonce regardless).
pub async fn release_payment_nonce(db: &D1Database, nonce: &str) {
    if let Ok(stmt) = db.prepare(RELEASE_SQL).bind(&[JsValue::from_str(nonce)]) {
        let _ = stmt.run().await;
    }
}

/// A D1 `payment_claims` table as the core's
/// [`ClaimStore`](bsv_middleware_core::ClaimStore): [`claim_payment_nonce`]
/// and [`release_payment_nonce`] behind the trait, for code written against
/// the core. A storage fault is a [`StoreError`](bsv_middleware_core::StoreError).
pub struct D1ClaimStore<'a>(pub &'a D1Database);

impl bsv_middleware_core::ClaimStore for D1ClaimStore<'_> {
    async fn claim(
        &self,
        key: &str,
        agent: &str,
    ) -> std::result::Result<bool, bsv_middleware_core::StoreError> {
        claim_payment_nonce(self.0, key, agent)
            .await
            .map_err(bsv_middleware_core::StoreError::new)
    }

    async fn release(&self, key: &str) -> std::result::Result<(), bsv_middleware_core::StoreError> {
        release_payment_nonce(self.0, key).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_is_won_only_by_an_inserted_row() {
        assert!(claim_won(Some(1)));
        assert!(!claim_won(Some(0)), "ignored insert = already claimed");
        assert!(!claim_won(None), "no row count = not won (fail closed)");
    }

    #[test]
    fn test_statements_target_the_documented_table() {
        assert!(PAYMENT_CLAIMS_SCHEMA.contains("payment_claims"));
        assert!(PAYMENT_CLAIMS_SCHEMA.contains("nonce TEXT PRIMARY KEY"));
        assert!(CLAIM_SQL.starts_with("INSERT OR IGNORE INTO payment_claims"));
        assert!(RELEASE_SQL.starts_with("DELETE FROM payment_claims"));
    }
}
