//! The conformance kit's own proof: `MemoryStore` keeps every law, and a
//! store that reads, yields once, then writes breaks the concurrent laws at
//! every N while keeping the sequential ones. `store_conformance_schedules`
//! holds the stores that only some schedules or sizes catch.

#![cfg(feature = "conformance")]

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bsv_middleware_core::store::conformance::{self, Violation};
use bsv_middleware_core::{
    ClaimStore, MemoryStore, PaymentNonceStore, PaymentPrefixStore, PrefixClaim, StoreError,
};

/// Answers `Pending` once (waking its task), then `Ready`.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn yield_once() -> YieldOnce {
    YieldOnce(false)
}

/// Reads the record, yields, then writes what the read decided: every
/// claim is a read followed by a separate write.
#[derive(Default)]
struct ReadYieldWrite {
    prefixes: RefCell<HashMap<String, (String, bool)>>,
    keys: RefCell<HashSet<String>>,
    fail: Cell<bool>,
}

impl ReadYieldWrite {
    fn check(&self) -> Result<(), StoreError> {
        if self.fail.get() {
            Err(StoreError::new("injected fault"))
        } else {
            Ok(())
        }
    }
}

impl PaymentPrefixStore for ReadYieldWrite {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        self.check()?;
        let read = self.prefixes.borrow().get(prefix).cloned();
        yield_once().await;
        let claim = match read {
            None => PrefixClaim::Won,
            Some((bound, _)) if bound != txid => PrefixClaim::OtherTransaction,
            Some((_, true)) => PrefixClaim::Won,
            Some(_) => PrefixClaim::SameTransaction,
        };
        if claim == PrefixClaim::Won {
            self.prefixes
                .borrow_mut()
                .insert(prefix.to_string(), (txid.to_string(), false));
        }
        Ok(claim)
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        self.check()?;
        if let Some((bound, released)) = self.prefixes.borrow_mut().get_mut(prefix) {
            if bound == txid {
                *released = true;
            }
        }
        Ok(())
    }
}

impl ClaimStore for ReadYieldWrite {
    async fn claim(&self, key: &str, _agent: &str) -> Result<bool, StoreError> {
        self.check()?;
        let present = self.keys.borrow().contains(key);
        yield_once().await;
        if present {
            return Ok(false);
        }
        self.keys.borrow_mut().insert(key.to_string());
        Ok(true)
    }

    async fn release(&self, key: &str) -> Result<(), StoreError> {
        self.check()?;
        self.keys.borrow_mut().remove(key);
        Ok(())
    }
}

impl PaymentNonceStore for ReadYieldWrite {
    async fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        _ttl_seconds: Option<u64>,
    ) -> Result<bool, StoreError> {
        ClaimStore::claim(self, &format!("{scope}\0{nonce}"), "").await
    }

    async fn release(&self, scope: &str, nonce: &str) -> Result<(), StoreError> {
        ClaimStore::release(self, &format!("{scope}\0{nonce}")).await
    }
}

/// The same record with the yield before the read: its read and write are
/// one step, so it keeps every law.
#[derive(Default)]
struct YieldReadWrite(MemoryStore);

impl PaymentPrefixStore for YieldReadWrite {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        yield_once().await;
        let claim = self.0.claim_prefix(prefix, txid, agent).await;
        yield_once().await;
        claim
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        yield_once().await;
        self.0.release_prefix(prefix, txid).await
    }
}

fn wins(v: &Violation) -> bool {
    v.detail.starts_with("the number of")
}

#[test]
fn memory_store_keeps_every_law_of_the_three_traits() {
    let store = MemoryStore::new();
    let fail = |on: bool| store.fail(on);
    let report =
        conformance::block_on(conformance::prefix_store(&store, "mem").fault(&fail).run()).unwrap();
    let sizes = conformance::SIZES.len();
    assert_eq!(sizes, 32);
    // One fresh transaction, N transactions, re-takes; sequential; faults;
    // a release racing re-takes; releases, then re-takes.
    assert_eq!(report.checked.len(), 3 * sizes + 1 + sizes + 2 * sizes);
    assert_eq!(report.skipped, vec![conformance::LAW_PREFIX_LEGACY]);
    let report =
        conformance::block_on(conformance::claim_store(&store, "mem").fault(&fail).run()).unwrap();
    assert_eq!(report.checked.len(), 2 * sizes + 1 + sizes + 2 * sizes);
    assert!(report.skipped.is_empty());
    let report =
        conformance::block_on(conformance::nonce_store(&store, "mem").fault(&fail).run()).unwrap();
    assert_eq!(report.checked.len(), 2 * sizes + 1 + sizes + 2 * sizes);
}

#[tokio::test]
async fn the_kit_runs_inside_a_runtime_too() {
    let store = MemoryStore::new();
    conformance::prefix_store(&store, "tokio")
        .run()
        .await
        .unwrap();
    conformance::claim_store(&store, "tokio")
        .run()
        .await
        .unwrap();
    conformance::nonce_store(&store, "tokio")
        .run()
        .await
        .unwrap();
}

#[test]
fn a_store_that_awaits_only_around_its_one_step_keeps_every_law() {
    let store = YieldReadWrite::default();
    let fail = |on: bool| store.0.fail(on);
    conformance::block_on(conformance::prefix_store(&store, "yrw").fault(&fail).run()).unwrap();
}

#[test]
fn a_read_yield_write_store_breaks_both_concurrent_prefix_laws_at_every_n() {
    for &n in conformance::SIZES {
        let store = ReadYieldWrite::default();
        let v = conformance::block_on(conformance::prefix_one_transaction(&store, "rw", n))
            .unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_PREFIX_ONE_TRANSACTION, n));
        assert!(wins(&v), "{v}");
        assert!(v.detail.contains(&format!("answered {n}")), "{v}");

        let v = conformance::block_on(conformance::prefix_many_transactions(&store, "rw", n))
            .unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_PREFIX_MANY_TRANSACTIONS, n));
        assert!(v.detail.contains(&format!("answered {n}")), "{v}");
    }
    // The whole run stops at the first law, at the smallest N.
    let store = ReadYieldWrite::default();
    let v = conformance::block_on(conformance::prefix_store(&store, "rw-run").run()).unwrap_err();
    assert_eq!((v.law, v.n), (conformance::LAW_PREFIX_ONE_TRANSACTION, 2));
}

#[tokio::test]
async fn a_read_yield_write_store_breaks_them_inside_a_runtime_too() {
    for &n in conformance::SIZES {
        let store = ReadYieldWrite::default();
        let v = conformance::prefix_one_transaction(&store, "rt", n)
            .await
            .unwrap_err();
        assert!(wins(&v), "{v}");
        let v = conformance::prefix_many_transactions(&store, "rt", n)
            .await
            .unwrap_err();
        assert!(wins(&v), "{v}");
    }
}

#[test]
fn a_read_yield_write_store_keeps_the_sequential_and_fault_laws() {
    let store = ReadYieldWrite::default();
    let fail = |on: bool| store.fail.set(on);
    conformance::block_on(conformance::prefix_sequential(&store, "seq")).unwrap();
    for &n in conformance::SIZES {
        conformance::block_on(conformance::prefix_fail_closed(&store, "seq", &fail, n)).unwrap();
    }
    conformance::block_on(conformance::claim_sequential(&store, "seq")).unwrap();
    conformance::block_on(conformance::nonce_sequential(&store, "seq")).unwrap();
}

#[test]
fn a_read_yield_write_claim_or_nonce_store_breaks_its_concurrent_law_at_every_n() {
    for &n in conformance::SIZES {
        let store = ReadYieldWrite::default();
        let v = conformance::block_on(conformance::claim_concurrent(&store, "rw", n)).unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_CLAIM_CONCURRENT, n));
        assert!(v.detail.contains(&format!("answered {n}")), "{v}");
        let v = conformance::block_on(conformance::nonce_concurrent(&store, "rw", n)).unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_NONCE_CONCURRENT, n));
        assert!(v.detail.contains(&format!("answered {n}")), "{v}");
    }
}

/// Grants a claim while faulting: what the fault law exists to catch.
struct ClaimsThroughAFault(MemoryStore, Cell<bool>);

impl PaymentPrefixStore for ClaimsThroughAFault {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        if self.1.get() {
            return Ok(PrefixClaim::Won);
        }
        self.0.claim_prefix(prefix, txid, agent).await
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        self.0.release_prefix(prefix, txid).await
    }
}

/// Lets a released record be re-taken by any transaction.
#[derive(Default)]
struct ReleaseFreesThePrefix(RefCell<HashMap<String, Option<String>>>);

impl PaymentPrefixStore for ReleaseFreesThePrefix {
    async fn claim_prefix(&self, p: &str, txid: &str, _: &str) -> Result<PrefixClaim, StoreError> {
        let mut map = self.0.borrow_mut();
        Ok(match map.get(p) {
            None | Some(None) => {
                map.insert(p.into(), Some(txid.into()));
                PrefixClaim::Won
            }
            Some(Some(bound)) if bound == txid => PrefixClaim::SameTransaction,
            Some(Some(_)) => PrefixClaim::OtherTransaction,
        })
    }

    async fn release_prefix(&self, p: &str, txid: &str) -> Result<(), StoreError> {
        let mut map = self.0.borrow_mut();
        if map.get(p) == Some(&Some(txid.to_string())) {
            map.insert(p.into(), None);
        }
        Ok(())
    }
}

#[test]
fn the_sequential_and_fault_laws_catch_what_they_name() {
    let store = ClaimsThroughAFault(MemoryStore::new(), Cell::new(false));
    let fail = |on: bool| {
        store.0.fail(on);
        store.1.set(on);
    };
    let v =
        conformance::block_on(conformance::prefix_fail_closed(&store, "f", &fail, 2)).unwrap_err();
    assert_eq!(v.law, conformance::LAW_PREFIX_FAIL_CLOSED);

    let store = ReleaseFreesThePrefix::default();
    let v = conformance::block_on(conformance::prefix_sequential(&store, "s")).unwrap_err();
    assert_eq!(v.law, conformance::LAW_PREFIX_SEQUENTIAL);
    assert!(
        v.detail
            .contains("the released record, another transaction"),
        "{v}"
    );
    let v =
        conformance::block_on(conformance::prefix_many_transactions(&store, "s", 2)).unwrap_err();
    assert!(v.detail.contains("after the winner's release"), "{v}");

    // MemoryStore never writes a legacy record, so a seeder that cannot is a
    // seeder fault, named, not a pass.
    let store = MemoryStore::new();
    let seed: &conformance::LegacySeeder<'_> =
        &|_p| Box::pin(async { Err(StoreError::new("no legacy records here")) });
    let v = conformance::block_on(conformance::prefix_legacy(&store, "l", seed)).unwrap_err();
    assert!(v.detail.contains("seeder"), "{v}");
}

#[test]
fn together_polls_every_future_once_per_pass_in_order() {
    let log = RefCell::new(Vec::new());
    let futures = (0..3)
        .map(|i| {
            let log = &log;
            async move {
                log.borrow_mut().push((i, 'r'));
                yield_once().await;
                log.borrow_mut().push((i, 'w'));
                i
            }
        })
        .collect();
    let out = conformance::block_on(conformance::together(futures));
    assert_eq!(out, vec![0, 1, 2]);
    assert_eq!(
        log.into_inner(),
        vec![(0, 'r'), (1, 'r'), (2, 'r'), (0, 'w'), (1, 'w'), (2, 'w')]
    );
}

#[test]
fn transaction_ids_are_sixty_four_lowercase_hex() {
    let t = conformance::txid_for("ns", "a");
    assert_eq!(t.len(), 64);
    assert!(t
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_ne!(t, conformance::txid_for("ns", "b"));
    assert_ne!(t, conformance::txid_for("other", "a"));
}
