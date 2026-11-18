//! The kit's re-take law and its bounds. A store whose fresh claim is one
//! step but whose re-take of a released key is a read, an await, then a
//! write is caught by the re-take law of each trait, by N and schedule. A
//! store that races only above 33 simultaneous claims, and one whose lock
//! is taken from a claim held back for 100 polls, keep every law at the
//! kit's defaults and are caught once the host raises the bound they need.
//! A store that never lets two claims win but answers `Err` after waiting
//! keeps every law at the defaults and fails at a raised bound.

#![cfg(feature = "conformance")]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bsv_middleware_core::store::conformance::{self, Schedule, Violation};
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

/// Prefix records: the bound txid and whether it is released.
type Rows = RefCell<HashMap<String, (String, bool)>>;

fn decide(rows: &Rows, prefix: &str, txid: &str) -> PrefixClaim {
    match rows.borrow().get(prefix) {
        None => PrefixClaim::Won,
        Some((bound, _)) if bound != txid => PrefixClaim::OtherTransaction,
        Some((_, true)) => PrefixClaim::Won,
        Some(_) => PrefixClaim::SameTransaction,
    }
}

fn hold(rows: &Rows, prefix: &str, txid: &str) {
    rows.borrow_mut()
        .insert(prefix.into(), (txid.into(), false));
}

fn release_rows(rows: &Rows, prefix: &str, txid: &str) {
    if let Some((bound, released)) = rows.borrow_mut().get_mut(prefix) {
        if bound == txid {
            *released = true;
        }
    }
}

fn fault_if(on: &Cell<bool>) -> Result<(), StoreError> {
    if on.get() {
        Err(StoreError::new("injected fault"))
    } else {
        Ok(())
    }
}

// ── a re-take in two steps ──────────────────────────────────────────────

/// A fresh key is claimed in one step; a released key is re-taken by a
/// read, an await, then a write. For all three traits.
#[derive(Default)]
struct RacyRetake {
    rows: Rows,
    /// Claim keys: `true` while held, `false` once released.
    keys: RefCell<HashMap<String, bool>>,
    fail: Cell<bool>,
}

impl PaymentPrefixStore for RacyRetake {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        fault_if(&self.fail)?;
        if !self.rows.borrow().contains_key(prefix) {
            hold(&self.rows, prefix, txid);
            return Ok(PrefixClaim::Won);
        }
        let claim = decide(&self.rows, prefix, txid);
        if claim == PrefixClaim::Won {
            yield_once().await;
            hold(&self.rows, prefix, txid);
        }
        Ok(claim)
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        fault_if(&self.fail)?;
        release_rows(&self.rows, prefix, txid);
        Ok(())
    }
}

impl ClaimStore for RacyRetake {
    async fn claim(&self, key: &str, _agent: &str) -> Result<bool, StoreError> {
        fault_if(&self.fail)?;
        let held = self.keys.borrow().get(key).copied();
        match held {
            None => {
                self.keys.borrow_mut().insert(key.into(), true);
                Ok(true)
            }
            Some(true) => Ok(false),
            Some(false) => {
                yield_once().await;
                self.keys.borrow_mut().insert(key.into(), true);
                Ok(true)
            }
        }
    }

    async fn release(&self, key: &str) -> Result<(), StoreError> {
        fault_if(&self.fail)?;
        if let Some(held) = self.keys.borrow_mut().get_mut(key) {
            *held = false;
        }
        Ok(())
    }
}

impl PaymentNonceStore for RacyRetake {
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

#[test]
fn a_store_whose_retake_is_read_await_write_is_caught_by_the_retake_law_of_each_trait() {
    let store = RacyRetake::default();
    let fail = |on: bool| store.fail.set(on);
    let v = conformance::block_on(conformance::prefix_store(&store, "rt").fault(&fail).run())
        .unwrap_err();
    eprintln!("prefix: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (conformance::LAW_PREFIX_RETAKE, 2, Some(Schedule::Reversed))
    );
    assert!(v.detail.starts_with("the number of Won: answered 2"), "{v}");

    let v = conformance::block_on(conformance::claim_store(&store, "rt").fault(&fail).run())
        .unwrap_err();
    eprintln!("claim: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (conformance::LAW_CLAIM_RETAKE, 2, Some(Schedule::Reversed))
    );
    assert!(v.detail.contains("answered 2"), "{v}");

    let v = conformance::block_on(conformance::nonce_store(&store, "rt").fault(&fail).run())
        .unwrap_err();
    eprintln!("nonce: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (conformance::LAW_NONCE_RETAKE, 2, Some(Schedule::Reversed))
    );
    assert!(v.detail.contains("answered 2"), "{v}");
}

#[test]
fn the_retake_law_catches_it_at_every_n_and_every_other_law_passes_it() {
    for &n in conformance::SIZES {
        let store = RacyRetake::default();
        let v = conformance::block_on(conformance::prefix_retake(&store, "n", n)).unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_PREFIX_RETAKE, n));
        assert!(v.detail.contains(&format!("answered {n}")), "{v}");
        let v = conformance::block_on(conformance::claim_retake(&store, "n", n)).unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_CLAIM_RETAKE, n));
        let v = conformance::block_on(conformance::nonce_retake(&store, "n", n)).unwrap_err();
        assert_eq!((v.law, v.n), (conformance::LAW_NONCE_RETAKE, n));
    }
    // Without the re-take law it keeps every law: what the law adds.
    let store = RacyRetake::default();
    let fail = |on: bool| store.fail.set(on);
    for &n in conformance::SIZES {
        conformance::block_on(conformance::prefix_one_transaction(&store, "o", n)).unwrap();
        conformance::block_on(conformance::prefix_many_transactions(&store, "o", n)).unwrap();
        conformance::block_on(conformance::claim_concurrent(&store, "o", n)).unwrap();
        conformance::block_on(conformance::nonce_concurrent(&store, "o", n)).unwrap();
        conformance::block_on(conformance::prefix_fail_closed(&store, "o", &fail, n)).unwrap();
    }
    conformance::block_on(conformance::prefix_sequential(&store, "o")).unwrap();
    conformance::block_on(conformance::claim_sequential(&store, "o")).unwrap();
    conformance::block_on(conformance::nonce_sequential(&store, "o")).unwrap();
}

#[test]
fn memory_store_keeps_the_retake_law_of_each_trait_at_raised_bounds() {
    let store = MemoryStore::new();
    let sizes = [2, 34, 64];
    for &n in &sizes {
        conformance::block_on(conformance::prefix_retake(&store, "mem", n)).unwrap();
        conformance::block_on(conformance::claim_retake(&store, "mem", n)).unwrap();
        conformance::block_on(conformance::nonce_retake(&store, "mem", n)).unwrap();
    }
    let report = conformance::block_on(
        conformance::prefix_store(&store, "mem-raised")
            .sizes(&sizes)
            .held_passes(256)
            .run(),
    )
    .unwrap();
    assert!(report
        .checked
        .contains(&(conformance::LAW_PREFIX_RETAKE, 64)));
}

// ── a race above the default sizes ──────────────────────────────────────

/// Read; write, with an await between only while more than 33 claims of
/// the key are pending.
#[derive(Default)]
struct RacesAbove33 {
    rows: Rows,
    pending: RefCell<HashMap<String, usize>>,
    fail: Cell<bool>,
}

impl PaymentPrefixStore for RacesAbove33 {
    #[allow(clippy::manual_async_fn)]
    fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> impl Future<Output = Result<PrefixClaim, StoreError>> {
        // Counted when the future is made, before any claim is polled.
        *self
            .pending
            .borrow_mut()
            .entry(prefix.to_string())
            .or_insert(0) += 1;
        let (prefix, txid) = (prefix.to_string(), txid.to_string());
        async move {
            let answer = match fault_if(&self.fail) {
                Err(e) => Err(e),
                Ok(()) => {
                    let many = self.pending.borrow()[&prefix] > 33;
                    let claim = decide(&self.rows, &prefix, &txid);
                    if many {
                        yield_once().await;
                    }
                    if claim == PrefixClaim::Won {
                        hold(&self.rows, &prefix, &txid);
                    }
                    Ok(claim)
                }
            };
            *self.pending.borrow_mut().get_mut(&prefix).unwrap() -= 1;
            answer
        }
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        fault_if(&self.fail)?;
        release_rows(&self.rows, prefix, txid);
        Ok(())
    }
}

#[test]
fn a_store_that_races_only_above_33_claims_is_caught_once_the_sizes_are_raised() {
    let store = RacesAbove33::default();
    let fail = |on: bool| store.fail.set(on);
    // At the default sizes (2 to 33) it keeps every law ...
    conformance::block_on(conformance::prefix_store(&store, "d").fault(&fail).run()).unwrap();
    // ... and at N = 34 it is caught.
    let store = RacesAbove33::default();
    let fail = |on: bool| store.fail.set(on);
    let raised: Vec<usize> = (2..=64).collect();
    let v = conformance::block_on(
        conformance::prefix_store(&store, "r")
            .fault(&fail)
            .sizes(&raised)
            .run(),
    )
    .unwrap_err();
    eprintln!("above 33: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            34,
            Some(Schedule::Reversed)
        )
    );
    assert!(
        v.detail.starts_with("the number of Won: answered 34"),
        "{v}"
    );
}

// ── a race past the default hold ────────────────────────────────────────

/// A lease lock that a waiting claim takes over after `steal_after` of its
/// own polls; under it, read; await; write.
struct StolenLease {
    rows: Rows,
    held: Cell<bool>,
    epoch: Cell<u64>,
    steal_after: usize,
    fail: Cell<bool>,
}

impl StolenLease {
    fn new(steal_after: usize) -> Self {
        StolenLease {
            rows: Default::default(),
            held: Cell::new(false),
            epoch: Cell::new(0),
            steal_after,
            fail: Cell::new(false),
        }
    }
}

impl PaymentPrefixStore for StolenLease {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        fault_if(&self.fail)?;
        let mut waited = 0;
        while self.held.get() && waited < self.steal_after {
            waited += 1;
            yield_once().await;
        }
        self.held.set(true);
        self.epoch.set(self.epoch.get() + 1);
        let mine = self.epoch.get();
        let claim = decide(&self.rows, prefix, txid);
        yield_once().await;
        if claim == PrefixClaim::Won {
            hold(&self.rows, prefix, txid);
        }
        if self.epoch.get() == mine {
            self.held.set(false);
        }
        Ok(claim)
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        fault_if(&self.fail)?;
        release_rows(&self.rows, prefix, txid);
        Ok(())
    }
}

fn lease_run(steal_after: usize, held: Option<usize>) -> Result<conformance::Report, Violation> {
    let store = StolenLease::new(steal_after);
    let fail = |on: bool| store.fail.set(on);
    let kit = conformance::prefix_store(&store, "lease").fault(&fail);
    let kit = match held {
        Some(passes) => kit.held_passes(passes),
        None => kit,
    };
    conformance::block_on(kit.run())
}

#[test]
fn a_lease_taken_over_after_100_polls_is_caught_once_the_hold_is_raised() {
    // Taken over after 50 polls: inside the default hold of 64 passes.
    let v = lease_run(50, None).unwrap_err();
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Ahead(0))
        )
    );
    // Taken over after 100: the default hold gives the held claim back
    // first, so it keeps every law ...
    lease_run(100, None).unwrap();
    // ... and a hold of 128 passes catches it.
    let v = lease_run(100, Some(128)).unwrap_err();
    eprintln!("lease 100, hold 128: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Ahead(0))
        )
    );
    assert!(v.detail.starts_with("the number of Won: answered 2"), "{v}");
}

#[test]
fn drive_held_holds_a_claim_back_for_the_passes_it_is_given() {
    for held in [0, 1, 64, 200] {
        let passes = Cell::new(0usize);
        let seen = Cell::new(None);
        let futures: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = vec![
            Box::pin(async {
                yield_once().await;
                seen.set(Some(passes.get()));
            }),
            Box::pin(async {
                for _ in 0..1000 {
                    passes.set(passes.get() + 1);
                    yield_once().await;
                }
            }),
        ];
        conformance::block_on(conformance::drive_held(futures, Schedule::Ahead(0), held));
        // Claim 0 is polled on the first pass, then again on pass `held`
        // (or on the second pass, when the hold is 0 or 1).
        assert_eq!(seen.get(), Some(held.max(1)), "hold {held}");
    }
}

// ── a larger bound can fail a store that never lets two claims win ──────

/// One lock across the read, four awaits and the write, so no two claims
/// can both win; a claim that has waited `budget` polls for the lock gives
/// up with `Err`.
struct Busy {
    rows: Rows,
    locked: Cell<bool>,
    budget: usize,
    fail: Cell<bool>,
}

impl Busy {
    fn new(budget: usize) -> Self {
        Busy {
            rows: Default::default(),
            locked: Cell::new(false),
            budget,
            fail: Cell::new(false),
        }
    }
}

impl PaymentPrefixStore for Busy {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        fault_if(&self.fail)?;
        let mut waited = 0;
        while self.locked.get() {
            waited += 1;
            if waited > self.budget {
                return Err(StoreError::new("busy"));
            }
            yield_once().await;
        }
        self.locked.set(true);
        let claim = decide(&self.rows, prefix, txid);
        for _ in 0..4 {
            yield_once().await;
        }
        if claim == PrefixClaim::Won {
            hold(&self.rows, prefix, txid);
        }
        self.locked.set(false);
        Ok(claim)
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        fault_if(&self.fail)?;
        release_rows(&self.rows, prefix, txid);
        Ok(())
    }
}

fn busy_run(
    sizes: Option<&[usize]>,
    held: Option<usize>,
) -> Result<conformance::Report, Violation> {
    let store = Busy::new(400);
    let fail = |on: bool| store.fail.set(on);
    let kit = conformance::prefix_store(&store, "busy").fault(&fail);
    let kit = match sizes {
        Some(sizes) => kit.sizes(sizes),
        None => kit,
    };
    let kit = match held {
        Some(passes) => kit.held_passes(passes),
        None => kit,
    };
    conformance::block_on(kit.run())
}

#[test]
fn a_store_that_answers_err_after_waiting_keeps_the_defaults_and_fails_a_raised_bound() {
    // At the defaults its waits stay under 400 polls: every law.
    let report = busy_run(None, None).unwrap();
    assert_eq!(report.checked.len(), 6 * conformance::SIZES.len() + 1);
    // With N up to 128, the claims queued behind the lock wait more than
    // 400 polls, and one gives up: an `Err` under contention, a violation.
    let raised: Vec<usize> = (2..=128).collect();
    let v = busy_run(Some(&raised), None).unwrap_err();
    eprintln!("busy, sizes 2..=128: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            86,
            Some(Schedule::Ahead(0))
        )
    );
    assert_eq!(
        v.detail,
        "claim 85: the store faulted (busy) outside a fault test"
    );
    // With a hold of 1000 passes, claim 0 keeps the lock for more than 400
    // polls of claim 1 at N = 2.
    let v = busy_run(None, Some(1000)).unwrap_err();
    eprintln!("busy, hold 1000: {v}");
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Ahead(0))
        )
    );
    assert_eq!(
        v.detail,
        "claim 1: the store faulted (busy) outside a fault test"
    );
}

// ── block_on's budget ───────────────────────────────────────────────────

#[test]
fn block_on_says_its_poll_budget_was_exhausted_and_what_to_do() {
    let panic = std::panic::catch_unwind(|| conformance::block_on(std::future::pending::<()>()))
        .unwrap_err();
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("poll budget"), "{message}");
    assert!(message.contains("10000000"), "{message}");
    assert!(message.contains("host's own runtime"), "{message}");
}
