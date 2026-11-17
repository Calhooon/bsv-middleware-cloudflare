//! The kit's schedules against stores that are not atomic in narrower ways
//! than a plain read, yield, write, and against two atomic stores that await
//! around their one step. Each store that is not atomic is caught by a named
//! law at a named N under a named schedule; each atomic store keeps every
//! law under every schedule.

#![cfg(feature = "conformance")]

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bsv_middleware_core::store::conformance::{self, Schedule, Violation};
use bsv_middleware_core::{PaymentPrefixStore, PrefixClaim, StoreError};

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

#[derive(Clone, Copy, Debug, PartialEq)]
enum Shape {
    /// Read; yield; yield; write.
    YieldTwice,
    /// Read; write, except the store's second call, which yields between.
    SecondCallYields,
    /// The k-th claim of a key awaits k times before its read (a lazy
    /// start, a connection, latency), then read; yield; write.
    StaggeredStart,
    /// Read; yield; write under a lock per transaction: one transaction's
    /// claims are serialized, different transactions' are not.
    LockPerTransaction,
    /// Read; write, with a yield between only while exactly 3 claims of
    /// the key are pending.
    YieldsAtThreePending,
    /// One atomic write; yield; then the outcome read from a store-wide
    /// "last change" flag that another claim may have overwritten.
    OutcomeReadLater,
    /// The k-th claim of a key awaits k times before its read; the first
    /// claim reads and writes in one step, every later one reads, yields,
    /// then writes.
    FirstClaimInOneStep,
    /// Atomic: one lock held across read; yield; yield; write.
    LockAcrossTheClaim,
    /// Atomic: a yield, the read and write in one step, then five yields
    /// before the answer (one transaction behind many awaits).
    OneStepManyAwaits,
}

struct Store {
    shape: Shape,
    rows: RefCell<HashMap<String, (String, bool)>>,
    calls: Cell<usize>,
    made: RefCell<HashMap<String, usize>>,
    pending: RefCell<HashMap<String, usize>>,
    tx_locks: RefCell<HashSet<String>>,
    lock: Cell<bool>,
    last_change: Cell<bool>,
    fail: Cell<bool>,
}

impl Store {
    fn new(shape: Shape) -> Self {
        Store {
            shape,
            rows: Default::default(),
            calls: Cell::new(0),
            made: Default::default(),
            pending: Default::default(),
            tx_locks: Default::default(),
            lock: Cell::new(false),
            last_change: Cell::new(false),
            fail: Cell::new(false),
        }
    }

    fn decide(&self, prefix: &str, txid: &str) -> PrefixClaim {
        match self.rows.borrow().get(prefix) {
            None => PrefixClaim::Won,
            Some((bound, _)) if bound != txid => PrefixClaim::OtherTransaction,
            Some((_, true)) => PrefixClaim::Won,
            Some(_) => PrefixClaim::SameTransaction,
        }
    }

    fn write(&self, prefix: &str, txid: &str) {
        self.rows
            .borrow_mut()
            .insert(prefix.into(), (txid.into(), false));
    }

    fn write_if_won(&self, prefix: &str, txid: &str, claim: PrefixClaim) {
        if claim == PrefixClaim::Won {
            self.write(prefix, txid);
        }
    }

    async fn claim(&self, prefix: &str, txid: &str, call: usize, index: usize) -> PrefixClaim {
        match self.shape {
            Shape::YieldTwice => {
                let claim = self.decide(prefix, txid);
                yield_once().await;
                yield_once().await;
                self.write_if_won(prefix, txid, claim);
                claim
            }
            Shape::SecondCallYields => {
                let claim = self.decide(prefix, txid);
                if call == 1 {
                    yield_once().await;
                }
                self.write_if_won(prefix, txid, claim);
                claim
            }
            Shape::StaggeredStart => {
                for _ in 0..index {
                    yield_once().await;
                }
                let claim = self.decide(prefix, txid);
                yield_once().await;
                self.write_if_won(prefix, txid, claim);
                claim
            }
            Shape::LockPerTransaction => {
                while self.tx_locks.borrow().contains(txid) {
                    yield_once().await;
                }
                self.tx_locks.borrow_mut().insert(txid.into());
                let claim = self.decide(prefix, txid);
                yield_once().await;
                self.write_if_won(prefix, txid, claim);
                self.tx_locks.borrow_mut().remove(txid);
                claim
            }
            Shape::YieldsAtThreePending => {
                let three = self.pending.borrow()[prefix] == 3;
                let claim = self.decide(prefix, txid);
                if three {
                    yield_once().await;
                }
                self.write_if_won(prefix, txid, claim);
                claim
            }
            Shape::OutcomeReadLater => {
                let claim = self.decide(prefix, txid);
                let changed = claim == PrefixClaim::Won;
                self.write_if_won(prefix, txid, claim);
                self.last_change.set(changed);
                yield_once().await;
                if self.last_change.get() {
                    PrefixClaim::Won
                } else {
                    match self.rows.borrow().get(prefix) {
                        Some((bound, _)) if bound == txid => PrefixClaim::SameTransaction,
                        _ => PrefixClaim::OtherTransaction,
                    }
                }
            }
            Shape::FirstClaimInOneStep => {
                for _ in 0..index {
                    yield_once().await;
                }
                let claim = self.decide(prefix, txid);
                if index > 0 {
                    yield_once().await;
                }
                self.write_if_won(prefix, txid, claim);
                claim
            }
            Shape::LockAcrossTheClaim => {
                while self.lock.get() {
                    yield_once().await;
                }
                self.lock.set(true);
                let claim = self.decide(prefix, txid);
                yield_once().await;
                yield_once().await;
                self.write_if_won(prefix, txid, claim);
                self.lock.set(false);
                claim
            }
            Shape::OneStepManyAwaits => {
                yield_once().await;
                let claim = self.decide(prefix, txid);
                self.write_if_won(prefix, txid, claim);
                for _ in 0..5 {
                    yield_once().await;
                }
                claim
            }
        }
    }
}

impl PaymentPrefixStore for Store {
    #[allow(clippy::manual_async_fn)]
    fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> impl Future<Output = Result<PrefixClaim, StoreError>> {
        // Counted when the future is made, before any claim is polled.
        let call = self.calls.get();
        self.calls.set(call + 1);
        let index = {
            let mut made = self.made.borrow_mut();
            let count = made.entry(prefix.to_string()).or_insert(0);
            *count += 1;
            *count - 1
        };
        *self
            .pending
            .borrow_mut()
            .entry(prefix.to_string())
            .or_insert(0) += 1;
        let (prefix, txid) = (prefix.to_string(), txid.to_string());
        async move {
            let answer = if self.fail.get() {
                Err(StoreError::new("injected fault"))
            } else {
                Ok(self.claim(&prefix, &txid, call, index).await)
            };
            *self.pending.borrow_mut().get_mut(&prefix).unwrap() -= 1;
            answer
        }
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        if self.fail.get() {
            return Err(StoreError::new("injected fault"));
        }
        if let Some((bound, released)) = self.rows.borrow_mut().get_mut(prefix) {
            if bound == txid {
                *released = true;
            }
        }
        Ok(())
    }
}

fn run(store: &Store, random: Option<usize>) -> Result<conformance::Report, Violation> {
    let fail = |on: bool| store.fail.set(on);
    let kit = conformance::prefix_store(store, "schedules").fault(&fail);
    let kit = match random {
        Some(count) => kit.random(count, conformance::DEFAULT_SEED),
        None => kit,
    };
    conformance::block_on(kit.run())
}

fn caught(shape: Shape) -> Violation {
    let v = run(&Store::new(shape), None).unwrap_err();
    eprintln!("{shape:?}: {v}");
    assert!(v.detail.starts_with("the number of Won"), "{v}");
    v
}

#[test]
fn a_store_that_yields_twice_between_read_and_write_is_caught() {
    let v = caught(Shape::YieldTwice);
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Reversed)
        )
    );
}

#[test]
fn a_store_whose_second_call_alone_yields_is_caught() {
    let v = caught(Shape::SecondCallYields);
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Reversed)
        )
    );
}

#[test]
fn a_store_whose_claims_start_after_different_delays_is_caught() {
    let v = caught(Shape::StaggeredStart);
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Reversed)
        )
    );
}

#[test]
fn a_store_serialized_per_transaction_is_caught_by_many_transactions() {
    let v = caught(Shape::LockPerTransaction);
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_MANY_TRANSACTIONS,
            2,
            Some(Schedule::Reversed)
        )
    );
}

#[test]
fn a_store_that_yields_only_at_three_pending_claims_is_caught_at_three() {
    let v = caught(Shape::YieldsAtThreePending);
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            3,
            Some(Schedule::Reversed)
        )
    );
}

#[test]
fn a_store_that_reads_its_outcome_after_an_await_is_caught_with_no_winner() {
    let v = caught(Shape::OutcomeReadLater);
    assert_eq!(
        (v.law, v.n, v.schedule),
        (
            conformance::LAW_PREFIX_ONE_TRANSACTION,
            2,
            Some(Schedule::Reversed)
        )
    );
    assert!(v.detail.contains("answered 0"), "{v}");
}

#[test]
fn a_store_whose_first_claim_is_one_step_is_caught_on_a_fresh_prefix_by_a_random_schedule_alone() {
    // Lockstep, reversed and every claim ahead poll the first claim on the
    // first pass, so it writes before any later claim reads: the laws of a
    // fresh prefix pass it under them.
    let store = Store::new(Shape::FirstClaimInOneStep);
    let v = run(&store, Some(0)).unwrap_err();
    // (Its re-take of a released prefix is a later claim, read; yield;
    // write, so the re-take law catches it under those orders.)
    assert_eq!(
        (v.law, v.n, v.schedule),
        (conformance::LAW_PREFIX_RETAKE, 2, Some(Schedule::Reversed))
    );
    // A random schedule can hold the first claim back while two later ones
    // overlap.
    let v = caught(Shape::FirstClaimInOneStep);
    assert!(matches!(v.schedule, Some(Schedule::Random(_))), "{v}");
    assert!(v.to_string().contains("seed 0x"), "{v}");
}

#[test]
fn lockstep_alone_at_two_eight_and_thirty_two_passes_three_of_these_stores() {
    // What the other schedules and sizes add: under lockstep alone at
    // N = 2, 8 and 32, these three keep both concurrent laws.
    for shape in [
        Shape::SecondCallYields,
        Shape::StaggeredStart,
        Shape::YieldsAtThreePending,
    ] {
        let store = Store::new(shape);
        for n in [2, 8, 32] {
            let lockstep = Schedule::Lockstep;
            conformance::block_on(conformance::prefix_one_transaction_under(
                &store, "lockstep", n, lockstep,
            ))
            .unwrap_or_else(|v| panic!("{shape:?}: {v}"));
            conformance::block_on(conformance::prefix_many_transactions_under(
                &store, "lockstep", n, lockstep,
            ))
            .unwrap_or_else(|v| panic!("{shape:?}: {v}"));
        }
    }
}

#[test]
fn each_store_is_caught_by_the_schedules_named_for_it() {
    // A fresh store per schedule, at the smallest N where its race shows.
    let catches = |shape: Shape, n: usize, schedule: Schedule| {
        let store = Store::new(shape);
        conformance::block_on(conformance::prefix_one_transaction_under(
            &store, "one", n, schedule,
        ))
        .is_err()
    };
    use Schedule::*;
    assert!(catches(Shape::SecondCallYields, 2, Ahead(1)));
    assert!(catches(Shape::SecondCallYields, 2, Reversed));
    assert!(!catches(Shape::SecondCallYields, 2, Lockstep));
    assert!(catches(Shape::StaggeredStart, 2, Ahead(0)));
    assert!(catches(Shape::StaggeredStart, 2, Reversed));
    assert!(!catches(Shape::StaggeredStart, 2, Lockstep));
    assert!(catches(Shape::YieldsAtThreePending, 3, Lockstep));
    assert!(!catches(Shape::YieldsAtThreePending, 2, Lockstep));
    assert!(!catches(Shape::YieldsAtThreePending, 4, Lockstep));
    for schedule in [Lockstep, Reversed, Ahead(0), Ahead(1), Ahead(2)] {
        assert!(
            !catches(Shape::FirstClaimInOneStep, 3, schedule),
            "{schedule}"
        );
    }
}

#[test]
fn stores_with_one_indivisible_claim_keep_every_law_under_every_schedule() {
    for shape in [Shape::LockAcrossTheClaim, Shape::OneStepManyAwaits] {
        let report = run(&Store::new(shape), None).unwrap_or_else(|v| panic!("{shape:?}: {v}"));
        let n = conformance::SIZES.len();
        assert_eq!(report.checked.len(), 3 * n + 1 + n, "{shape:?}");
    }
}

#[test]
fn every_schedule_finishes_and_returns_outputs_in_input_order() {
    for n in [1, 2, 5, 33] {
        for schedule in conformance::schedules(n, 4, 7) {
            let log = RefCell::new(Vec::new());
            let futures = (0..n)
                .map(|i| {
                    let log = &log;
                    async move {
                        for _ in 0..i % 4 {
                            yield_once().await;
                        }
                        log.borrow_mut().push(i);
                        i
                    }
                })
                .collect();
            let out = conformance::block_on(conformance::drive(futures, schedule));
            assert_eq!(out, (0..n).collect::<Vec<_>>(), "{schedule}");
            assert_eq!(log.borrow().len(), n, "{schedule}");
        }
    }
}

#[test]
fn the_schedules_at_n_are_reversed_lockstep_each_claim_ahead_and_the_random_ones() {
    let s = conformance::schedules(4, 3, 9);
    assert_eq!(s.len(), 2 + 4 + 3);
    assert_eq!(&s[..2], &[Schedule::Reversed, Schedule::Lockstep]);
    assert_eq!(
        &s[2..6],
        &(0..4).map(Schedule::Ahead).collect::<Vec<_>>()[..]
    );
    let seeds: HashSet<_> = s[6..].iter().collect();
    assert_eq!(seeds.len(), 3);
    assert_eq!(s, conformance::schedules(4, 3, 9));
    assert_ne!(s[6..], conformance::schedules(4, 3, 10)[6..]);
}

#[test]
fn ahead_polls_the_held_claim_first_then_after_the_others() {
    let log = RefCell::new(Vec::new());
    let futures = (0..3)
        .map(|i| {
            let log = &log;
            async move {
                log.borrow_mut().push((i, 'r'));
                yield_once().await;
                log.borrow_mut().push((i, 'w'));
            }
        })
        .collect();
    conformance::block_on(conformance::drive(futures, Schedule::Ahead(1)));
    assert_eq!(
        log.into_inner(),
        vec![(1, 'r'), (0, 'r'), (2, 'r'), (0, 'w'), (2, 'w'), (1, 'w')]
    );
}

/// An atomic store whose waiting claims park on a lock's waker list and are
/// woken only by the release: no claim wakes itself while it waits.
#[derive(Default)]
struct ParkingLock {
    inner: bsv_middleware_core::MemoryStore,
    held: Cell<bool>,
    waiters: RefCell<Vec<std::task::Waker>>,
}

impl ParkingLock {
    fn acquire(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| {
            if self.held.get() {
                self.waiters.borrow_mut().push(cx.waker().clone());
                Poll::Pending
            } else {
                self.held.set(true);
                Poll::Ready(())
            }
        })
    }

    fn release(&self) {
        self.held.set(false);
        for waker in self.waiters.borrow_mut().drain(..) {
            waker.wake();
        }
    }
}

impl PaymentPrefixStore for ParkingLock {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        self.acquire().await;
        tokio::task::yield_now().await;
        let claim = self.inner.claim_prefix(prefix, txid, agent).await;
        tokio::task::yield_now().await;
        self.release();
        claim
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        self.inner.release_prefix(prefix, txid).await
    }
}

#[tokio::test]
async fn a_store_whose_waiters_park_finishes_every_schedule_inside_a_runtime() {
    let store = ParkingLock::default();
    let fail = |on: bool| store.inner.fail(on);
    let report = conformance::prefix_store(&store, "parking")
        .fault(&fail)
        .run()
        .await
        .unwrap();
    let n = conformance::SIZES.len();
    assert_eq!(report.checked.len(), 3 * n + 1 + n);
}
