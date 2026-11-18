//! The kit's release laws: a release started together with claims of its
//! key, and releases started together before the claims. A store whose
//! release writes a stale record back after an await is caught by the race
//! law of each trait; a store whose every release credits one more re-take
//! is caught by the releases law of each trait. A compare-and-set store and
//! a store whose waiters park on a lock keep every law of the three traits
//! inside tokio.

#![cfg(feature = "conformance")]

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bsv_middleware_core::store::conformance::{self, Report, Schedule, Violation};
use bsv_middleware_core::{
    ClaimStore, PaymentNonceStore, PaymentPrefixStore, PrefixClaim, StoreError,
};

/// Answers `Pending` once (waking its task), then `Ready`.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if std::mem::replace(&mut self.0, true) {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn yield_once() -> YieldOnce {
    YieldOnce(false)
}

async fn yields(k: usize) {
    for _ in 0..k {
        yield_once().await
    }
}

/// A key's record: held or released by a transaction.
#[derive(Clone, Debug, PartialEq)]
enum Rec {
    Held(String),
    Released(String),
}

fn decide(rec: Option<&Rec>, txid: &str) -> PrefixClaim {
    match rec {
        None => PrefixClaim::Won,
        Some(Rec::Held(t)) | Some(Rec::Released(t)) if t != txid => PrefixClaim::OtherTransaction,
        Some(Rec::Released(_)) => PrefixClaim::Won,
        Some(Rec::Held(_)) => PrefixClaim::SameTransaction,
    }
}

fn fault_if(on: &Cell<bool>) -> Result<(), StoreError> {
    if on.get() {
        Err(StoreError::new("injected fault"))
    } else {
        Ok(())
    }
}

type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + 'a>>;

/// One backend behind all three traits: a claim and a release of a key by a
/// transaction (claims and nonces use the empty transaction).
trait Core {
    fn claim(&self, key: String, txid: String) -> Answer<'_, PrefixClaim>;
    fn release(&self, key: String, txid: String) -> Answer<'_, ()>;
    fn fail(&self) -> &Cell<bool>;
}

struct View<C>(C);

impl<C: Core> PaymentPrefixStore for View<C> {
    fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        _agent: &str,
    ) -> impl Future<Output = Result<PrefixClaim, StoreError>> {
        self.0.claim(format!("p:{prefix}"), txid.to_string())
    }

    fn release_prefix(
        &self,
        prefix: &str,
        txid: &str,
    ) -> impl Future<Output = Result<(), StoreError>> {
        self.0.release(format!("p:{prefix}"), txid.to_string())
    }
}

impl<C: Core> ClaimStore for View<C> {
    fn claim(&self, key: &str, _agent: &str) -> impl Future<Output = Result<bool, StoreError>> {
        let claim = self.0.claim(format!("c:{key}"), String::new());
        async move { claim.await.map(|c| c == PrefixClaim::Won) }
    }

    fn release(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> {
        self.0.release(format!("c:{key}"), String::new())
    }
}

impl<C: Core> PaymentNonceStore for View<C> {
    fn try_consume(
        &self,
        scope: &str,
        nonce: &str,
        _ttl_seconds: Option<u64>,
    ) -> impl Future<Output = Result<bool, StoreError>> {
        let claim = self.0.claim(format!("n:{scope}\0{nonce}"), String::new());
        async move { claim.await.map(|c| c == PrefixClaim::Won) }
    }

    fn release(&self, scope: &str, nonce: &str) -> impl Future<Output = Result<(), StoreError>> {
        self.0.release(format!("n:{scope}\0{nonce}"), String::new())
    }
}

/// Every law of the three traits, the fault laws included.
async fn all_three<C: Core>(store: &View<C>, namespace: &str) -> [Result<Report, Violation>; 3] {
    let fail = |on: bool| store.0.fail().set(on);
    [
        conformance::prefix_store(store, namespace)
            .fault(&fail)
            .run()
            .await,
        conformance::claim_store(store, namespace)
            .fault(&fail)
            .run()
            .await,
        conformance::nonce_store(store, namespace)
            .fault(&fail)
            .run()
            .await,
    ]
}

fn keeps_every_law(answers: [Result<Report, Violation>; 3], name: &str) {
    let sizes = conformance::SIZES.len();
    // Prefix: three concurrent laws, sequential, faults, the race and the
    // releases law (no legacy seeder). Claim and nonce: two concurrent laws,
    // sequential, faults, the race and the releases law.
    let want = [6 * sizes + 1, 5 * sizes + 1, 5 * sizes + 1];
    for (answer, want) in answers.into_iter().zip(want) {
        let report = answer.unwrap_or_else(|v| panic!("{name}: {v}"));
        assert_eq!(report.checked.len(), want, "{name}");
        for law in [
            conformance::LAW_PREFIX_RELEASE_RACE,
            conformance::LAW_PREFIX_RELEASES,
            conformance::LAW_CLAIM_RELEASE_RACE,
            conformance::LAW_CLAIM_RELEASES,
            conformance::LAW_NONCE_RELEASE_RACE,
            conformance::LAW_NONCE_RELEASES,
        ] {
            let runs = report.checked.iter().filter(|(l, _)| *l == law).count();
            assert!(runs == 0 || runs == sizes, "{name}: {law} at {runs} sizes");
        }
    }
}

// ── a release that writes a stale record back ───────────────────────────

/// Every claim is one step. A release of a held record writes it released,
/// awaits, then writes the record it built a second time: a re-take that
/// wins between the two writes is undone, and the record says released
/// again.
#[derive(Default)]
struct StaleRelease {
    rows: RefCell<HashMap<String, Rec>>,
    fail: Cell<bool>,
}

impl Core for StaleRelease {
    fn claim(&self, key: String, txid: String) -> Answer<'_, PrefixClaim> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            let claim = decide(self.rows.borrow().get(&key), &txid);
            if claim == PrefixClaim::Won {
                self.rows.borrow_mut().insert(key, Rec::Held(txid));
            }
            Ok(claim)
        })
    }

    fn release(&self, key: String, txid: String) -> Answer<'_, ()> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            let built = match self.rows.borrow().get(&key) {
                Some(Rec::Held(t)) if *t == txid => Some(Rec::Released(txid.clone())),
                _ => None,
            };
            if let Some(record) = built {
                self.rows.borrow_mut().insert(key.clone(), record.clone());
                yield_once().await;
                self.rows.borrow_mut().insert(key, record);
            }
            Ok(())
        })
    }

    fn fail(&self) -> &Cell<bool> {
        &self.fail
    }
}

#[test]
fn a_release_that_writes_a_stale_record_back_is_caught_by_the_race_law_of_each_trait() {
    let store = View(StaleRelease::default());
    let [prefix, claim, nonce] = conformance::block_on(all_three(&store, "stale"));
    for (v, law, step) in [
        (
            prefix.unwrap_err(),
            conformance::LAW_PREFIX_RELEASE_RACE,
            "after the race (one Won): a re-take: answered Won, the law requires SameTransaction",
        ),
        (
            claim.unwrap_err(),
            conformance::LAW_CLAIM_RELEASE_RACE,
            "after the race (one won): a claim: answered true, the law requires false",
        ),
        (
            nonce.unwrap_err(),
            conformance::LAW_NONCE_RELEASE_RACE,
            "after the race (one won): a consumption: answered true, the law requires false",
        ),
    ] {
        eprintln!("stale release: {v}");
        assert_eq!(
            (v.law, v.n, v.schedule),
            (law, 2, Some(Schedule::Lockstep)),
            "{v}"
        );
        assert_eq!(v.detail, step, "{v}");
    }
}

#[test]
fn the_stale_release_keeps_every_other_law() {
    // It is caught by the race law alone: every law that runs a release
    // to its end before the claims start passes it, at every N.
    let store = View(StaleRelease::default());
    conformance::block_on(async {
        for &n in conformance::SIZES {
            conformance::prefix_retake(&store, "k", n).await.unwrap();
            conformance::prefix_releases(&store, "k", n).await.unwrap();
            conformance::claim_retake(&store, "k", n).await.unwrap();
            conformance::claim_releases(&store, "k", n).await.unwrap();
            conformance::nonce_retake(&store, "k", n).await.unwrap();
            conformance::nonce_releases(&store, "k", n).await.unwrap();
        }
    });
}

#[test]
fn the_stale_release_lets_two_retakes_win_when_one_starts_late() {
    // Driven by hand: the release, a re-take, and a re-take that yields
    // once before it claims. The undone re-take and the late one both win.
    let store = View(StaleRelease::default());
    let won = conformance::block_on(async {
        let first = store.claim_prefix("p", "t", "a").await.unwrap();
        assert_eq!(first, PrefixClaim::Won);
        type Op<'a> = Pin<Box<dyn Future<Output = Option<PrefixClaim>> + 'a>>;
        let release: Op<'_> = Box::pin(async {
            store.release_prefix("p", "t").await.unwrap();
            None
        });
        let now: Op<'_> =
            Box::pin(async { Some(store.claim_prefix("p", "t", "a").await.unwrap()) });
        let late: Op<'_> = Box::pin(async {
            yield_once().await;
            Some(store.claim_prefix("p", "t", "a").await.unwrap())
        });
        let out = conformance::drive(vec![release, now, late], Schedule::Lockstep).await;
        out.iter().filter(|o| **o == Some(PrefixClaim::Won)).count()
    });
    assert_eq!(won, 2);
}

// ── a release that credits one more re-take each time ───────────────────

/// Every claim is one step. A release by the bound transaction adds one to
/// the record's credit, and a re-take wins while the credit is above zero,
/// taking one: two releases of one claim let two re-takes win.
#[derive(Default)]
struct CreditRelease {
    rows: RefCell<HashMap<String, (String, usize)>>,
    fail: Cell<bool>,
}

impl Core for CreditRelease {
    fn claim(&self, key: String, txid: String) -> Answer<'_, PrefixClaim> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            let mut rows = self.rows.borrow_mut();
            Ok(match rows.get_mut(&key) {
                None => {
                    rows.insert(key, (txid, 0));
                    PrefixClaim::Won
                }
                Some((bound, _)) if *bound != txid => PrefixClaim::OtherTransaction,
                Some((_, credit)) if *credit > 0 => {
                    *credit -= 1;
                    PrefixClaim::Won
                }
                Some(_) => PrefixClaim::SameTransaction,
            })
        })
    }

    fn release(&self, key: String, txid: String) -> Answer<'_, ()> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            if let Some((bound, credit)) = self.rows.borrow_mut().get_mut(&key) {
                if *bound == txid {
                    *credit += 1;
                }
            }
            Ok(())
        })
    }

    fn fail(&self) -> &Cell<bool> {
        &self.fail
    }
}

#[test]
fn a_release_that_credits_each_call_is_caught_by_the_releases_law_of_each_trait() {
    let store = View(CreditRelease::default());
    let [prefix, claim, nonce] = conformance::block_on(all_three(&store, "credit"));
    for (v, law, count) in [
        (
            prefix.unwrap_err(),
            conformance::LAW_PREFIX_RELEASES,
            "the number of Won: answered 2, the law requires 1",
        ),
        (
            claim.unwrap_err(),
            conformance::LAW_CLAIM_RELEASES,
            "the number of claims won: answered 2, the law requires 1",
        ),
        (
            nonce.unwrap_err(),
            conformance::LAW_NONCE_RELEASES,
            "the number of consumptions won: answered 2, the law requires 1",
        ),
    ] {
        eprintln!("credit release: {v}");
        assert_eq!(
            (v.law, v.n, v.schedule),
            (law, 2, Some(Schedule::Reversed)),
            "{v}"
        );
        assert_eq!(v.detail, count, "{v}");
    }
}

// ── two correct stores of different make ────────────────────────────────

/// A versioned record: read, await, then a compare-and-set of the version;
/// a lost compare-and-set reads again. The release is a compare-and-set
/// loop too.
#[derive(Default)]
struct CompareAndSet {
    rows: RefCell<HashMap<String, (u64, Option<Rec>)>>,
    fail: Cell<bool>,
}

impl CompareAndSet {
    fn read(&self, key: &str) -> (u64, Option<Rec>) {
        self.rows.borrow().get(key).cloned().unwrap_or((0, None))
    }

    fn cas(&self, key: &str, version: u64, record: Rec) -> bool {
        let mut rows = self.rows.borrow_mut();
        if rows.get(key).map(|r| r.0).unwrap_or(0) != version {
            return false;
        }
        rows.insert(key.to_string(), (version + 1, Some(record)));
        true
    }
}

impl Core for CompareAndSet {
    fn claim(&self, key: String, txid: String) -> Answer<'_, PrefixClaim> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            loop {
                let (version, record) = self.read(&key);
                yield_once().await;
                let claim = decide(record.as_ref(), &txid);
                if claim != PrefixClaim::Won {
                    return Ok(claim);
                }
                if self.cas(&key, version, Rec::Held(txid.clone())) {
                    return Ok(PrefixClaim::Won);
                }
            }
        })
    }

    fn release(&self, key: String, txid: String) -> Answer<'_, ()> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            loop {
                let (version, record) = self.read(&key);
                yield_once().await;
                match record {
                    Some(Rec::Held(t)) if t == txid => {
                        if self.cas(&key, version, Rec::Released(t)) {
                            return Ok(());
                        }
                    }
                    _ => return Ok(()),
                }
            }
        })
    }

    fn fail(&self) -> &Cell<bool> {
        &self.fail
    }
}

/// One store-wide lock whose waiters park (woken only by the unlock); the
/// holder awaits `inside` times between its read and its write, in claims
/// and releases alike.
struct ParkingLock {
    rows: RefCell<HashMap<String, Rec>>,
    locked: Cell<bool>,
    waiters: RefCell<VecDeque<Waker>>,
    inside: usize,
    fail: Cell<bool>,
}

impl ParkingLock {
    fn new(inside: usize) -> Self {
        ParkingLock {
            rows: RefCell::default(),
            locked: Cell::new(false),
            waiters: RefCell::default(),
            inside,
            fail: Cell::new(false),
        }
    }

    fn lock(&self) -> Lock<'_> {
        Lock(self)
    }

    fn unlock(&self) {
        self.locked.set(false);
        if let Some(waker) = self.waiters.borrow_mut().pop_front() {
            waker.wake();
        }
    }
}

struct Lock<'a>(&'a ParkingLock);

impl Future for Lock<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.locked.get() {
            self.0.waiters.borrow_mut().push_back(cx.waker().clone());
            Poll::Pending
        } else {
            self.0.locked.set(true);
            Poll::Ready(())
        }
    }
}

impl Core for ParkingLock {
    fn claim(&self, key: String, txid: String) -> Answer<'_, PrefixClaim> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            self.lock().await;
            let claim = decide(self.rows.borrow().get(&key), &txid);
            yields(self.inside).await;
            if claim == PrefixClaim::Won {
                self.rows.borrow_mut().insert(key, Rec::Held(txid));
            }
            self.unlock();
            Ok(claim)
        })
    }

    fn release(&self, key: String, txid: String) -> Answer<'_, ()> {
        Box::pin(async move {
            fault_if(&self.fail)?;
            self.lock().await;
            let held = matches!(self.rows.borrow().get(&key), Some(Rec::Held(t)) if *t == txid);
            yields(self.inside).await;
            if held {
                self.rows.borrow_mut().insert(key, Rec::Released(txid));
            }
            self.unlock();
            Ok(())
        })
    }

    fn fail(&self) -> &Cell<bool> {
        &self.fail
    }
}

#[tokio::test]
async fn a_compare_and_set_store_keeps_every_law_of_the_three_traits_in_tokio() {
    let store = View(CompareAndSet::default());
    keeps_every_law(all_three(&store, "cas").await, "compare-and-set");
}

#[tokio::test]
async fn a_store_whose_waiters_park_on_a_lock_keeps_every_law_of_the_three_traits_in_tokio() {
    let store = View(ParkingLock::new(8));
    keeps_every_law(all_three(&store, "parking").await, "parking lock");
}

#[tokio::test]
async fn memory_store_keeps_the_release_laws_at_raised_bounds() {
    let store = bsv_middleware_core::MemoryStore::new();
    let sizes = [34, 64];
    let prefix = conformance::prefix_store(&store, "raised")
        .sizes(&sizes)
        .held_passes(256)
        .run()
        .await
        .unwrap();
    let claim = conformance::claim_store(&store, "raised")
        .sizes(&sizes)
        .held_passes(256)
        .run()
        .await
        .unwrap();
    let nonce = conformance::nonce_store(&store, "raised")
        .sizes(&sizes)
        .held_passes(256)
        .run()
        .await
        .unwrap();
    for (report, laws) in [
        (
            prefix,
            [
                conformance::LAW_PREFIX_RELEASE_RACE,
                conformance::LAW_PREFIX_RELEASES,
            ],
        ),
        (
            claim,
            [
                conformance::LAW_CLAIM_RELEASE_RACE,
                conformance::LAW_CLAIM_RELEASES,
            ],
        ),
        (
            nonce,
            [
                conformance::LAW_NONCE_RELEASE_RACE,
                conformance::LAW_NONCE_RELEASES,
            ],
        ),
    ] {
        for law in laws {
            let at: Vec<usize> = report
                .checked
                .iter()
                .filter(|(l, _)| *l == law)
                .map(|(_, n)| *n)
                .collect();
            assert_eq!(at, sizes, "{law}");
        }
    }
}
