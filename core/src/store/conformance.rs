//! The conformance kit for the single-use stores (feature `conformance`).
//!
//! A host that implements [`PaymentPrefixStore`], [`ClaimStore`] or
//! [`PaymentNonceStore`] over its own backend runs this kit against its
//! implementation, in its own tests, to show that the store keeps the
//! trait's contract: one winner among simultaneous claims, the sequential
//! laws, and a fault that is an `Err`, never a claim.
//!
//! ```
//! # use bsv_middleware_core::store::{conformance, MemoryStore};
//! let store = MemoryStore::new();
//! let fail = |on: bool| store.fail(on);
//! conformance::block_on(conformance::prefix_store(&store, "my-host").fault(&fail).run()).unwrap();
//! ```
//!
//! Inside a runtime (tokio, `wasm-bindgen-futures` in a Worker), `.run().await`
//! in place of [`block_on`].
//!
//! # How the claims are started together
//!
//! Every concurrent law builds its N claim futures first and then drives
//! them on the current task under each [`Schedule`] in turn, at every N in
//! [`SIZES`] (2 to 33):
//!
//! - [`Schedule::Lockstep`]: each pass polls every unfinished claim once,
//!   in the order the claims were made;
//! - [`Schedule::Reversed`]: the same, in the reverse order;
//! - [`Schedule::Ahead`]`(i)`, for every `i` below N: claim `i` is polled
//!   first, then held back while the others are polled every pass, until
//!   they have finished or [`HELD_PASSES`] passes have gone by;
//! - [`Schedule::Random`]`(seed)`, [`RANDOM_SCHEDULES`] seeds by default:
//!   each of the first [`HELD_PASSES`] passes polls a seeded random subset
//!   of the unfinished claims, and every later pass all of them, in a
//!   seeded random order. A violation names its schedule, and with it the
//!   seed, so the run can be repeated.
//!
//! A pass that holds a claim back wakes the task, so the hold is bounded:
//! after [`HELD_PASSES`] passes every unfinished claim is polled on every
//! pass and waits on its own waker.
//!
//! Each claim of a schedule runs on a fresh key, and the law counts the
//! winners and names the law, N and the schedule.
//!
//! What this catches: a store whose claim can be interrupted between the
//! read that decides and the write that records (an await that is not
//! ready there), when some claim enters that window while another is inside
//! it under one of these poll orders at one of these N, and whose futures
//! make progress each time they are polled (a map, a local SQL connection,
//! a store that wakes itself). What it cannot catch: a race that needs a
//! poll order or an N it does not run; a race decided by the backend's own
//! clock rather than by the order of polls (inside a host's runtime the kit
//! orders the polls, not the backend's I/O); a race between processes or
//! isolates, since the kit runs on one thread. A store with one
//! indivisible claim (a compare-and-set, a statement under a unique
//! constraint read back in the same transaction, a single-threaded actor)
//! has exactly one winner under every schedule, however many awaits
//! surround that step. The kit can show that a store races; it cannot show
//! that a store never does.
//!
//! The kit has no runtime of its own and spawns nothing: it runs on one
//! thread, on every target (wasm32 included), and accepts stores that are
//! not `Send`. [`block_on`] polls with a no-op waker, for stores whose
//! futures make progress without an executor (a map, a local SQL
//! connection); a store whose futures wait on a host's I/O is driven by
//! awaiting `run()` inside that host's runtime.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use super::{ClaimStore, PaymentNonceStore, PaymentPrefixStore, PrefixClaim, StoreError};

/// The numbers of simultaneous claims every concurrent law is run at: every
/// N from 2 to 33.
pub const SIZES: &[usize] = &[
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33,
];

/// The number of [`Schedule::Random`] schedules each concurrent law runs at
/// each N, by default.
pub const RANDOM_SCHEDULES: usize = 8;

/// The base seed of the default [`Schedule::Random`] schedules.
pub const DEFAULT_SEED: u64 = 0x6b69_7473_6565_6400;

/// The passes in which [`Schedule::Ahead`] and [`Schedule::Random`] may
/// leave an unfinished claim unpolled; every later pass polls them all.
pub const HELD_PASSES: usize = 64;

/// A boxed future that need not be `Send`.
pub type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Writes a legacy record (one with no transaction binding) for a prefix.
pub type LegacySeeder<'a> = dyn Fn(String) -> LocalFuture<'a, Result<(), StoreError>> + 'a;

/// A law the store broke: which law, at which number of simultaneous claims
/// (1 for a sequential law), under which schedule, and what was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The law's name (one of the `LAW_*` constants).
    pub law: &'static str,
    /// The number of simultaneous claims (1 for a sequential law).
    pub n: usize,
    /// The schedule the claims were driven under (`None` for a sequential
    /// law, and for the fault laws, which run in lockstep).
    pub schedule: Option<Schedule>,
    /// What the store answered.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "law `{}` at N={}", self.law, self.n)?;
        if let Some(schedule) = self.schedule {
            write!(f, " under {schedule}")?;
        }
        write!(f, ": {}", self.detail)
    }
}

impl std::error::Error for Violation {}

/// The laws a run checked and the laws it could not (no fault switch, no
/// legacy seeder).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Each law checked, with the number of simultaneous claims.
    pub checked: Vec<(&'static str, usize)>,
    /// Each law not checked, for want of the hook it needs.
    pub skipped: Vec<&'static str>,
}

/// N claims of one prefix by one transaction: one `Won`, every other `SameTransaction`.
pub const LAW_PREFIX_ONE_TRANSACTION: &str = "prefix: one transaction, N claims";
/// N claims of one prefix by N transactions: one `Won`, every other
/// `OtherTransaction`; the winner's binding holds for every later claim.
pub const LAW_PREFIX_MANY_TRANSACTIONS: &str = "prefix: N transactions, one prefix";
/// The trait's sequential laws: held refuses its own transaction; release
/// lets only the bound transaction re-take; another transaction is refused
/// forever.
pub const LAW_PREFIX_SEQUENTIAL: &str = "prefix: sequential laws";
/// A legacy record with no binding answers `Unknown` to every transaction.
pub const LAW_PREFIX_LEGACY: &str = "prefix: legacy record";
/// A store that reports a fault answers `Err`, never a claim.
pub const LAW_PREFIX_FAIL_CLOSED: &str = "prefix: fail closed";
/// N claims of one key: one `true`.
pub const LAW_CLAIM_CONCURRENT: &str = "claim: N claims, one key";
/// A claimed key refuses; a released key can be claimed again.
pub const LAW_CLAIM_SEQUENTIAL: &str = "claim: sequential laws";
/// A store that reports a fault answers `Err`, never a claim.
pub const LAW_CLAIM_FAIL_CLOSED: &str = "claim: fail closed";
/// N consumptions of one nonce in one scope: one `true`.
pub const LAW_NONCE_CONCURRENT: &str = "nonce: N consumptions, one nonce";
/// A consumed nonce refuses; scopes are separate; a released nonce can be
/// consumed again.
pub const LAW_NONCE_SEQUENTIAL: &str = "nonce: sequential laws";
/// A store that reports a fault answers `Err`, never a consumption.
pub const LAW_NONCE_FAIL_CLOSED: &str = "nonce: fail closed";

// ── the driver ──────────────────────────────────────────────────────────

/// The order in which a concurrent law polls its N claims, pass by pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Schedule {
    /// Each pass polls every unfinished claim once, in the order made.
    Lockstep,
    /// Each pass polls every unfinished claim once, in the reverse order.
    Reversed,
    /// Claim `i` is polled first, once; then each pass polls the others,
    /// and claim `i` only once they have finished or [`HELD_PASSES`]
    /// passes have gone by.
    Ahead(usize),
    /// Each of the first [`HELD_PASSES`] passes polls a random subset of the
    /// unfinished claims (each with probability one half), every later pass
    /// all of them, in a random order; both drawn from the seed.
    Random(u64),
}

impl Schedule {
    fn tag(&self) -> String {
        match self {
            Schedule::Lockstep => "lockstep".into(),
            Schedule::Reversed => "reversed".into(),
            Schedule::Ahead(i) => format!("ahead-{i}"),
            Schedule::Random(seed) => format!("random-{seed:016x}"),
        }
    }
}

impl fmt::Display for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Schedule::Lockstep => f.write_str("schedule lockstep"),
            Schedule::Reversed => f.write_str("schedule reversed"),
            Schedule::Ahead(i) => write!(f, "schedule ahead (claim {i} first, then held back)"),
            Schedule::Random(seed) => write!(f, "schedule random (seed {seed:#018x})"),
        }
    }
}

/// The schedules a concurrent law runs at `n` claims, in this order:
/// reversed, lockstep, each claim ahead in turn, and `random` seeded random schedules whose
/// seeds are drawn from `seed` and `n`.
pub fn schedules(n: usize, random: usize, seed: u64) -> Vec<Schedule> {
    let mut out = vec![Schedule::Reversed, Schedule::Lockstep];
    out.extend((0..n).map(Schedule::Ahead));
    out.extend(
        (0..random)
            .map(|k| Schedule::Random(splitmix(seed ^ splitmix((n as u64) << 32 | k as u64)))),
    );
    out
}

fn splitmix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Drives `futures` together on the current task in lockstep: every poll
/// polls each unfinished future once, in order, with the caller's waker.
/// Outputs come back in the order of the input.
pub async fn together<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    drive(futures, Schedule::Lockstep).await
}

/// Drives `futures` together on the current task under `schedule`, with
/// the caller's waker. A pass that leaves an unfinished future unpolled
/// wakes the task, so a held-back future is always polled again. Outputs
/// come back in the order of the input.
pub async fn drive<F: Future>(futures: Vec<F>, schedule: Schedule) -> Vec<F::Output> {
    let state = match schedule {
        Schedule::Random(seed) => seed,
        _ => 0,
    };
    Driven {
        futures: futures.into_iter().map(|f| Some(Box::pin(f))).collect(),
        outputs: Vec::new(),
        schedule,
        pass: 0,
        state,
    }
    .await
}

struct Driven<F: Future> {
    futures: Vec<Option<Pin<Box<F>>>>,
    outputs: Vec<Option<F::Output>>,
    schedule: Schedule,
    pass: usize,
    state: u64,
}

// Each future is boxed, so nothing is pinned in place in this struct.
impl<F: Future> Unpin for Driven<F> {}

impl<F: Future> Driven<F> {
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(1);
        splitmix(self.state)
    }

    /// The claims this pass polls, in order.
    fn order(&mut self) -> Vec<usize> {
        let n = self.futures.len();
        match self.schedule {
            Schedule::Lockstep => (0..n).collect(),
            Schedule::Reversed => (0..n).rev().collect(),
            Schedule::Ahead(ahead) => {
                let others_done = self
                    .futures
                    .iter()
                    .enumerate()
                    .all(|(i, f)| i == ahead || f.is_none());
                if self.pass == 0 {
                    std::iter::once(ahead)
                        .chain((0..n).filter(|&i| i != ahead))
                        .collect()
                } else if others_done || self.pass >= HELD_PASSES {
                    (0..n).collect()
                } else {
                    (0..n).filter(|&i| i != ahead).collect()
                }
            }
            Schedule::Random(_) => {
                let mut order: Vec<usize> = (0..n).collect();
                for i in (1..n).rev() {
                    let j = (self.next() % (i as u64 + 1)) as usize;
                    order.swap(i, j);
                }
                if self.pass >= HELD_PASSES {
                    return order;
                }
                let mut kept = Vec::with_capacity(n);
                for i in order {
                    if self.next() & 1 == 1 {
                        kept.push(i);
                    }
                }
                kept
            }
        }
    }
}

impl<F: Future> Future for Driven<F> {
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.outputs.len() != this.futures.len() {
            this.outputs = (0..this.futures.len()).map(|_| None).collect();
        }
        let order = this.order();
        this.pass += 1;
        let mut polled = vec![false; this.futures.len()];
        for i in order {
            polled[i] = true;
            if let Some(future) = &mut this.futures[i] {
                if let Poll::Ready(value) = future.as_mut().poll(cx) {
                    this.outputs[i] = Some(value);
                    this.futures[i] = None;
                }
            }
        }
        let unfinished = this.futures.iter().any(Option::is_some);
        if !unfinished {
            return Poll::Ready(this.outputs.iter_mut().filter_map(Option::take).collect());
        }
        // A future this pass did not poll has registered no waker for it:
        // wake the task so that it is polled on a later pass.
        if this
            .futures
            .iter()
            .zip(&polled)
            .any(|(f, &p)| f.is_some() && !p)
        {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

/// The number of polls [`block_on`] makes before it gives up on a future
/// that never completes without an executor.
pub const BLOCK_ON_POLLS: usize = 10_000_000;

/// Runs `future` to completion on this thread, polling it with a no-op
/// waker. For stores whose futures complete without an executor's I/O;
/// panics after [`BLOCK_ON_POLLS`] polls without an answer.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..BLOCK_ON_POLLS {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("the future did not complete without an executor: await it in the host's runtime");
}

// ── names ───────────────────────────────────────────────────────────────

/// A transaction id for `label` under `namespace`: 64 lowercase hex
/// characters, distinct for distinct inputs.
pub fn txid_for(namespace: &str, label: &str) -> String {
    hex::encode(bsv_sdk::primitives::hash::sha256(
        format!("bsv-middleware-core conformance\0{namespace}\0{label}").as_bytes(),
    ))
}

fn key(namespace: &str, law: &str, n: usize) -> String {
    let law: String = law
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{namespace}:{law}:{n}")
}

fn key_under(namespace: &str, law: &str, n: usize, schedule: Schedule) -> String {
    format!("{}:{}", key(namespace, law, n), schedule.tag())
}

fn under(schedule: Schedule) -> impl Fn(Violation) -> Violation {
    move |mut v| {
        v.schedule = Some(schedule);
        v
    }
}

fn fault(law: &'static str, n: usize, step: &str, e: &StoreError) -> Violation {
    Violation {
        law,
        n,
        schedule: None,
        detail: format!("{step}: the store faulted ({e}) outside a fault test"),
    }
}

fn expect<T: PartialEq + fmt::Debug>(
    law: &'static str,
    n: usize,
    step: &str,
    got: T,
    want: T,
) -> Result<(), Violation> {
    if got == want {
        Ok(())
    } else {
        Err(Violation {
            law,
            n,
            schedule: None,
            detail: format!("{step}: answered {got:?}, the law requires {want:?}"),
        })
    }
}

// ── PaymentPrefixStore ──────────────────────────────────────────────────

const AGENT: &str = "conformance";

/// Law (a): `n` claims of one fresh prefix by one transaction, started
/// together: exactly one `Won`, every other `SameTransaction`. Run under
/// every schedule of [`schedules`]`(n, RANDOM_SCHEDULES, DEFAULT_SEED)`.
pub async fn prefix_one_transaction<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    n: usize,
) -> Result<(), Violation> {
    for schedule in schedules(n, RANDOM_SCHEDULES, DEFAULT_SEED) {
        prefix_one_transaction_under(store, namespace, n, schedule).await?;
    }
    Ok(())
}

/// Law (a) under one schedule.
pub async fn prefix_one_transaction_under<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    n: usize,
    schedule: Schedule,
) -> Result<(), Violation> {
    one_transaction(store, namespace, n, schedule)
        .await
        .map_err(under(schedule))
}

async fn one_transaction<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    n: usize,
    schedule: Schedule,
) -> Result<(), Violation> {
    let law = LAW_PREFIX_ONE_TRANSACTION;
    let prefix = key_under(namespace, law, n, schedule);
    let txid = txid_for(namespace, &prefix);
    let answers = drive(
        (0..n)
            .map(|_| store.claim_prefix(&prefix, &txid, AGENT))
            .collect(),
        schedule,
    )
    .await;
    let mut won = 0;
    for (i, answer) in answers.into_iter().enumerate() {
        match answer {
            Ok(PrefixClaim::Won) => won += 1,
            Ok(PrefixClaim::SameTransaction) => {}
            Ok(other) => {
                return Err(Violation {
                    law,
                    n,
                    schedule: None,
                    detail: format!("claim {i} answered {other:?}; only Won or SameTransaction"),
                })
            }
            Err(e) => return Err(fault(law, n, &format!("claim {i}"), &e)),
        }
    }
    expect(law, n, "the number of Won", won, 1)
}

/// Law (b): `n` claims of one fresh prefix by `n` different transactions,
/// started together: exactly one `Won`, every other `OtherTransaction`;
/// afterwards the winner's transaction is bound for every later claim, and
/// stays bound after its release. Run under every schedule of
/// [`schedules`]`(n, RANDOM_SCHEDULES, DEFAULT_SEED)`.
pub async fn prefix_many_transactions<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    n: usize,
) -> Result<(), Violation> {
    for schedule in schedules(n, RANDOM_SCHEDULES, DEFAULT_SEED) {
        prefix_many_transactions_under(store, namespace, n, schedule).await?;
    }
    Ok(())
}

/// Law (b) under one schedule.
pub async fn prefix_many_transactions_under<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    n: usize,
    schedule: Schedule,
) -> Result<(), Violation> {
    many_transactions(store, namespace, n, schedule)
        .await
        .map_err(under(schedule))
}

async fn many_transactions<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    n: usize,
    schedule: Schedule,
) -> Result<(), Violation> {
    let law = LAW_PREFIX_MANY_TRANSACTIONS;
    let prefix = key_under(namespace, law, n, schedule);
    let txids: Vec<String> = (0..n)
        .map(|i| txid_for(namespace, &format!("{prefix}/{i}")))
        .collect();
    let answers = drive(
        txids
            .iter()
            .map(|txid| store.claim_prefix(&prefix, txid, AGENT))
            .collect(),
        schedule,
    )
    .await;
    let mut winners = Vec::new();
    for (i, answer) in answers.into_iter().enumerate() {
        match answer {
            Ok(PrefixClaim::Won) => winners.push(i),
            Ok(PrefixClaim::OtherTransaction) => {}
            Ok(other) => {
                return Err(Violation {
                    law,
                    n,
                    schedule: None,
                    detail: format!("claim {i} answered {other:?}; only Won or OtherTransaction"),
                })
            }
            Err(e) => return Err(fault(law, n, &format!("claim {i}"), &e)),
        }
    }
    expect(law, n, "the number of Won", winners.len(), 1)?;
    let winner = winners[0];
    let later = |i: usize| -> PrefixClaim {
        if i == winner {
            PrefixClaim::SameTransaction
        } else {
            PrefixClaim::OtherTransaction
        }
    };
    for (i, txid) in txids.iter().enumerate() {
        let answer = store
            .claim_prefix(&prefix, txid, AGENT)
            .await
            .map_err(|e| fault(law, n, "a later claim", &e))?;
        expect(law, n, &format!("a later claim by {i}"), answer, later(i))?;
    }
    store
        .release_prefix(&prefix, &txids[winner])
        .await
        .map_err(|e| fault(law, n, "the winner's release", &e))?;
    for (i, txid) in txids.iter().enumerate().filter(|(i, _)| *i != winner) {
        let answer = store
            .claim_prefix(&prefix, txid, AGENT)
            .await
            .map_err(|e| fault(law, n, "a claim after release", &e))?;
        expect(
            law,
            n,
            &format!("claim by {i} after the winner's release"),
            answer,
            PrefixClaim::OtherTransaction,
        )?;
    }
    let answer = store
        .claim_prefix(&prefix, &txids[winner], AGENT)
        .await
        .map_err(|e| fault(law, n, "the winner's re-take", &e))?;
    expect(law, n, "the winner's re-take", answer, PrefixClaim::Won)
}

/// Law (c): the sequential laws of [`PaymentPrefixStore`]. A held record
/// refuses its own transaction; a release by another transaction changes
/// nothing; a release lets only the bound transaction re-take, once;
/// another transaction is refused, released or not.
pub async fn prefix_sequential<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
) -> Result<(), Violation> {
    let law = LAW_PREFIX_SEQUENTIAL;
    let prefix = key(namespace, law, 1);
    let a = txid_for(namespace, &format!("{prefix}/a"));
    let b = txid_for(namespace, &format!("{prefix}/b"));
    let claim = |txid: &str, step: &'static str, want: PrefixClaim| {
        let txid = txid.to_string();
        let prefix = prefix.clone();
        async move {
            let got = store
                .claim_prefix(&prefix, &txid, AGENT)
                .await
                .map_err(|e| fault(law, 1, step, &e))?;
            expect(law, 1, step, got, want)
        }
    };
    let release = |txid: &str, step: &'static str| {
        let txid = txid.to_string();
        let prefix = prefix.clone();
        async move {
            store
                .release_prefix(&prefix, &txid)
                .await
                .map_err(|e| fault(law, 1, step, &e))
        }
    };
    claim(&a, "a fresh claim", PrefixClaim::Won).await?;
    claim(
        &a,
        "the held record, its own transaction",
        PrefixClaim::SameTransaction,
    )
    .await?;
    claim(
        &b,
        "the held record, another transaction",
        PrefixClaim::OtherTransaction,
    )
    .await?;
    release(&b, "a release by another transaction").await?;
    claim(
        &a,
        "after another transaction's release, its own transaction",
        PrefixClaim::SameTransaction,
    )
    .await?;
    claim(
        &b,
        "after another transaction's release, that transaction",
        PrefixClaim::OtherTransaction,
    )
    .await?;
    release(&a, "the bound transaction's release").await?;
    claim(
        &b,
        "the released record, another transaction",
        PrefixClaim::OtherTransaction,
    )
    .await?;
    claim(
        &a,
        "the released record, its own transaction",
        PrefixClaim::Won,
    )
    .await?;
    claim(
        &a,
        "the re-taken record, its own transaction",
        PrefixClaim::SameTransaction,
    )
    .await?;
    claim(
        &b,
        "the re-taken record, another transaction",
        PrefixClaim::OtherTransaction,
    )
    .await
}

/// Law (c), legacy: a record written by `seed` with no transaction binding
/// answers `Unknown` to every transaction, before and after a release.
pub async fn prefix_legacy<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    seed: &LegacySeeder<'_>,
) -> Result<(), Violation> {
    let law = LAW_PREFIX_LEGACY;
    let prefix = key(namespace, law, 1);
    seed(prefix.clone()).await.map_err(|e| Violation {
        law,
        n: 1,
        schedule: None,
        detail: format!("the legacy seeder faulted: {e}"),
    })?;
    for label in ["a", "b"] {
        let txid = txid_for(namespace, &format!("{prefix}/{label}"));
        let got = store
            .claim_prefix(&prefix, &txid, AGENT)
            .await
            .map_err(|e| fault(law, 1, "a claim of the legacy record", &e))?;
        expect(
            law,
            1,
            "a claim of the legacy record",
            got,
            PrefixClaim::Unknown,
        )?;
        store
            .release_prefix(&prefix, &txid)
            .await
            .map_err(|e| fault(law, 1, "a release of the legacy record", &e))?;
        let got = store
            .claim_prefix(&prefix, &txid, AGENT)
            .await
            .map_err(|e| fault(law, 1, "a claim after a release", &e))?;
        expect(law, 1, "a claim after a release", got, PrefixClaim::Unknown)?;
    }
    Ok(())
}

/// Law (d): with `fault(true)` in force, a claim of a fresh prefix and a
/// release are `Err`, never a claim; `n` claims started together all are.
pub async fn prefix_fail_closed<S: PaymentPrefixStore>(
    store: &S,
    namespace: &str,
    fault_switch: &dyn Fn(bool),
    n: usize,
) -> Result<(), Violation> {
    let law = LAW_PREFIX_FAIL_CLOSED;
    let prefix = key(namespace, law, n);
    let txid = txid_for(namespace, &prefix);
    fault_switch(true);
    let answers = together(
        (0..n)
            .map(|_| store.claim_prefix(&prefix, &txid, AGENT))
            .collect(),
    )
    .await;
    let release = store.release_prefix(&prefix, &txid).await;
    fault_switch(false);
    for (i, answer) in answers.into_iter().enumerate() {
        if let Ok(claim) = answer {
            return Err(Violation {
                law,
                n,
                schedule: None,
                detail: format!("claim {i} under a fault answered Ok({claim:?}); a fault is Err"),
            });
        }
    }
    if release.is_ok() {
        return Err(Violation {
            law,
            n,
            schedule: None,
            detail: "a release under a fault answered Ok; a fault is Err".into(),
        });
    }
    Ok(())
}

/// Runs the [`PaymentPrefixStore`] laws against one store.
pub struct PrefixStoreKit<'a, S> {
    store: &'a S,
    namespace: &'a str,
    sizes: &'a [usize],
    random: usize,
    seed: u64,
    fault: Option<&'a dyn Fn(bool)>,
    legacy: Option<&'a LegacySeeder<'a>>,
}

/// The [`PaymentPrefixStore`] laws for `store`. `namespace` prefixes every
/// key the kit writes: use a fresh one for each run on a store that keeps
/// its records.
pub fn prefix_store<'a, S: PaymentPrefixStore>(
    store: &'a S,
    namespace: &'a str,
) -> PrefixStoreKit<'a, S> {
    PrefixStoreKit {
        store,
        namespace,
        sizes: SIZES,
        random: RANDOM_SCHEDULES,
        seed: DEFAULT_SEED,
        fault: None,
        legacy: None,
    }
}

impl<'a, S: PaymentPrefixStore> PrefixStoreKit<'a, S> {
    /// The switch that makes the store report a fault (`true`) or not.
    pub fn fault(mut self, switch: &'a dyn Fn(bool)) -> Self {
        self.fault = Some(switch);
        self
    }

    /// Writes a legacy record (no transaction binding) for a prefix.
    pub fn legacy(mut self, seed: &'a LegacySeeder<'a>) -> Self {
        self.legacy = Some(seed);
        self
    }

    /// The numbers of simultaneous claims (default [`SIZES`]).
    pub fn sizes(mut self, sizes: &'a [usize]) -> Self {
        self.sizes = sizes;
        self
    }

    /// The number of [`Schedule::Random`] schedules at each N (default
    /// [`RANDOM_SCHEDULES`]) and the base seed they are drawn from
    /// (default [`DEFAULT_SEED`]).
    pub fn random(mut self, count: usize, seed: u64) -> Self {
        self.random = count;
        self.seed = seed;
        self
    }

    /// Every law, in order; the first law broken is the `Err`.
    pub async fn run(self) -> Result<Report, Violation> {
        let mut report = Report::default();
        for &n in self.sizes {
            for schedule in schedules(n, self.random, self.seed) {
                prefix_one_transaction_under(self.store, self.namespace, n, schedule).await?;
            }
            report.checked.push((LAW_PREFIX_ONE_TRANSACTION, n));
        }
        for &n in self.sizes {
            for schedule in schedules(n, self.random, self.seed) {
                prefix_many_transactions_under(self.store, self.namespace, n, schedule).await?;
            }
            report.checked.push((LAW_PREFIX_MANY_TRANSACTIONS, n));
        }
        prefix_sequential(self.store, self.namespace).await?;
        report.checked.push((LAW_PREFIX_SEQUENTIAL, 1));
        match self.legacy {
            Some(seed) => {
                prefix_legacy(self.store, self.namespace, seed).await?;
                report.checked.push((LAW_PREFIX_LEGACY, 1));
            }
            None => report.skipped.push(LAW_PREFIX_LEGACY),
        }
        match self.fault {
            Some(switch) => {
                for &n in self.sizes {
                    prefix_fail_closed(self.store, self.namespace, switch, n).await?;
                    report.checked.push((LAW_PREFIX_FAIL_CLOSED, n));
                }
            }
            None => report.skipped.push(LAW_PREFIX_FAIL_CLOSED),
        }
        Ok(report)
    }
}

// ── ClaimStore ──────────────────────────────────────────────────────────

/// `n` claims of one fresh key, started together: exactly one `true`. Run
/// under every schedule of [`schedules`]`(n, RANDOM_SCHEDULES, DEFAULT_SEED)`.
pub async fn claim_concurrent<S: ClaimStore>(
    store: &S,
    namespace: &str,
    n: usize,
) -> Result<(), Violation> {
    for schedule in schedules(n, RANDOM_SCHEDULES, DEFAULT_SEED) {
        claim_concurrent_under(store, namespace, n, schedule).await?;
    }
    Ok(())
}

/// [`claim_concurrent`] under one schedule.
pub async fn claim_concurrent_under<S: ClaimStore>(
    store: &S,
    namespace: &str,
    n: usize,
    schedule: Schedule,
) -> Result<(), Violation> {
    let law = LAW_CLAIM_CONCURRENT;
    let claim_key = key_under(namespace, law, n, schedule);
    let answers = drive(
        (0..n).map(|_| store.claim(&claim_key, AGENT)).collect(),
        schedule,
    )
    .await;
    let mut won = 0;
    for (i, answer) in answers.into_iter().enumerate() {
        match answer {
            Ok(true) => won += 1,
            Ok(false) => {}
            Err(e) => return Err(under(schedule)(fault(law, n, &format!("claim {i}"), &e))),
        }
    }
    expect(law, n, "the number of claims won", won, 1).map_err(under(schedule))
}

/// A fresh key is won once; a second claim is refused; after a release it
/// is won again, once.
pub async fn claim_sequential<S: ClaimStore>(store: &S, namespace: &str) -> Result<(), Violation> {
    let law = LAW_CLAIM_SEQUENTIAL;
    let claim_key = key(namespace, law, 1);
    let step = |s: &'static str| move |e: StoreError| fault(law, 1, s, &e);
    let first = store
        .claim(&claim_key, AGENT)
        .await
        .map_err(step("a fresh claim"))?;
    expect(law, 1, "a fresh claim", first, true)?;
    let again = store
        .claim(&claim_key, AGENT)
        .await
        .map_err(step("a second claim"))?;
    expect(law, 1, "a second claim", again, false)?;
    store.release(&claim_key).await.map_err(step("a release"))?;
    let retaken = store
        .claim(&claim_key, AGENT)
        .await
        .map_err(step("a claim after release"))?;
    expect(law, 1, "a claim after release", retaken, true)?;
    let again = store
        .claim(&claim_key, AGENT)
        .await
        .map_err(step("a claim after re-take"))?;
    expect(law, 1, "a claim after re-take", again, false)
}

/// With `fault(true)` in force, `n` claims started together are all `Err`
/// (a release is best-effort by the trait, so it is not judged).
pub async fn claim_fail_closed<S: ClaimStore>(
    store: &S,
    namespace: &str,
    fault_switch: &dyn Fn(bool),
    n: usize,
) -> Result<(), Violation> {
    let law = LAW_CLAIM_FAIL_CLOSED;
    let claim_key = key(namespace, law, n);
    fault_switch(true);
    let answers = together((0..n).map(|_| store.claim(&claim_key, AGENT)).collect()).await;
    fault_switch(false);
    if let Some((i, Ok(won))) = answers.iter().enumerate().find(|(_, a)| a.is_ok()) {
        return Err(Violation {
            law,
            n,
            schedule: None,
            detail: format!("claim {i} under a fault answered Ok({won}); a fault is Err"),
        });
    }
    Ok(())
}

/// Runs the [`ClaimStore`] laws against one store.
pub struct ClaimStoreKit<'a, S> {
    store: &'a S,
    namespace: &'a str,
    sizes: &'a [usize],
    random: usize,
    seed: u64,
    fault: Option<&'a dyn Fn(bool)>,
}

/// The [`ClaimStore`] laws for `store`; `namespace` as in [`prefix_store`].
pub fn claim_store<'a, S: ClaimStore>(store: &'a S, namespace: &'a str) -> ClaimStoreKit<'a, S> {
    ClaimStoreKit {
        store,
        namespace,
        sizes: SIZES,
        random: RANDOM_SCHEDULES,
        seed: DEFAULT_SEED,
        fault: None,
    }
}

impl<'a, S: ClaimStore> ClaimStoreKit<'a, S> {
    /// The switch that makes the store report a fault (`true`) or not.
    pub fn fault(mut self, switch: &'a dyn Fn(bool)) -> Self {
        self.fault = Some(switch);
        self
    }

    /// The numbers of simultaneous claims (default [`SIZES`]).
    pub fn sizes(mut self, sizes: &'a [usize]) -> Self {
        self.sizes = sizes;
        self
    }

    /// The number of [`Schedule::Random`] schedules at each N (default
    /// [`RANDOM_SCHEDULES`]) and the base seed they are drawn from
    /// (default [`DEFAULT_SEED`]).
    pub fn random(mut self, count: usize, seed: u64) -> Self {
        self.random = count;
        self.seed = seed;
        self
    }

    /// Every law, in order; the first law broken is the `Err`.
    pub async fn run(self) -> Result<Report, Violation> {
        let mut report = Report::default();
        for &n in self.sizes {
            for schedule in schedules(n, self.random, self.seed) {
                claim_concurrent_under(self.store, self.namespace, n, schedule).await?;
            }
            report.checked.push((LAW_CLAIM_CONCURRENT, n));
        }
        claim_sequential(self.store, self.namespace).await?;
        report.checked.push((LAW_CLAIM_SEQUENTIAL, 1));
        match self.fault {
            Some(switch) => {
                for &n in self.sizes {
                    claim_fail_closed(self.store, self.namespace, switch, n).await?;
                    report.checked.push((LAW_CLAIM_FAIL_CLOSED, n));
                }
            }
            None => report.skipped.push(LAW_CLAIM_FAIL_CLOSED),
        }
        Ok(report)
    }
}

// ── PaymentNonceStore ───────────────────────────────────────────────────

/// `n` consumptions of one fresh nonce in one scope, started together:
/// exactly one `true`. Run under every schedule of
/// [`schedules`]`(n, RANDOM_SCHEDULES, DEFAULT_SEED)`.
pub async fn nonce_concurrent<S: PaymentNonceStore>(
    store: &S,
    namespace: &str,
    n: usize,
) -> Result<(), Violation> {
    for schedule in schedules(n, RANDOM_SCHEDULES, DEFAULT_SEED) {
        nonce_concurrent_under(store, namespace, n, schedule).await?;
    }
    Ok(())
}

/// [`nonce_concurrent`] under one schedule.
pub async fn nonce_concurrent_under<S: PaymentNonceStore>(
    store: &S,
    namespace: &str,
    n: usize,
    schedule: Schedule,
) -> Result<(), Violation> {
    let law = LAW_NONCE_CONCURRENT;
    let scope = key_under(namespace, law, n, schedule);
    let answers = drive(
        (0..n)
            .map(|_| store.try_consume(&scope, "nonce", None))
            .collect(),
        schedule,
    )
    .await;
    let mut won = 0;
    for (i, answer) in answers.into_iter().enumerate() {
        match answer {
            Ok(true) => won += 1,
            Ok(false) => {}
            Err(e) => {
                return Err(under(schedule)(fault(
                    law,
                    n,
                    &format!("consumption {i}"),
                    &e,
                )))
            }
        }
    }
    expect(law, n, "the number of consumptions won", won, 1).map_err(under(schedule))
}

/// A fresh nonce is consumed once; the same nonce in another scope is
/// fresh; after a release it is consumed again, once.
pub async fn nonce_sequential<S: PaymentNonceStore>(
    store: &S,
    namespace: &str,
) -> Result<(), Violation> {
    let law = LAW_NONCE_SEQUENTIAL;
    let scope = key(namespace, law, 1);
    let other = format!("{scope}:other");
    let step = |s: &'static str| move |e: StoreError| fault(law, 1, s, &e);
    let ttl = Some(3600);
    let first = store
        .try_consume(&scope, "n", ttl)
        .await
        .map_err(step("a fresh nonce"))?;
    expect(law, 1, "a fresh nonce", first, true)?;
    let again = store
        .try_consume(&scope, "n", ttl)
        .await
        .map_err(step("a replay"))?;
    expect(law, 1, "a replay", again, false)?;
    let scoped = store
        .try_consume(&other, "n", ttl)
        .await
        .map_err(step("another scope"))?;
    expect(law, 1, "the same nonce in another scope", scoped, true)?;
    store
        .release(&scope, "n")
        .await
        .map_err(step("a release"))?;
    let retaken = store
        .try_consume(&scope, "n", ttl)
        .await
        .map_err(step("after release"))?;
    expect(law, 1, "a consumption after release", retaken, true)?;
    let again = store
        .try_consume(&scope, "n", ttl)
        .await
        .map_err(step("a second replay"))?;
    expect(law, 1, "a replay after re-take", again, false)
}

/// With `fault(true)` in force, `n` consumptions started together are all
/// `Err` (a release is best-effort by the trait, so it is not judged).
pub async fn nonce_fail_closed<S: PaymentNonceStore>(
    store: &S,
    namespace: &str,
    fault_switch: &dyn Fn(bool),
    n: usize,
) -> Result<(), Violation> {
    let law = LAW_NONCE_FAIL_CLOSED;
    let scope = key(namespace, law, n);
    fault_switch(true);
    let answers = together(
        (0..n)
            .map(|_| store.try_consume(&scope, "nonce", None))
            .collect(),
    )
    .await;
    fault_switch(false);
    if let Some((i, Ok(won))) = answers.iter().enumerate().find(|(_, a)| a.is_ok()) {
        return Err(Violation {
            law,
            n,
            schedule: None,
            detail: format!("consumption {i} under a fault answered Ok({won}); a fault is Err"),
        });
    }
    Ok(())
}

/// Runs the [`PaymentNonceStore`] laws against one store.
pub struct NonceStoreKit<'a, S> {
    store: &'a S,
    namespace: &'a str,
    sizes: &'a [usize],
    random: usize,
    seed: u64,
    fault: Option<&'a dyn Fn(bool)>,
}

/// The [`PaymentNonceStore`] laws for `store`; `namespace` as in [`prefix_store`].
pub fn nonce_store<'a, S: PaymentNonceStore>(
    store: &'a S,
    namespace: &'a str,
) -> NonceStoreKit<'a, S> {
    NonceStoreKit {
        store,
        namespace,
        sizes: SIZES,
        random: RANDOM_SCHEDULES,
        seed: DEFAULT_SEED,
        fault: None,
    }
}

impl<'a, S: PaymentNonceStore> NonceStoreKit<'a, S> {
    /// The switch that makes the store report a fault (`true`) or not.
    pub fn fault(mut self, switch: &'a dyn Fn(bool)) -> Self {
        self.fault = Some(switch);
        self
    }

    /// The numbers of simultaneous consumptions (default [`SIZES`]).
    pub fn sizes(mut self, sizes: &'a [usize]) -> Self {
        self.sizes = sizes;
        self
    }

    /// The number of [`Schedule::Random`] schedules at each N (default
    /// [`RANDOM_SCHEDULES`]) and the base seed they are drawn from
    /// (default [`DEFAULT_SEED`]).
    pub fn random(mut self, count: usize, seed: u64) -> Self {
        self.random = count;
        self.seed = seed;
        self
    }

    /// Every law, in order; the first law broken is the `Err`.
    pub async fn run(self) -> Result<Report, Violation> {
        let mut report = Report::default();
        for &n in self.sizes {
            for schedule in schedules(n, self.random, self.seed) {
                nonce_concurrent_under(self.store, self.namespace, n, schedule).await?;
            }
            report.checked.push((LAW_NONCE_CONCURRENT, n));
        }
        nonce_sequential(self.store, self.namespace).await?;
        report.checked.push((LAW_NONCE_SEQUENTIAL, 1));
        match self.fault {
            Some(switch) => {
                for &n in self.sizes {
                    nonce_fail_closed(self.store, self.namespace, switch, n).await?;
                    report.checked.push((LAW_NONCE_FAIL_CLOSED, n));
                }
            }
            None => report.skipped.push(LAW_NONCE_FAIL_CLOSED),
        }
        Ok(report)
    }
}
