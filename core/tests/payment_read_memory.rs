//! The payment read's memory is a bounded multiple of the body.
//!
//! The adapter's payment door reads the payer's BEEF through two core
//! functions, in this order: [`verify_payment_output`], then
//! [`payment_subject_txid`]. This test builds payments the size of a 128 KiB
//! `x-bsv-payment` header, runs both functions under a counting allocator, and
//! holds the peak heap of each call to a fixed multiple of the BEEF's size.
//!
//! The shapes:
//! - a wide parent (many outputs), unproven, spent by many inputs of the
//!   subject (two widths);
//! - the same parent proven by a BUMP;
//! - a parent of one output proven by a wide BUMP, spent by many inputs;
//! - many tiny transactions (no input, no output) before the subject, in
//!   BEEF V2 and V1;
//! - a subject of many empty outputs.
//!
//! Output 0 of every subject pays the derived script, so each body is a
//! payment the output check answers `Verified` for, and the subject's txid is
//! the subject's.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use bsv_middleware_core::{
    expected_locking_script, payment_subject_txid, verify_payment_output, PaymentVerdict,
};
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::script::{LockingScript, UnlockingScript};
use bsv_sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput, BEEF_V1,
    BEEF_V2,
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// The peak with a growing `realloc` counted as its growth alone.
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The peak with the old and the new block both live during a `realloc`.
static PEAK_HELD: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
            PEAK_HELD.fetch_max(live, Ordering::SeqCst);
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            PEAK_HELD.fetch_max(LIVE.load(Ordering::SeqCst) + new_size, Ordering::SeqCst);
            let live = if new_size >= layout.size() {
                LIVE.fetch_add(new_size - layout.size(), Ordering::SeqCst) + new_size
                    - layout.size()
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst)
                    - (layout.size() - new_size)
            };
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        new_ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        System.dealloc(ptr, layout);
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The ceiling: each call's peak heap, above what was live before it, is at
/// most this many times the BEEF's size.
const CEILING_PER_BODY_BYTE: usize = 128;

/// The size of the header the payment travels in.
const HEADER_BYTES: usize = 128 * 1024;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const PREFIX: &str = "cGF5bWVudC1yZWFkLW1lbW9yeS1wcmVmaXg=";
const SUFFIX: &str = "cGF5bWVudC1yZWFkLW1lbW9yeS1zdWZmaXg=";

/// The BEEF bytes that fit the header as the payment's JSON
/// `{"derivationPrefix","derivationSuffix","transaction"}`, base64.
fn beef_budget() -> usize {
    let overhead = r#"{"derivationPrefix":"","derivationSuffix":"","transaction":""}"#.len()
        + PREFIX.len()
        + SUFFIX.len();
    (HEADER_BYTES - overhead) / 4 * 3
}

fn hash_of(i: u64) -> String {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&i.to_le_bytes());
    b[31] = 0xab;
    hex::encode(b)
}

/// A subject of one input from outside the BEEF, output 0 paying `pay`,
/// then `empty_outputs` outputs of value 0 and an empty script.
fn subject(pay: &[u8], empty_outputs: usize) -> Transaction {
    let mut subject = Transaction::new();
    let mut outside = TransactionInput::new(hash_of(9), 0);
    outside.unlocking_script = Some(UnlockingScript::new());
    subject.inputs.push(outside);
    subject
        .add_output(TransactionOutput::new(
            1000,
            LockingScript::from_binary(pay).unwrap(),
        ))
        .unwrap();
    for _ in 0..empty_outputs {
        subject
            .add_output(TransactionOutput::new(0, LockingScript::new()))
            .unwrap();
    }
    subject
}

/// One parent (one input from outside the BEEF, `outputs` empty-script
/// outputs), proven when `bump_leaves > 0` by a BUMP whose level 0 holds
/// `bump_leaves` leaves; one subject of `inputs` inputs spending the parent's
/// outputs in turn, output 0 paying `pay`.
fn payment(outputs: usize, inputs: usize, bump_leaves: usize, pay: &[u8]) -> (Vec<u8>, String) {
    let mut parent = Transaction::new();
    let mut outside = TransactionInput::new(hash_of(7), 0);
    outside.unlocking_script = Some(UnlockingScript::new());
    parent.inputs.push(outside);
    for _ in 0..outputs {
        parent
            .add_output(TransactionOutput::new(1, LockingScript::new()))
            .unwrap();
    }
    let parent_txid = parent.id();
    let mut subject = Transaction::new();
    subject
        .add_output(TransactionOutput::new(
            1000,
            LockingScript::from_binary(pay).unwrap(),
        ))
        .unwrap();
    for i in 0..inputs {
        let mut input = TransactionInput::new(parent_txid.clone(), (i % outputs) as u32);
        input.unlocking_script = Some(UnlockingScript::new());
        subject.inputs.push(input);
    }
    let mut beef = Beef::new();
    let bump = (bump_leaves > 0).then(|| {
        let mut level0 = vec![MerklePathLeaf::new_txid(0, parent_txid.clone())];
        for offset in 1..bump_leaves as u64 {
            level0.push(MerklePathLeaf::new(offset, hash_of(1000 + offset)));
        }
        let mut path = vec![level0];
        for _ in 1..bump_leaves.trailing_zeros() {
            path.push(vec![]);
        }
        beef.merge_bump(MerklePath::new(900_000, path).unwrap())
    });
    beef.merge_raw_tx(parent.to_binary(), bump);
    beef.merge_raw_tx(subject.to_binary(), None);
    (beef.to_binary(), subject.id())
}

/// One subject of `empty_outputs + 1` outputs.
fn many_outputs(empty_outputs: usize, pay: &[u8]) -> (Vec<u8>, String) {
    let subject = subject(pay, empty_outputs);
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None);
    (beef.to_binary(), subject.id())
}

fn write_varint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

/// `tiny` transactions of no input and no output (each 10 bytes, told
/// apart by their locktime), then the subject, as BEEF V1 or V2 without a
/// BUMP, written entry by entry in this order.
fn many_tiny(tiny: usize, v1: bool, pay: &[u8]) -> (Vec<u8>, String) {
    let subject = subject(pay, 0);
    let mut entries: Vec<Vec<u8>> = (0..tiny)
        .map(|i| {
            let mut tx = Transaction::new();
            tx.lock_time = i as u32;
            tx.to_binary()
        })
        .collect();
    entries.push(subject.to_binary());
    let mut body = Vec::new();
    body.extend_from_slice(&if v1 { BEEF_V1 } else { BEEF_V2 }.to_le_bytes());
    write_varint(0, &mut body);
    write_varint(entries.len() as u64, &mut body);
    for entry in entries {
        if v1 {
            body.extend_from_slice(&entry);
            body.push(0);
        } else {
            body.push(0);
            body.extend_from_slice(&entry);
        }
    }
    (body, subject.id())
}

/// The largest count `n` whose payment `make(n)` still fits the header.
fn fill(make: impl Fn(usize) -> (Vec<u8>, String)) -> (Vec<u8>, String) {
    let budget = beef_budget();
    let (mut lo, mut hi) = (1usize, budget);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if make(mid).0.len() <= budget {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    make(lo)
}

/// The heap a call holds at its peak, above what was live when it began, by
/// each accounting: a `realloc`'s growth alone, and both blocks held.
fn peak_of<T>(call: impl FnOnce() -> T) -> (T, usize, usize) {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    PEAK_HELD.store(base, Ordering::SeqCst);
    let answer = call();
    (
        answer,
        PEAK.load(Ordering::SeqCst) - base,
        PEAK_HELD.load(Ordering::SeqCst) - base,
    )
}

/// The payment read's memory is a bounded multiple of the body: on every
/// shape, each of the door's two reads peaks at most
/// [`CEILING_PER_BODY_BYTE`] times the BEEF's size, with both blocks of a
/// `realloc` counted, and reads the subject's verdict and txid.
#[test]
fn the_payment_reads_memory_follows_the_body() {
    let sender = PrivateKey::from_hex(SENDER_KEY)
        .unwrap()
        .public_key()
        .to_hex();
    let pay =
        hex::decode(expected_locking_script(SERVER_KEY, &sender, PREFIX, SUFFIX).unwrap()).unwrap();
    type Make<'a> = Box<dyn Fn(usize) -> (Vec<u8>, String) + 'a>;
    let shapes: Vec<(&str, Make)> = vec![
        (
            "wide unproven parent",
            Box::new(|n| payment(6144, n, 0, &pay)),
        ),
        ("unproven parent", Box::new(|n| payment(768, n, 0, &pay))),
        (
            "wide proven parent",
            Box::new(|n| payment(6144, n, 2, &pay)),
        ),
        (
            "proven parent, wide BUMP",
            Box::new(|n| payment(1, n, 1024, &pay)),
        ),
        (
            "many tiny transactions, then the subject (BEEF V2)",
            Box::new(|n| many_tiny(n, false, &pay)),
        ),
        (
            "many tiny transactions, then the subject (BEEF V1)",
            Box::new(|n| many_tiny(n, true, &pay)),
        ),
        (
            "subject of many empty outputs",
            Box::new(|n| many_outputs(n, &pay)),
        ),
    ];
    for (name, make) in shapes {
        let (body, subject) = fill(make);
        assert!(body.len() <= beef_budget() && body.len() > beef_budget() * 9 / 10);
        let ceiling = CEILING_PER_BODY_BYTE * body.len();
        let times = |peak: usize| peak as f64 / body.len() as f64;

        let (verdict, verify_grown, verify_held) =
            peak_of(|| verify_payment_output(SERVER_KEY, &sender, PREFIX, SUFFIX, &body, 0, 1000));
        let (txid, subject_grown, subject_held) = peak_of(|| payment_subject_txid(&body));
        println!(
            "{name}: body {} B; output check peak {verify_held} B ({:.1}x held, {:.1}x grown); \
             subject txid peak {subject_held} B ({:.1}x held, {:.1}x grown)",
            body.len(),
            times(verify_held),
            times(verify_grown),
            times(subject_held),
            times(subject_grown),
        );
        assert!(
            verify_held <= ceiling,
            "{name}: the output check peaked at {verify_held} B on a {} B body",
            body.len()
        );
        assert!(
            subject_held <= ceiling,
            "{name}: the subject read peaked at {subject_held} B on a {} B body",
            body.len()
        );
        assert_eq!(
            verdict.unwrap(),
            PaymentVerdict::Verified { satoshis: 1000 },
            "{name}"
        );
        assert_eq!(txid.unwrap(), subject, "{name}");
    }
}
