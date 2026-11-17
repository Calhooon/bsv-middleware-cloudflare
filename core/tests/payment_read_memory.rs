//! The payment read's memory follows the body.
//!
//! The adapter's payment door reads the payer's BEEF through two core
//! functions, in this order: [`verify_payment_output`], then
//! [`payment_subject_txid`]. This test builds payments the size of a 128 KiB
//! `x-bsv-payment` header whose subject spends one parent through many inputs,
//! runs both functions under a counting allocator, and holds the peak heap of
//! each call to a fixed multiple of the BEEF's size.
//!
//! The shapes:
//! - a wide parent (many outputs), unproven, spent by many inputs of the
//!   subject (two widths);
//! - the same parent proven by a BUMP;
//! - a parent of one output proven by a wide BUMP, spent by many inputs.
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
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
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
const CEILING_PER_BODY_BYTE: usize = 48;

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

/// The most inputs whose payment still fits the header.
fn fill(outputs: usize, bump_leaves: usize, pay: &[u8]) -> (Vec<u8>, String) {
    let budget = beef_budget();
    let (mut lo, mut hi) = (1usize, 8 * budget);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if payment(outputs, mid, bump_leaves, pay).0.len() <= budget {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    payment(outputs, lo, bump_leaves, pay)
}

/// The heap a call holds at its peak, above what was live when it began.
fn peak_of<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let answer = call();
    (answer, PEAK.load(Ordering::SeqCst) - base)
}

/// The payment read's memory follows the body: on every shape, each of the
/// door's two reads peaks within a fixed multiple of the BEEF's size, and
/// reads the subject's verdict and txid.
#[test]
fn the_payment_reads_memory_follows_the_body() {
    let sender = PrivateKey::from_hex(SENDER_KEY)
        .unwrap()
        .public_key()
        .to_hex();
    let pay =
        hex::decode(expected_locking_script(SERVER_KEY, &sender, PREFIX, SUFFIX).unwrap()).unwrap();
    let shapes = [
        ("wide unproven parent", 6144, 0),
        ("unproven parent", 768, 0),
        ("wide proven parent", 6144, 2),
        ("proven parent, wide BUMP", 1, 1024),
    ];
    for (name, outputs, bump_leaves) in shapes {
        let (body, subject) = fill(outputs, bump_leaves, &pay);
        assert!(body.len() <= beef_budget() && body.len() > beef_budget() * 9 / 10);
        let ceiling = CEILING_PER_BODY_BYTE * body.len();

        let (verdict, verify_peak) =
            peak_of(|| verify_payment_output(SERVER_KEY, &sender, PREFIX, SUFFIX, &body, 0, 1000));
        let (txid, subject_peak) = peak_of(|| payment_subject_txid(&body));
        println!(
            "{name}: body {} B, output check peak {verify_peak} B ({:.1}x), \
             subject txid peak {subject_peak} B ({:.1}x)",
            body.len(),
            verify_peak as f64 / body.len() as f64,
            subject_peak as f64 / body.len() as f64,
        );
        assert!(
            verify_peak <= ceiling,
            "{name}: the output check peaked at {verify_peak} B on a {} B body",
            body.len()
        );
        assert!(
            subject_peak <= ceiling,
            "{name}: the subject read peaked at {subject_peak} B on a {} B body",
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
