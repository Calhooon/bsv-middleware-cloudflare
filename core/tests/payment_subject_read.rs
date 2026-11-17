//! The payment check reads the same subject as the reference read kept for
//! comparison.
//!
//! `verify_payment_output` and `payment_subject_txid` read the payment's
//! subject alone (`Transaction::from_beef_subject`). The reference read kept
//! for comparison is `Transaction::from_beef`, which also links the subject's
//! input ancestry. Both pick the subject the same way: the Atomic BEEF's
//! named transaction, otherwise the last entry. This differential pin runs the
//! two reads side by side (`support/subject_read.rs`) over the 22 conformance
//! vectors, the shapes the crate's own fixtures build, and generated BEEFs of
//! every shape the selection can meet: Atomic BEEF naming the tip, an ancestor
//! or an absent txid; BEEF V1 and V2 whose last entry is the tip or an
//! ancestor; two tips; txid-only entries; a duplicated entry; and each of
//! those truncated or with one byte changed. Wherever the reference read
//! reads a subject, the crate reads the same txid and the same verdict;
//! wherever both refuse, with the same reason, word for word.
//! `work_budget.rs` runs the same comparison over its fixtures.

#[path = "support/subject_read.rs"]
mod subject_read;

use bsv_middleware_core::expected_locking_script;
use bsv_sdk::primitives::{PrivateKey, Writer};
use bsv_sdk::script::{LockingScript, UnlockingScript};
use bsv_sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;
use subject_read::{compare, Tally, Terms};

const VECTORS: &str = include_str!("../conformance/brc29-payment-vectors.json");

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const PREFIX: &str = "prefix";
const SUFFIX: &str = "suffix";
const REQUIRED: u64 = 1000;

/// Generated cases; each also runs truncated and with one byte changed.
const GENERATED: usize = 600;

const BEEF_V1: u32 = 0xefbe_0001;
const BEEF_V2: u32 = 0xefbe_0002;
const ATOMIC: u32 = 0x0101_0101;

fn sender() -> String {
    PrivateKey::from_hex(SENDER_KEY)
        .unwrap()
        .public_key()
        .to_hex()
}

fn our_script() -> Vec<u8> {
    hex::decode(expected_locking_script(SERVER_KEY, &sender(), PREFIX, SUFFIX).unwrap()).unwrap()
}

/// xorshift64*: the cases are the same on every run.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn outside_txid(i: u64) -> String {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&i.to_le_bytes());
    b[31] = 0x11;
    hex::encode(b)
}

/// A transaction spending `spends` (txid, output) with empty unlocking
/// scripts, paying `outputs`.
fn tx(spends: &[(String, u32)], outputs: &[(u64, Vec<u8>)]) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in spends {
        let mut input = TransactionInput::new(txid.clone(), *vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs.push(input);
    }
    for (satoshis, script) in outputs {
        tx.add_output(TransactionOutput::new(
            *satoshis,
            LockingScript::from_binary(script).unwrap(),
        ))
        .unwrap();
    }
    tx
}

/// A one-leaf BUMP: a block of one transaction, whose root is its txid.
fn one_leaf_bump(txid: &str, height: u32) -> MerklePath {
    MerklePath::new(
        height,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// One BEEF entry as written, in the order given.
enum Entry {
    Raw { tx: Vec<u8>, bump: Option<u64> },
    TxidOnly(String),
}

/// A BEEF written byte for byte: the entries in the order given (no sort),
/// with an Atomic header naming `atomic` when set. V1 cannot carry a
/// txid-only entry; it writes such an entry's transaction instead.
fn write_beef(
    version: u32,
    atomic: Option<&str>,
    bumps: &[MerklePath],
    entries: &[Entry],
) -> Vec<u8> {
    let mut w = Writer::new();
    if let Some(txid) = atomic {
        w.write_u32_le(ATOMIC);
        let mut b = hex::decode(txid).unwrap();
        b.reverse();
        w.write_bytes(&b);
    }
    w.write_u32_le(version);
    w.write_var_int(bumps.len() as u64);
    for bump in bumps {
        w.write_bytes(&bump.to_binary());
    }
    w.write_var_int(entries.len() as u64);
    for entry in entries {
        match (version, entry) {
            (BEEF_V2, Entry::Raw { tx, bump: None }) => {
                w.write_u8(0).write_bytes(tx);
            }
            (BEEF_V2, Entry::Raw { tx, bump: Some(i) }) => {
                w.write_u8(1).write_var_int(*i).write_bytes(tx);
            }
            (BEEF_V2, Entry::TxidOnly(txid)) => {
                let mut b = hex::decode(txid).unwrap();
                b.reverse();
                w.write_u8(2).write_bytes(&b);
            }
            (_, Entry::Raw { tx, bump }) => {
                w.write_bytes(tx);
                match bump {
                    Some(i) => {
                        w.write_u8(1).write_var_int(*i);
                    }
                    None => {
                        w.write_u8(0);
                    }
                }
            }
            (_, Entry::TxidOnly(_)) => unreachable!("V1 entries are raw"),
        }
    }
    w.into_bytes()
}

/// One generated payment: a proven or unproven root, a chain of hops (each
/// spending one or several outputs of the hop before, sometimes the same
/// parent through many inputs), a tip paying a few outputs, and sometimes a
/// second tip. Written in one of the selection's orders and wrappers.
fn generated(rng: &mut Rng, case: u64) -> (Vec<u8>, usize, u64) {
    let ours = our_script();
    let other = vec![0x76, 0xa9, 0x14, 0x22, 0x88, 0xac];
    let proven_root = rng.chance(60);
    let hops = rng.below(4);
    let width = 1 + rng.below(4);

    let root = tx(
        &[(outside_txid(case), rng.below(3) as u32)],
        &(0..width)
            .map(|i| (5_000 + i as u64, vec![0x51]))
            .collect::<Vec<_>>(),
    );
    let mut chain = vec![root];
    for hop in 0..hops {
        let prev = chain.last().unwrap();
        let n_out = prev.outputs.len();
        let mut spends: Vec<(String, u32)> = (0..n_out).map(|i| (prev.id(), i as u32)).collect();
        if rng.chance(30) {
            // The same parent output spent by several inputs.
            for _ in 0..rng.below(5) {
                spends.push((prev.id(), rng.below(n_out) as u32));
            }
        }
        if rng.chance(20) {
            // An input from outside the BEEF.
            spends.push((outside_txid(case * 100 + hop as u64), 0));
        }
        let outs = (0..1 + rng.below(3))
            .map(|i| (4_000 - hop as u64 * 10 - i as u64, vec![0x51]))
            .collect::<Vec<_>>();
        chain.push(tx(&spends, &outs));
    }
    let parent = chain.last().unwrap().clone();
    let pay = |rng: &mut Rng| -> Vec<(u64, Vec<u8>)> {
        (0..1 + rng.below(3))
            .map(|_| {
                let script = if rng.chance(70) {
                    ours.clone()
                } else {
                    other.clone()
                };
                let sats = [0, 1, REQUIRED - 1, REQUIRED, REQUIRED + 1, 5_000][rng.below(6)];
                (sats, script)
            })
            .collect()
    };
    let tip_spends: Vec<(String, u32)> = (0..parent.outputs.len())
        .map(|i| (parent.id(), i as u32))
        .collect();
    let tip = tx(&tip_spends, &pay(rng));
    let second_tip = rng.chance(25).then(|| tx(&[(parent.id(), 0)], &pay(rng)));

    let height = 800_000 + (case % 1000) as u32;
    let mut bumps = Vec::new();
    if proven_root {
        bumps.push(one_leaf_bump(&chain[0].id(), height));
    }
    let mut txs: Vec<Transaction> = chain.clone();
    txs.push(tip.clone());
    if let Some(second) = &second_tip {
        txs.push(second.clone());
    }
    let ids: Vec<String> = txs.iter().map(Transaction::id).collect();

    // The order: dependency order (the tip, or the second tip, last); an
    // ancestor last; or shuffled.
    let mut order: Vec<usize> = (0..txs.len()).collect();
    match rng.below(4) {
        0 | 1 => {}
        2 => {
            let moved = order.remove(rng.below(chain.len()));
            order.push(moved);
        }
        _ => {
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i + 1));
            }
        }
    }
    let version = if rng.chance(50) { BEEF_V1 } else { BEEF_V2 };
    let mut entries: Vec<Entry> = order
        .iter()
        .map(|&i| Entry::Raw {
            tx: txs[i].to_binary(),
            bump: (i == 0 && proven_root).then_some(0),
        })
        .collect();
    if version == BEEF_V2 && rng.chance(25) {
        // A txid-only entry: the proven root, the tip, or any entry.
        let pick = match rng.below(3) {
            0 => order.iter().position(|&i| i == 0).unwrap(),
            1 => order.iter().position(|&i| i == chain.len()).unwrap(),
            _ => rng.below(entries.len()),
        };
        entries[pick] = Entry::TxidOnly(ids[order[pick]].clone());
    }
    if rng.chance(5) {
        // An entry written twice.
        let i = rng.below(txs.len());
        entries.push(Entry::Raw {
            tx: txs[i].to_binary(),
            bump: None,
        });
    }
    let atomic = match rng.below(6) {
        0 | 1 => Some(ids[chain.len()].clone()),
        2 => Some(ids[rng.below(ids.len())].clone()),
        3 => Some(outside_txid(case + 7_000_000)),
        _ => None,
    };
    let bytes = write_beef(version, atomic.as_deref(), &bumps, &entries);
    let output_index = rng.below(4);
    let required = [REQUIRED, REQUIRED + 1, 1][rng.below(3)];
    (bytes, output_index, required)
}

/// A shared parent of `outputs` outputs of `script_len`-byte scripts spent
/// by `inputs` inputs of the subject.
fn shared_parent(outputs: usize, script_len: usize, inputs: usize, proven: bool) -> Vec<u8> {
    let parent = tx(
        &[(outside_txid(9), 0)],
        &vec![(1, vec![0x51; script_len]); outputs],
    );
    let spends: Vec<(String, u32)> = (0..inputs)
        .map(|i| (parent.id(), (i % outputs) as u32))
        .collect();
    let subject = tx(&spends, &[(REQUIRED, our_script())]);
    let mut beef = Beef::new();
    let bump = proven.then(|| beef.merge_bump(one_leaf_bump(&parent.id(), 900_000)));
    beef.merge_raw_tx(parent.to_binary(), bump);
    beef.merge_raw_tx(subject.to_binary(), None);
    beef.to_binary()
}

/// The shapes the crate's own tests build (`brc29::test_support`, the
/// payment-verify tests, the adapter's copies of both, `stream_memory.rs`
/// at a small size, the refund's Atomic BEEF of one transaction).
fn crate_fixtures() -> Vec<(String, Vec<u8>)> {
    let ours = our_script();
    let mut out = Vec::new();
    // beef_with_unproven_payment / beef_with_proven_payment.
    let payment = tx(&[("11".repeat(32), 0)], &[(REQUIRED, ours.clone())]);
    let mut beef = Beef::new();
    beef.merge_transaction(payment.clone());
    out.push(("unproven payment".into(), beef.to_binary()));
    let mut beef = Beef::new();
    beef.merge_bump(one_leaf_bump(&payment.id(), 850_000));
    beef.merge_transaction(payment.clone());
    out.push(("proven payment".into(), beef.to_binary()));
    out.push((
        "atomic payment of one transaction".into(),
        beef.to_binary_atomic(&payment.id()).unwrap(),
    ));
    // beef_of: a rootless proven parent, then the subject (and Atomic forms).
    let rootless = tx(&[], &[(1, vec![0x52])]);
    let first = tx(&[(rootless.id(), 0)], &[(REQUIRED, vec![0x51])]);
    let last = tx(&[(first.id(), 0)], &[(REQUIRED, ours.clone())]);
    let mut beef = Beef::new();
    let bump = beef.merge_bump(one_leaf_bump(&first.id(), 850_000));
    beef.merge_raw_tx(first.to_binary(), Some(bump));
    beef.merge_raw_tx(last.to_binary(), None);
    out.push(("plain parent and subject".into(), beef.to_binary()));
    out.push((
        "atomic naming the subject".into(),
        beef.to_binary_atomic(&last.id()).unwrap(),
    ));
    out.push((
        "atomic naming the parent".into(),
        beef.to_binary_atomic(&first.id()).unwrap(),
    ));
    let mut unproven = Beef::new();
    unproven.merge_raw_tx(first.to_binary(), None);
    unproven.merge_raw_tx(last.to_binary(), None);
    out.push(("unproven parent and subject".into(), unproven.to_binary()));
    // A forged stranger proven by its own BUMP, the subject last.
    let forged = tx(&[("11".repeat(32), 0)], &[(5, vec![0x53])]);
    let mut beef = Beef::new();
    beef.merge_bump(one_leaf_bump(&payment.id(), 850_000));
    beef.merge_bump(one_leaf_bump(&forged.id(), 850_000));
    beef.merge_raw_tx(forged.to_binary(), Some(1));
    beef.merge_raw_tx(payment.to_binary(), Some(0));
    out.push(("forged stranger, then the subject".into(), beef.to_binary()));
    out.push(("empty BEEF".into(), Beef::new().to_binary()));
    out.push(("no bytes".into(), Vec::new()));
    // stream_memory.rs: a proven parent under a chain of hops, written raw.
    let parent = tx(&[(outside_txid(0xaa), 0)], &[(1000, vec![0x75, 0x51])]);
    let mut previous = parent.id();
    let mut entries = vec![Entry::Raw {
        tx: parent.to_binary(),
        bump: Some(0),
    }];
    for hop in 0..16 {
        let lock = if hop == 15 {
            ours.clone()
        } else {
            vec![0x75, 0x51]
        };
        let mut t = tx(&[(previous.clone(), 0)], &[(1000, lock)]);
        t.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&[7u8; 1024]).unwrap());
        previous = t.id();
        entries.push(Entry::Raw {
            tx: t.to_binary(),
            bump: None,
        });
    }
    out.push((
        "stream_memory's chain of hops, 16 x 1 KiB".into(),
        write_beef(
            BEEF_V2,
            None,
            &[one_leaf_bump(&parent.id(), 800_000)],
            &entries,
        ),
    ));
    out
}

fn vector_terms(case: &Value) -> (Vec<u8>, String, String, String, String, usize, u64) {
    let s = |k: &str| case[k].as_str().unwrap().to_string();
    (
        hex::decode(case["transaction"]["beef_hex"].as_str().unwrap()).unwrap(),
        s("server_private_key"),
        s("sender_identity_key"),
        s("derivation_prefix"),
        s("derivation_suffix"),
        case["output_index"].as_u64().unwrap() as usize,
        case["required_satoshis"].as_u64().unwrap(),
    )
}

/// The 22 vectors: the same txid and the same verdict as the reference read,
/// at the vector's own terms and at every output index the subject has.
#[test]
fn the_vectors_read_the_same_subject() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    let mut tally = Tally::default();
    let mut largest = 0;
    for case in cases {
        let (beef, server, sender, prefix, suffix, index, required) = vector_terms(case);
        largest = largest.max(beef.len());
        for output_index in [index, 0, 1, 2] {
            let terms = Terms {
                server_key: &server,
                sender: &sender,
                prefix: &prefix,
                suffix: &suffix,
                output_index,
                required,
            };
            tally.add(compare(case["name"].as_str().unwrap(), &terms, &beef));
        }
    }
    println!("vectors: {tally:?}, largest BEEF {largest} B");
    assert_eq!(tally.bodies, 88);
    assert_eq!(tally.link_bound_only, 0);
    assert!(tally.verified >= 8);
}

/// The shapes the crate's fixtures build: the same txid and verdict.
#[test]
fn the_crate_fixtures_read_the_same_subject() {
    let sender = sender();
    let mut tally = Tally::default();
    for (name, beef) in crate_fixtures() {
        for output_index in 0..3 {
            let terms = Terms {
                server_key: SERVER_KEY,
                sender: &sender,
                prefix: PREFIX,
                suffix: SUFFIX,
                output_index,
                required: REQUIRED,
            };
            tally.add(compare(&name, &terms, &beef));
        }
    }
    println!("crate fixtures: {tally:?}");
    assert_eq!(tally.link_bound_only, 0);
    assert!(tally.verified >= 5);
    assert!(tally.both_refused >= 6);
}

/// Generated BEEFs of every shape the subject selection meets, each also
/// truncated and with one byte changed: wherever the reference read reads a
/// subject, the same txid and verdict; wherever it refuses, the same refusal.
#[test]
fn generated_beefs_read_the_same_subject() {
    let sender = sender();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut tally = Tally::default();
    for case in 0..GENERATED as u64 {
        let (beef, output_index, required) = generated(&mut rng, case);
        let terms = Terms {
            server_key: SERVER_KEY,
            sender: &sender,
            prefix: PREFIX,
            suffix: SUFFIX,
            output_index,
            required,
        };
        tally.add(compare(&format!("case {case}"), &terms, &beef));
        let cut = rng.below(beef.len());
        tally.add(compare(
            &format!("case {case} cut at {cut}"),
            &terms,
            &beef[..cut],
        ));
        let mut changed = beef.clone();
        let at = rng.below(changed.len());
        changed[at] ^= 1 + rng.below(255) as u8;
        tally.add(compare(
            &format!("case {case} changed at {at}"),
            &terms,
            &changed,
        ));
    }
    println!("generated: {tally:?}");
    assert_eq!(tally.bodies, 3 * GENERATED);
    assert_eq!(tally.link_bound_only, 0);
    // Every class is met, the paying one most of all.
    assert!(tally.verified >= 100, "{tally:?}");
    assert!(tally.read_not_paying >= 100, "{tally:?}");
    assert!(tally.both_refused >= 300, "{tally:?}");
}

/// A shared parent spent by many inputs, light and heavy: the crate reads the
/// subject the bytes name and judges its named output, at every size.
#[test]
fn a_shared_parent_reads_the_same_subject() {
    let sender = sender();
    let terms = Terms {
        server_key: SERVER_KEY,
        sender: &sender,
        prefix: PREFIX,
        suffix: SUFFIX,
        output_index: 0,
        required: REQUIRED,
    };
    let mut tally = Tally::default();
    for (outputs, inputs) in [(1, 50), (20, 20), (64, 200)] {
        for proven in [false, true] {
            let beef = shared_parent(outputs, 0, inputs, proven);
            tally.add(compare(&format!("{outputs}x{inputs}"), &terms, &beef));
        }
    }
    assert_eq!(tally.verified, 6, "{tally:?}");
    for proven in [false, true] {
        let beef = shared_parent(1, 64 * 1024, 300, proven);
        tally.add(compare("one 64 KiB output x 300", &terms, &beef));
    }
    println!("shared parent: {tally:?}");
    assert_eq!(tally.link_bound_only, 2, "{tally:?}");
    for proven in [false, true] {
        let beef = shared_parent(1, 64 * 1024, 300, proven);
        assert_eq!(
            bsv_middleware_core::verify_payment_output(
                SERVER_KEY, &sender, PREFIX, SUFFIX, &beef, 0, REQUIRED
            )
            .unwrap(),
            bsv_middleware_core::PaymentVerdict::Verified { satoshis: REQUIRED }
        );
    }
}
