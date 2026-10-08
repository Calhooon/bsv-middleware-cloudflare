//! BRC-29 payment-verification conformance: runs every case of
//! `conformance/brc29-payment-vectors.json` through the crate's public API.
//!
//! The vector file is PRODUCED here (`emit_brc29_payment_vectors`, fixed
//! synthetic inputs, the crate's own answer recorded as `crate_result`) and
//! pinned byte-for-byte, so it cannot drift from the verifier. It is meant to
//! be copied verbatim into other implementations; `conformance/README.md`
//! describes the schema. The runner below reads the file the way a second
//! implementation would: from JSON only, never from the emitter's tables.
//!
//! The core (`core/`, the `bsv-middleware-core` package) ships its own copy
//! under `core/conformance/` so its published tarball runs the vectors
//! without this repository; the emitter writes both copies and
//! `the_cores_copy_of_the_vectors_is_byte_identical` pins them equal, so
//! the root copy stays canonical.
//!
//! The file is a cross-repository agreement whose canonical copy is owned by
//! the stack review repository; this emitter reproduces that copy byte for
//! byte except the `producer` line and, on the one ruled case, the fields
//! that record this crate's own answer (`crate_result`, `note`). The
//! `rulings` list (`RULINGS`) carries the owner's ruling: date, case, word
//! and `by` verbatim, `why` in this crate's public wording.
//!
//! Regenerate (only when a case is added or the verifier's answer changes on
//! purpose): `cargo test --test conformance_brc29 -- --ignored emit`.

use std::cell::RefCell;

use bsv_middleware_cloudflare::{
    expected_brc29_locking_script, verify_brc29_payment, verify_brc29_payment_output,
    verify_brc29_payment_with_header_lookup, PaymentVerifyError,
};
use bsv_sdk::primitives::hash::hash160;
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::script::LockingScript;
use bsv_sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::{json, Value};

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/brc29-payment-vectors.json"
);
const PINNED: &str = include_str!("../conformance/brc29-payment-vectors.json");
/// The core's copy of the file (`core/conformance/`), shipped inside the
/// `bsv-middleware-core` package. It sits next to this manifest only in the
/// repository: the sub-package is not part of this crate's own tarball.
const CORE_COPY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/core/conformance/brc29-payment-vectors.json"
);

// ─── The runner (reads JSON only) ───────────────────────────────────

/// What a case's crate call returned, plus the heights the lookup was asked.
struct Outcome {
    result: Result<u64, PaymentVerifyError>,
    asked: Vec<u32>,
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string in {v}"))
}

fn u(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not an integer in {v}"))
}

/// The header lookup a case describes: `answer: "root"` answers
/// `merkle_root` at `height` (and nothing else), `answer: "error"` fails.
fn lookup_answer(lookup: &Value, height: u32) -> Result<String, String> {
    match s(lookup, "answer") {
        "root" if u(lookup, "height") == u64::from(height) => {
            Ok(s(lookup, "merkle_root").to_string())
        }
        "root" => Err(format!("no header at height {height}")),
        "error" => Err(s(lookup, "reason").to_string()),
        other => panic!("unknown lookup answer {other:?}"),
    }
}

/// Run one case: `stage: "config"` through `verify_brc29_payment` with the
/// case's `header_url` (the gate refuses before any network work), every
/// other stage through `verify_brc29_payment_with_header_lookup` with the
/// case's lookup.
async fn run_case(case: &Value) -> Outcome {
    let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
    let server_key = s(case, "server_private_key");
    let sender = s(case, "sender_identity_key");
    let prefix = s(case, "derivation_prefix");
    let suffix = s(case, "derivation_suffix");
    let index = u(case, "output_index") as usize;
    let required = u(case, "required_satoshis");
    let service = &case["header_service"];

    if s(case, "stage") == "config" {
        let result = verify_brc29_payment(
            server_key,
            sender,
            prefix,
            suffix,
            &tx,
            index,
            required,
            service["url"].as_str(),
        )
        .await;
        return Outcome {
            result,
            asked: Vec::new(),
        };
    }

    let asked = RefCell::new(Vec::new());
    let lookup = &service["lookup"];
    let result = verify_brc29_payment_with_header_lookup(
        server_key,
        sender,
        prefix,
        suffix,
        &tx,
        index,
        required,
        |height| {
            asked.borrow_mut().push(height);
            let answer = lookup_answer(lookup, height);
            async move { answer }
        },
    )
    .await;
    Outcome {
        result,
        asked: asked.into_inner(),
    }
}

/// The conformance word for an outcome. `Ok` is `Verified` and nothing
/// else: since 0.4.0 the crate serves on no other word. A root the lookup
/// could not answer is `Unverifiable`, an `Err` (fail-closed, the ruling of
/// 2026-10-08), carrying the output's satoshis as the file's `fields`.
fn word_of(outcome: &Outcome) -> (String, Value) {
    match &outcome.result {
        Ok(sats) => ("Verified".into(), json!({ "satoshis": sats })),
        Err(PaymentVerifyError::Unverifiable { satoshis, .. }) => {
            ("Unverifiable".into(), json!({ "satoshis": satoshis }))
        }
        Err(PaymentVerifyError::Underpaid { satoshis, required }) => (
            "Underpaid".into(),
            json!({ "paid": satoshis, "required": required }),
        ),
        Err(PaymentVerifyError::WrongScript { expected, actual }) => (
            "WrongScript".into(),
            json!({ "expected_script": expected, "actual_script": actual }),
        ),
        Err(PaymentVerifyError::NoHeaderService) => ("NoHeaderService".into(), json!({})),
        Err(PaymentVerifyError::RootMismatch { height, root }) => (
            "RootMismatch".into(),
            json!({ "height": height, "merkle_root": root }),
        ),
        Err(other) => (format!("Unmapped({other:?})"), json!({})),
    }
}

fn crate_result_of(result: &Result<u64, PaymentVerifyError>) -> String {
    match result {
        Ok(sats) => format!("Ok({sats})"),
        Err(e) => format!("Err({e:?})"),
    }
}

/// The checks every case gets that do not depend on the verdict: the
/// identity and script derivations, and that the listed outputs are the
/// outputs of the BEEF's subject transaction.
fn check_case_is_self_consistent(case: &Value, name: &str) {
    let server = PrivateKey::from_hex(s(case, "server_private_key")).unwrap();
    assert_eq!(
        server.public_key().to_hex(),
        s(case, "server_identity_key"),
        "{name}: server_identity_key"
    );
    assert_eq!(
        expected_brc29_locking_script(
            s(case, "server_private_key"),
            s(case, "sender_identity_key"),
            s(case, "derivation_prefix"),
            s(case, "derivation_suffix"),
        )
        .unwrap(),
        s(case, "expected_locking_script"),
        "{name}: expected_locking_script"
    );
    let txv = &case["transaction"];
    let tx = Transaction::from_beef(&hex::decode(s(txv, "beef_hex")).unwrap(), None).unwrap();
    assert_eq!(tx.id(), s(txv, "txid"), "{name}: txid");
    let listed = txv["outputs"].as_array().unwrap();
    assert_eq!(tx.outputs.len(), listed.len(), "{name}: output count");
    for (out, want) in tx.outputs.iter().zip(listed) {
        assert_eq!(out.satoshis.unwrap_or(0), u(want, "satoshis"), "{name}");
        assert_eq!(
            out.locking_script.to_hex(),
            s(want, "locking_script"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn every_brc29_vector_gives_its_word() {
    let doc: Value = serde_json::from_str(PINNED).unwrap();
    assert_eq!(doc["schema"], "brc29-payment-vectors/1");
    let cases = doc["cases"].as_array().unwrap();
    assert!(!cases.is_empty());

    let mut mismatches = Vec::new();
    for case in cases {
        let name = s(case, "name");
        check_case_is_self_consistent(case, name);

        let outcome = run_case(case).await;
        let (word, fields) = word_of(&outcome);
        let expected = &case["expected"];
        if word != s(expected, "word") || fields != expected["fields"] {
            mismatches.push(format!(
                "{name}: intended {} {}, crate gave {word} {fields}",
                expected["word"], expected["fields"]
            ));
        }
        // The outcome, not only the spelling: `Verified` is the one word
        // the 0.3 API answers `Ok`; every other word, `Unverifiable`
        // included, is an `Err` (refused).
        let serves = s(expected, "word") == "Verified";
        if outcome.result.is_ok() != serves {
            mismatches.push(format!(
                "{name}: {} must {}, crate gave {}",
                expected["word"],
                if serves { "serve (Ok)" } else { "refuse (Err)" },
                crate_result_of(&outcome.result)
            ));
        }
        let got = crate_result_of(&outcome.result);
        if got != s(case, "crate_result") {
            mismatches.push(format!(
                "{name}: crate_result recorded {}, now {got}",
                case["crate_result"]
            ));
        }
        if !case["requires_merkle_lookup"].as_bool().unwrap() {
            assert!(
                outcome.asked.is_empty() || word == "Verified",
                "{name}: a refusal that does not need a lookup must not ask for one"
            );
        }

        // A pure implementation (no header service) runs the script + amount
        // check alone on every `stage: "output"` case and must get the same
        // word.
        if s(case, "stage") == "output" {
            let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
            let pure = verify_brc29_payment_output(
                s(case, "server_private_key"),
                s(case, "sender_identity_key"),
                s(case, "derivation_prefix"),
                s(case, "derivation_suffix"),
                &tx,
                u(case, "output_index") as usize,
                u(case, "required_satoshis"),
            );
            let (pure_word, pure_fields) = word_of(&Outcome {
                result: pure,
                asked: Vec::new(),
            });
            if pure_word != word || pure_fields != fields {
                mismatches.push(format!(
                    "{name}: output-only check gave {pure_word} {pure_fields}, full gave {word} {fields}"
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "conformance mismatches:\n{}",
        mismatches.join("\n")
    );
}

/// The ruling the file records, as the owner's `rulings` list: the
/// lookup-error case expects `Unverifiable`, the case agrees with its
/// ruling, and the list is the verbatim text this emitter carries.
#[test]
fn the_lookup_error_case_is_ruled_unverifiable() {
    let doc: Value = serde_json::from_str(PINNED).unwrap();
    let rulings = doc["rulings"].as_array().expect("a rulings list");
    assert_eq!(rulings.len(), 1);
    let ruling = &rulings[0];
    assert_eq!(s(ruling, "case"), "spv-lookup-error");
    assert_eq!(s(ruling, "word"), "Unverifiable");
    assert_eq!(s(ruling, "date"), "2026-10-08");
    for key in ["date", "case", "word", "by", "why"] {
        assert!(ruling[key].is_string(), "a ruling carries {key}");
    }
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| s(c, "name") == "spv-lookup-error")
        .expect("the ruled case");
    assert_eq!(s(&case["expected"], "word"), "Unverifiable");
    assert!(
        s(case, "crate_result").starts_with("Err(Unverifiable"),
        "{}",
        case["crate_result"]
    );
    let words = doc["words"].as_object().unwrap();
    assert_eq!(words.len(), 6, "six words in the glossary");
}

#[tokio::test]
async fn brc29_vectors_are_the_pinned_bytes() {
    assert!(
        build_vectors().await == PINNED,
        "conformance/brc29-payment-vectors.json is stale or hand-edited. It is a CROSS-REPO \
         agreement: regenerate with `cargo test --test conformance_brc29 -- --ignored emit`, \
         review the diff, and copy the file to every implementation that runs it."
    );
}

/// The core's copy is the root copy, byte for byte. Outside the repository
/// (this crate's own packaged tarball) the core sub-package is not shipped
/// and there is no second copy to compare; inside it, a missing copy is a
/// defect.
#[test]
fn the_cores_copy_of_the_vectors_is_byte_identical() {
    match std::fs::read_to_string(CORE_COPY_PATH) {
        Ok(core_copy) => assert!(
            core_copy == PINNED,
            "core/conformance/brc29-payment-vectors.json differs from the root copy. The root copy \
             is canonical: regenerate with `cargo test --test conformance_brc29 -- --ignored emit` \
             (it writes both copies)."
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let core_manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/core/Cargo.toml");
            assert!(
                !std::path::Path::new(core_manifest).exists(),
                "core/ is present but its conformance copy is missing: {e}"
            );
            eprintln!("core/ is not part of this package; no second copy to compare");
        }
        Err(e) => panic!("cannot read {CORE_COPY_PATH}: {e}"),
    }
}

/// Writes `conformance/brc29-payment-vectors.json` and the core's copy
/// (`core/conformance/`) on purpose.
#[tokio::test]
#[ignore = "writes conformance/brc29-payment-vectors.json (both copies) on purpose"]
async fn emit_brc29_payment_vectors() {
    let bytes = build_vectors().await;
    for path in [VECTORS_PATH, CORE_COPY_PATH] {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
        std::fs::write(path, &bytes).unwrap();
    }
}

// ─── The producer (fixed synthetic inputs) ──────────────────────────

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const OTHER_SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
/// base64("brc29-conformance-prefix")
const PREFIX: &str = "YnJjMjktY29uZm9ybWFuY2UtcHJlZml4";
/// base64("brc29-conformance-suffix")
const SUFFIX: &str = "YnJjMjktY29uZm9ybWFuY2Utc3VmZml4";
/// base64("brc29-conformance-stale-prefix"), a prefix from an older quote.
const STALE_PREFIX: &str = "YnJjMjktY29uZm9ybWFuY2Utc3RhbGUtcHJlZml4";
/// RFC 2606 reserved name: never a real service.
const HEADERS_URL: &str = "https://headers.example";
const PROOF_HEIGHT: u32 = 850_000;
const PRICE: u64 = 1000;

fn identity(private_hex: &str) -> String {
    PrivateKey::from_hex(private_hex)
        .unwrap()
        .public_key()
        .to_hex()
}

fn p2pkh_of_pubkey(pubkey_hex: &str) -> String {
    format!(
        "76a914{}88ac",
        hex::encode(hash160(&hex::decode(pubkey_hex).unwrap()))
    )
}

fn script(server: &str, sender_identity: &str, prefix: &str) -> String {
    expected_brc29_locking_script(server, sender_identity, prefix, SUFFIX).unwrap()
}

/// A BEEF holding ONE transaction with `outputs`, proven by a one-leaf BUMP
/// at `PROOF_HEIGHT` (a block of one transaction: the merkle root IS the
/// txid). Returns the bytes and the txid.
fn proven_beef(outputs: &[(String, u64)]) -> (Vec<u8>, String) {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput {
        source_txid: Some("11".repeat(32)),
        source_output_index: 0,
        ..Default::default()
    })
    .unwrap();
    for (script_hex, sats) in outputs {
        tx.add_output(TransactionOutput {
            satoshis: Some(*sats),
            locking_script: LockingScript::from_hex(script_hex).unwrap(),
            change: false,
        })
        .unwrap();
    }
    let txid = tx.id();
    let bump = MerklePath::new(
        PROOF_HEIGHT,
        vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]],
    )
    .unwrap();
    let mut beef = Beef::new();
    beef.merge_bump(bump);
    beef.merge_transaction(tx);
    (beef.to_binary(), txid)
}

#[derive(Clone, Copy)]
enum Lookup {
    /// The service answers the proof's own root (upper-cased if `true`).
    ProofRoot(bool),
    /// The service answers a different root at the proof's height.
    OtherRoot,
    /// The service cannot answer.
    Error,
}

struct CaseDef {
    name: &'static str,
    description: &'static str,
    stage: &'static str,
    sender_private_key: &'static str,
    /// `None`: the sender's own identity; `Some(key)` overrides it (pay-yourself).
    sender_identity_override: Option<&'static str>,
    outputs: Vec<(String, u64)>,
    output_index: u64,
    header_url: Option<&'static str>,
    lookup: Lookup,
    word: &'static str,
    note: &'static str,
}

fn case_defs() -> Vec<CaseDef> {
    let sender = identity(SENDER_KEY);
    let ours = script(SERVER_KEY, &sender, PREFIX);
    let base = |name, description, outputs: Vec<(String, u64)>, word, note| CaseDef {
        name,
        description,
        stage: "output",
        sender_private_key: SENDER_KEY,
        sender_identity_override: None,
        outputs,
        output_index: 0,
        header_url: Some(HEADERS_URL),
        lookup: Lookup::ProofRoot(false),
        word,
        note,
    };

    let mut defs = vec![
        base(
            "exact-amount",
            "Output 0 pays the derived key exactly the price.",
            vec![(ours.clone(), PRICE)],
            "Verified",
            "",
        ),
        base(
            "one-sat-under",
            "Output 0 pays the derived key one satoshi below the price.",
            vec![(ours.clone(), PRICE - 1)],
            "Underpaid",
            "",
        ),
        base(
            "one-sat-over",
            "Output 0 pays the derived key one satoshi above the price; overpayment is accepted and the paid amount reported.",
            vec![(ours.clone(), PRICE + 1)],
            "Verified",
            "",
        ),
        base(
            "zero-sat-output",
            "Output 0 carries the derived key's script but zero satoshis.",
            vec![(ours.clone(), 0)],
            "Underpaid",
            "",
        ),
        base(
            "wrong-script-another-server",
            "Output 0 pays the key a DIFFERENT server would derive for the same sender, prefix and suffix (one payment replayed across servers).",
            vec![(script(OTHER_SERVER_KEY, &sender, PREFIX), 5000)],
            "WrongScript",
            "",
        ),
        base(
            "wrong-script-stale-prefix",
            "Output 0 pays this server's key for an older quote's derivation prefix (a paid transaction replayed against a fresh quote).",
            vec![(script(SERVER_KEY, &sender, STALE_PREFIX), 5000)],
            "WrongScript",
            "",
        ),
        base(
            "wrong-script-pays-sender",
            "Output 0 pays the sender's own identity key (P2PKH of sender_identity_key): the client keeps the funds.",
            vec![(p2pkh_of_pubkey(&sender), 5000)],
            "WrongScript",
            "",
        ),
        base(
            "first-output-underpays-second-would-pay",
            "Reference rule: the payment is output 0 only. Output 0 pays the derived key one sat under the price, output 1 pays it in full; refused.",
            vec![(ours.clone(), PRICE - 1), (ours.clone(), PRICE)],
            "Underpaid",
            "The express payment middleware internalizes outputIndex 0 only; an implementation must not search later outputs for one that pays.",
        ),
        base(
            "first-output-is-change-second-would-pay",
            "Reference rule: output 0 is change back to the sender, output 1 pays the derived key in full; refused.",
            vec![(p2pkh_of_pubkey(&sender), 5000), (ours.clone(), PRICE)],
            "WrongScript",
            "Same rule as first-output-underpays-second-would-pay, script side.",
        ),
    ];

    // Pay-yourself: the sender IS the server (same identity key).
    let server_id = identity(SERVER_KEY);
    defs.push(CaseDef {
        sender_private_key: SERVER_KEY,
        sender_identity_override: Some(SERVER_KEY),
        ..base(
            "pay-yourself-sender-is-server",
            "The sender identity key is the server's own identity key and output 0 pays the key derived for that (server, server, prefix, suffix) tuple.",
            vec![(script(SERVER_KEY, &server_id, PREFIX), PRICE)],
            "Verified",
            "The verifier does not refuse sender == server: BRC-42 with the counterparty set to one's own key is well defined, the output pays a key the server can spend, so it is a real payment. Refusing self-payment is a policy above the verifier.",
        )
    });

    // No header service: the gate refuses before any other check, for a
    // payment that would otherwise verify.
    for (name, url, what) in [
        ("no-header-service-none", None, "header_url absent (null)."),
        ("no-header-service-blank", Some(""), "header_url is the empty string."),
        (
            "no-header-service-placeholder",
            Some("https://chaintracks.invalid"),
            "header_url is the reserved .invalid placeholder.",
        ),
        (
            "no-header-service-trailing-dot",
            Some("https://chaintracks.invalid."),
            "The placeholder as a trailing-dot FQDN.",
        ),
        (
            "no-header-service-percent-encoded",
            Some("https://chaintracks%2Einvalid"),
            "The placeholder with a percent-encoded dot (a URL parser would decode it).",
        ),
        (
            "no-header-service-backslash-userinfo",
            Some("https://real.example\\@chaintracks.invalid"),
            "A backslash before userinfo: a WHATWG parser reads the host as real.example, a naive split as chaintracks.invalid. Refused rather than guessed.",
        ),
    ] {
        defs.push(CaseDef {
            stage: "config",
            header_url: url,
            ..base(
                name,
                what,
                vec![(ours.clone(), PRICE)],
                "NoHeaderService",
                "Fail-closed: a deployment misconfiguration, refused before the script, amount or proof is looked at.",
            )
        });
    }

    // SPV: the payment is correct; only the header service's answer varies.
    for (name, lookup, word, what, note) in [
        (
            "spv-root-match",
            Lookup::ProofRoot(false),
            "Verified",
            "The header service answers the proof's merkle root at the proof's height.",
            "",
        ),
        (
            "spv-root-match-uppercase",
            Lookup::ProofRoot(true),
            "Verified",
            "The header service answers the proof's root in upper-case hex.",
            "Roots compare case-insensitively.",
        ),
        (
            "spv-root-mismatch",
            Lookup::OtherRoot,
            "RootMismatch",
            "The header service answers a DIFFERENT merkle root at the proof's height.",
            "Fail-closed: a mismatch is a fraud signal, not an outage.",
        ),
        (
            "spv-lookup-error",
            Lookup::Error,
            "Unverifiable",
            "The header service cannot answer (HTTP 503).",
            "Fail-closed (ruled 2026-10-08): the root was NOT checked, so the crate refuses with Err(Unverifiable) carrying the output's satoshis and the reason; the host answers a 5xx and keeps the quote for a retry. 0.3.x accepted this case with a logged warning.",
        ),
    ] {
        defs.push(CaseDef {
            stage: "spv",
            lookup,
            ..base(name, what, vec![(ours.clone(), PRICE)], word, note)
        });
    }
    defs
}

fn expected_fields(word: &str, def: &CaseDef, expected_script: &str, root: &str) -> Value {
    let out = &def.outputs[def.output_index as usize];
    match word {
        "Verified" | "Unverifiable" => json!({ "satoshis": out.1 }),
        "Underpaid" => json!({ "paid": out.1, "required": PRICE }),
        "WrongScript" => json!({ "expected_script": expected_script, "actual_script": out.0 }),
        "NoHeaderService" => json!({}),
        "RootMismatch" => json!({ "height": PROOF_HEIGHT, "merkle_root": root }),
        other => panic!("unknown word {other}"),
    }
}

async fn build_vectors() -> String {
    let mut cases = Vec::new();
    for def in case_defs() {
        let sender_identity = identity(def.sender_identity_override.unwrap_or(SENDER_KEY));
        let expected_script = script(SERVER_KEY, &sender_identity, PREFIX);
        let (beef, txid) = proven_beef(&def.outputs);
        let lookup = match (def.stage, def.lookup) {
            ("config", _) => Value::Null,
            (_, Lookup::ProofRoot(upper)) => json!({
                "answer": "root",
                "height": PROOF_HEIGHT,
                "merkle_root": if upper { txid.to_ascii_uppercase() } else { txid.clone() },
            }),
            (_, Lookup::OtherRoot) => json!({
                "answer": "root",
                "height": PROOF_HEIGHT,
                "merkle_root": "00".repeat(32),
            }),
            (_, Lookup::Error) => json!({
                "answer": "error",
                "reason": format!("header service HTTP 503 at height {PROOF_HEIGHT}"),
            }),
        };
        let mut case = json!({
            "name": def.name,
            "description": def.description,
            "stage": def.stage,
            "requires_merkle_lookup": def.stage == "spv",
            "server_private_key": SERVER_KEY,
            "server_identity_key": identity(SERVER_KEY),
            "sender_private_key": def.sender_private_key,
            "sender_identity_key": sender_identity,
            "derivation_prefix": PREFIX,
            "derivation_suffix": SUFFIX,
            "expected_locking_script": expected_script,
            "transaction": {
                "beef_hex": hex::encode(&beef),
                "txid": txid,
                "proof": { "height": PROOF_HEIGHT, "merkle_root": txid },
                "outputs": def.outputs.iter().map(|(script, sats)| json!({
                    "satoshis": sats,
                    "locking_script": script,
                })).collect::<Vec<_>>(),
            },
            "output_index": def.output_index,
            "required_satoshis": PRICE,
            "header_service": { "url": def.header_url, "lookup": lookup },
            "expected": {
                "word": def.word,
                "fields": expected_fields(def.word, &def, &expected_script, &txid),
            },
            "crate_result": "",
        });
        if !def.note.is_empty() {
            case["note"] = json!(def.note);
        }
        let outcome = run_case(&case).await;
        case["crate_result"] = json!(crate_result_of(&outcome.result));
        cases.push(case);
    }

    let doc = json!({
        "schema": "brc29-payment-vectors/1",
        "producer": format!("bsv-middleware-cloudflare {} tests/conformance_brc29.rs build_vectors (fixed synthetic inputs; regenerate, never retype)", env!("CARGO_PKG_VERSION")),
        "description": "BRC-29 payment verification before internalize: does output `output_index` of the payment transaction pay the server's BRC-29 derived key at least `required_satoshis`, and does its merkle proof tie to a block header? See conformance/README.md.",
        "words": {
            "Verified": "Accept. fields.satoshis = the output's satoshis.",
            "AcceptedUnverified": "Accept, but the header service could not answer so the merkle root was NOT checked (fail-open). fields.satoshis.",
            "Underpaid": "Refuse: the output pays the derived key less than required. fields.paid, fields.required.",
            "WrongScript": "Refuse: the output's locking script is not the expected one. fields.expected_script, fields.actual_script.",
            "NoHeaderService": "Refuse before any other check: no usable header service is configured (fail-closed misconfiguration).",
            "RootMismatch": "Refuse: the header at the proof's height carries a different merkle root (fail-closed fraud signal). fields.height, fields.merkle_root (the proof's root)."
        },
        "derivation": {
            "brc": "BRC-29 over BRC-42/BRC-43",
            "protocol_id": [2, "3241645161d8"],
            "key_id": "<derivation_prefix> <derivation_suffix>",
            "server_side": "child public key for (server_private_key, counterparty = sender_identity_key, for_self = true)",
            "sender_side": "child public key for (sender_private_key, counterparty = server_identity_key, for_self = false); equal by BRC-42",
            "locking_script": "P2PKH: 76a914 <hash160(compressed child pubkey)> 88ac"
        },
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    // The owner's rulings, appended after the sorted keys exactly as the
    // canonical copy carries them (its own key order, not serde's).
    let body = text
        .strip_suffix("\n}")
        .expect("a pretty-printed object ends with a newline and a brace");
    text = format!("{body},\n{RULINGS}\n}}\n");
    text
}

/// The owner's `rulings` list, verbatim: date, case, word, by, why.
const RULINGS: &str = r#"  "rulings": [
    {
      "date": "2026-10-08",
      "case": "spv-lookup-error",
      "word": "Unverifiable",
      "by": "the owner",
      "why": "fail closed on a header lookup error: a merkle root that was not checked against a block header is not evidence, so the verifier refuses instead of accepting with a warning; the Cloudflare crate fails closed from 0.3.9 and 0.4.0"
    }
  ]"#;
