//! BRC-29 payment-verification conformance: every case of
//! `conformance/brc29-payment-vectors.json` through the core's
//! [`verify_brc29_payment`] with the header service replaced by a stub that
//! answers from the case's `header_service.lookup`.
//!
//! The file is owned and produced by the Workers adapter
//! (`tests/conformance_brc29.rs` at the repository root, which pins its
//! bytes at `conformance/brc29-payment-vectors.json` there). This crate
//! ships its own copy under `core/conformance/` so the published package
//! runs the file on its own; the adapter's runner asserts the two copies
//! are byte-identical, so the root copy stays the canonical one. This
//! runner reads it the way a second implementation does: from
//! JSON only, comparing `expected.word` and `expected.fields`. The six
//! words are the core's [`PaymentVerdict`]; `spv-lookup-error` expects
//! `Unverifiable`, a refusal (the ruling of 2026-10-08, recorded in the
//! file's `rulings`), and this runner checks that the core's answer there
//! is refused, not only spelled right. The file's `words` glossary still
//! carries the retired spelling `AcceptedUnverified` for that word; it is
//! the file owner's to rename. `config` cases carry the adapter's URL
//! gate's refusal: the core has no URL, so a refused configuration is
//! `None` service.

use std::cell::RefCell;

use bsv_middleware_core::brc29::{expected_locking_script, sender_locking_script};
use bsv_middleware_core::{
    verify_brc29_payment, verify_payment_output, LookupFn, MerkleRoot, NoService, PaymentFault,
    PaymentVerdict, ServiceError,
};
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::transaction::Transaction;
use serde_json::{json, Value};

/// This crate's copy of the vector file (inside the package, so the
/// published tarball runs it); the adapter pins it equal to the root copy.
const VECTORS: &str = include_str!("../conformance/brc29-payment-vectors.json");

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
fn lookup_answer(lookup: &Value, height: u32) -> Result<Option<MerkleRoot>, ServiceError> {
    match s(lookup, "answer") {
        "root" if u(lookup, "height") == u64::from(height) => {
            Ok(Some(MerkleRoot::new(s(lookup, "merkle_root"))))
        }
        "root" => Ok(None),
        "error" => Err(ServiceError::new(s(lookup, "reason"))),
        other => panic!("unknown lookup answer {other:?}"),
    }
}

/// The conformance word and fields for a core answer.
fn word_of(answer: &Result<PaymentVerdict, PaymentFault>) -> (String, Value) {
    match answer {
        Ok(PaymentVerdict::Verified { satoshis }) => {
            ("Verified".into(), json!({ "satoshis": satoshis }))
        }
        Ok(PaymentVerdict::Unverifiable { satoshis, .. }) => {
            ("Unverifiable".into(), json!({ "satoshis": satoshis }))
        }
        Ok(PaymentVerdict::Underpaid { paid, required }) => (
            "Underpaid".into(),
            json!({ "paid": paid, "required": required }),
        ),
        Ok(PaymentVerdict::WrongScript { expected, actual }) => (
            "WrongScript".into(),
            json!({ "expected_script": expected, "actual_script": actual }),
        ),
        Ok(PaymentVerdict::NoHeaderService) => ("NoHeaderService".into(), json!({})),
        Ok(PaymentVerdict::RootMismatch { height, root }) => (
            "RootMismatch".into(),
            json!({ "height": height, "merkle_root": root }),
        ),
        Err(fault) => (format!("Fault({fault:?})"), json!({})),
    }
}

/// Run one case: `stage: "config"` is a configuration the adapter's gate
/// refused, so the core sees no service; every other stage runs through a
/// stub service answering from the case's lookup. Returns the answer and
/// the heights the stub was asked for.
async fn run_case(case: &Value) -> (Result<PaymentVerdict, PaymentFault>, Vec<u32>) {
    let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
    let server_key = s(case, "server_private_key");
    let sender = s(case, "sender_identity_key");
    let prefix = s(case, "derivation_prefix");
    let suffix = s(case, "derivation_suffix");
    let index = u(case, "output_index") as usize;
    let required = u(case, "required_satoshis");

    if s(case, "stage") == "config" {
        let answer = verify_brc29_payment(
            server_key,
            sender,
            prefix,
            suffix,
            &tx,
            index,
            required,
            None::<&NoService>,
        )
        .await;
        return (answer, Vec::new());
    }

    let asked = RefCell::new(Vec::new());
    let lookup = &case["header_service"]["lookup"];
    let service = LookupFn(|height| {
        asked.borrow_mut().push(height);
        let answer = lookup_answer(lookup, height);
        async move { answer }
    });
    let answer = verify_brc29_payment(
        server_key,
        sender,
        prefix,
        suffix,
        &tx,
        index,
        required,
        Some(&service),
    )
    .await;
    (answer, asked.into_inner())
}

/// The checks every case gets that do not depend on the verdict: the
/// identity and script derivations from BOTH sides, and that the listed
/// outputs are the outputs of the BEEF's subject transaction.
fn check_case_is_self_consistent(case: &Value, name: &str) {
    let server = PrivateKey::from_hex(s(case, "server_private_key")).unwrap();
    assert_eq!(
        server.public_key().to_hex(),
        s(case, "server_identity_key"),
        "{name}: server_identity_key"
    );
    let expected = expected_locking_script(
        s(case, "server_private_key"),
        s(case, "sender_identity_key"),
        s(case, "derivation_prefix"),
        s(case, "derivation_suffix"),
    )
    .unwrap();
    assert_eq!(
        expected,
        s(case, "expected_locking_script"),
        "{name}: expected_locking_script"
    );
    let sender_side = sender_locking_script(
        s(case, "sender_private_key"),
        s(case, "server_identity_key"),
        s(case, "derivation_prefix"),
        s(case, "derivation_suffix"),
    )
    .unwrap();
    assert_eq!(
        sender_side, expected,
        "{name}: the sender derives the same script (BRC-42)"
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
async fn every_brc29_vector_gives_its_word_through_the_trait() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["schema"], "brc29-payment-vectors/1");
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20, "the 20 vectors");
    let words = doc["words"].as_object().unwrap();
    assert_eq!(words.len(), 6, "six words");

    let mut mismatches = Vec::new();
    for case in cases {
        let name = s(case, "name");
        check_case_is_self_consistent(case, name);

        let (answer, asked) = run_case(case).await;
        let (word, fields) = word_of(&answer);
        let expected = &case["expected"];
        if word != s(expected, "word") || fields != expected["fields"] {
            mismatches.push(format!(
                "{name}: intended {} {}, core gave {word} {fields}",
                expected["word"], expected["fields"]
            ));
        }
        // The outcome, not only the spelling: `Verified` is the one word
        // that serves; every other word, `Unverifiable` included, is refused.
        if let Ok(verdict) = &answer {
            let serves = s(expected, "word") == "Verified";
            if verdict.is_verified() != serves || verdict.is_refused() == serves {
                mismatches.push(format!(
                    "{name}: {} must {} but the core's predicates say verified={} refused={}",
                    expected["word"],
                    if serves { "serve" } else { "refuse" },
                    verdict.is_verified(),
                    verdict.is_refused()
                ));
            }
        }
        if !case["requires_merkle_lookup"].as_bool().unwrap() {
            assert!(
                asked.is_empty() || word == "Verified",
                "{name}: a refusal that does not need a lookup must not ask for one"
            );
        } else {
            let proof_height = u(&case["transaction"]["proof"], "height") as u32;
            assert_eq!(
                asked,
                vec![proof_height],
                "{name}: asked once, at the proof's height"
            );
        }

        // The pays-us-correctly check alone must give the same word on every
        // `stage: "output"` case.
        if s(case, "stage") == "output" {
            let tx = hex::decode(s(&case["transaction"], "beef_hex")).unwrap();
            let pure = verify_payment_output(
                s(case, "server_private_key"),
                s(case, "sender_identity_key"),
                s(case, "derivation_prefix"),
                s(case, "derivation_suffix"),
                &tx,
                u(case, "output_index") as usize,
                u(case, "required_satoshis"),
            );
            let (pure_word, pure_fields) = word_of(&pure);
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

/// The file's six words are the core's six; the glossary still spells
/// `Unverifiable` by its retired name `AcceptedUnverified` (the file
/// owner's to rename), while the ruled case uses the core's word.
#[test]
fn the_vector_words_are_the_cores_words() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let mut file_words: Vec<&str> = doc["words"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    file_words.sort_unstable();
    let core_words = [
        PaymentVerdict::Verified { satoshis: 0 }.word(),
        PaymentVerdict::Underpaid {
            paid: 0,
            required: 0,
        }
        .word(),
        PaymentVerdict::WrongScript {
            expected: String::new(),
            actual: String::new(),
        }
        .word(),
        PaymentVerdict::NoHeaderService.word(),
        PaymentVerdict::RootMismatch {
            height: 0,
            root: String::new(),
        }
        .word(),
        PaymentVerdict::Unverifiable {
            satoshis: 0,
            reason: String::new(),
        }
        .word(),
    ];
    let mut spelled: Vec<&str> = core_words
        .iter()
        .map(|w| {
            if *w == "Unverifiable" {
                "AcceptedUnverified"
            } else {
                w
            }
        })
        .collect();
    spelled.sort_unstable();
    assert_eq!(file_words, spelled);
}

/// The ruling the file records: `spv-lookup-error` expects `Unverifiable`
/// (fail closed), the case agrees with its ruling, and the ruled word is one
/// of the core's six. A second implementation reads the same list.
#[test]
fn the_lookup_error_case_is_ruled_unverifiable() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let rulings = doc["rulings"].as_array().expect("a rulings list");
    let ruling = rulings
        .iter()
        .find(|r| s(r, "case") == "spv-lookup-error")
        .expect("the lookup-error ruling");
    assert_eq!(s(ruling, "word"), "Unverifiable");
    assert_eq!(s(ruling, "date"), "2026-10-08");
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| s(c, "name") == "spv-lookup-error")
        .expect("the case");
    assert_eq!(s(&case["expected"], "word"), "Unverifiable");
    assert_eq!(s(&case["header_service"]["lookup"], "answer"), "error");
    assert_eq!(
        PaymentVerdict::Unverifiable {
            satoshis: 0,
            reason: String::new()
        }
        .word(),
        s(ruling, "word")
    );
}
