//! BRC-29 payment verification before internalize.
//!
//! Verifies that an incoming BRC-29 payment transaction actually pays the
//! server's derived key at least the quoted amount BEFORE the payment is
//! internalized and service is rendered.
//!
//! The expected locking script commits to the server identity, the sender
//! identity, and this request's derivation prefix + suffix, so a transaction
//! built for any other (server, sender, nonce) tuple fails the byte-compare.
//! This closes four holes in one check:
//!   - underpaid / zero-sat outputs (amount check)
//!   - outputs paying a key the server can't spend, e.g. the client's own
//!     key (script check)
//!   - replaying an already-internalized tx against a fresh quote nonce
//!     (prefix is part of the invoice number, so the expected script differs)
//!   - replaying one payment across multiple servers (server identity is part
//!     of the derivation, so the expected script differs per server)
//!
//! The script/amount check proves the payment *pays us correctly*; it does not
//! prove the payment transaction is *real and confirmable*. [`verify_brc29_payment`]
//! adds that: BEEF structural completeness (rejects missing inputs / txid-only
//! gaps / broken proof chains) plus SPV: each merkle root in the proof is
//! checked against block headers via a header service speaking the ChainTracks
//! `findHeaderHexForHeight` API. SPV is **fail-open** on service errors (header
//! service down / timeout / height not yet indexed): the payment is still
//! accepted, with the upstream broadcast as the backstop, so a header-service
//! outage never halts revenue. It is **fail-closed** on an explicit root
//! MISMATCH, which is a fraud signal, not an outage.
//!
//! ## Header service
//!
//! This crate ships **no** header service of its own. Pass the base URL of
//! your own ChainTracks-compatible service as `header_url`; `None` resolves to
//! [`DEFAULT_CHAINTRACKS_URL`], a reserved `.invalid` placeholder under which
//! the merkle-root check is **skipped** (structural BEEF validation still
//! runs, and a warning is logged). Set your own header service for SPV.
//!
//! ## Relation to the payment middleware
//!
//! [`process_payment_with_storage`](crate::process_payment_with_storage)
//! verifies the derivation-prefix HMAC, consumes the prefix once, and hands
//! the transaction to the wallet storage server, which does its own script
//! and amount checks when it internalizes. The functions here are for callers
//! that run their **own** payment flow (a custom 402 handler, a pre-charge +
//! refund model, a non-wallet settlement path) and want the same guarantees
//! locally, before any remote call: an output that pays this server's derived
//! key, carrying at least the quoted satoshis, inside a complete proof.

use bsv_sdk::primitives::hash::hash160;
use bsv_sdk::primitives::{PrivateKey, PublicKey};
use bsv_sdk::transaction::{Beef, Transaction};
use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use serde::Deserialize;

/// BRC-29 payment protocol ID (security level 2, counterparty-scoped).
const BRC29_PROTOCOL_ID: &str = "3241645161d8";

/// Placeholder header-service base URL: **set your own header service.**
///
/// `.invalid` is a reserved top-level domain (RFC 2606) that never resolves.
/// When [`verify_brc29_payment`] receives `None` (or this exact value) as
/// `header_url`, the merkle-root check is skipped with a logged warning; the
/// structural BEEF check still runs. Point `header_url` at a service that
/// answers `GET {base}/findHeaderHexForHeight?height={h}` with
/// `{"status":"success","value":{"merkleRoot":"<hex>", ...}}` to enable SPV.
pub const DEFAULT_CHAINTRACKS_URL: &str = "https://chaintracks.invalid";

/// Errors from BRC-29 payment output verification.
///
/// All variants are client-fault: the payment must be rejected without
/// internalizing, and no refund is owed (no funds were accepted).
#[derive(Debug)]
pub enum PaymentVerifyError {
    /// Transaction could not be parsed from BEEF bytes.
    BadTransaction(String),
    /// The transaction has no output at the required index.
    MissingOutput { index: usize, output_count: usize },
    /// The output's locking script does not pay the server's derived key.
    WrongScript { expected: String, actual: String },
    /// The output pays the right key but less than the quoted price.
    Underpaid { satoshis: u64, required: u64 },
    /// Key derivation failed (invalid keys or derivation inputs).
    KeyDerivation(String),
    /// The BEEF is structurally incomplete: missing inputs, txid-only gaps,
    /// or a proof chain that does not verify. The payment cannot be trusted
    /// to be real and confirmable.
    BadBeef(String),
    /// A merkle root in the proof does NOT match the block header at that
    /// height: a fraud signal. Rejected even in fail-open mode.
    RootMismatch { height: u32, root: String },
}

impl std::fmt::Display for PaymentVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentVerifyError::BadTransaction(msg) => {
                write!(f, "Payment transaction unparseable: {}", msg)
            }
            PaymentVerifyError::MissingOutput {
                index,
                output_count,
            } => write!(
                f,
                "Payment transaction has no output at index {} ({} outputs present)",
                index, output_count
            ),
            PaymentVerifyError::WrongScript { expected, actual } => write!(
                f,
                "Payment output does not pay this server's BRC-29 derived key (expected script {}, got {})",
                expected, actual
            ),
            PaymentVerifyError::Underpaid {
                satoshis,
                required,
            } => write!(
                f,
                "Payment output carries {} satoshis but {} are required",
                satoshis, required
            ),
            PaymentVerifyError::KeyDerivation(msg) => {
                write!(f, "Key derivation failed: {}", msg)
            }
            PaymentVerifyError::BadBeef(msg) => {
                write!(f, "Payment proof is incomplete or unverifiable: {}", msg)
            }
            PaymentVerifyError::RootMismatch { height, root } => write!(
                f,
                "Payment merkle root {} at height {} does not match the block header",
                root, height
            ),
        }
    }
}

impl std::error::Error for PaymentVerifyError {}

// ─── Header-service response types ──────────────────────────────────

/// `{"status":"success","value":{...}}`
#[derive(Deserialize)]
struct ChainTracksApiResponse {
    status: String,
    value: Option<ChainTracksHeader>,
}

/// Handles both camelCase (`merkleRoot`) and lowercase (`merkleroot`) forms.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainTracksHeader {
    merkle_root: Option<String>,
    merkleroot: Option<String>,
}

/// Pure half of the header lookup: the merkle root carried by a
/// `findHeaderHexForHeight` response body, or why it cannot be read.
fn parse_header_response(body: &str, height: u32) -> std::result::Result<String, String> {
    let api: ChainTracksApiResponse =
        serde_json::from_str(body).map_err(|e| format!("parse response: {}", e))?;
    if api.status != "success" {
        return Err(format!(
            "header service status '{}' at height {}",
            api.status, height
        ));
    }
    let header = api
        .value
        .ok_or_else(|| format!("no header at height {}", height))?;
    header
        .merkle_root
        .or(header.merkleroot)
        .ok_or_else(|| "response missing merkleRoot".to_string())
}

/// Ask the header service whether `root` is the merkle root of the block at
/// `height`. `Ok(true)` = match, `Ok(false)` = mismatch (fraud), `Err` = the
/// service could not answer (caller decides fail-open vs fail-closed).
async fn check_merkle_root(
    base_url: &str,
    root: &str,
    height: u32,
) -> std::result::Result<bool, String> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{}/findHeaderHexForHeight?height={}", base, height);
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    let request =
        worker::Request::new_with_init(&url, &init).map_err(|e| format!("request build: {}", e))?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| format!("fetch height {}: {}", height, e))?;
    let status = response.status_code();
    if status >= 400 {
        return Err(format!(
            "header service HTTP {} at height {}",
            status, height
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("read response: {}", e))?;
    let mr = parse_header_response(&body, height)?;
    Ok(mr.eq_ignore_ascii_case(root))
}

/// Logs through the Workers console on wasm32; a no-op under native tests.
fn warn_log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

/// Verify a payment BEEF is structurally complete and its proofs check out.
///
/// Rejects on structural failure and on a root mismatch; fails open (accepts,
/// logs) when the header service cannot answer, and skips the root check
/// entirely (logs) when `header_url` is the [`DEFAULT_CHAINTRACKS_URL`]
/// placeholder. See the module docs.
async fn verify_payment_beef(
    tx_bytes: &[u8],
    header_url: &str,
) -> std::result::Result<(), PaymentVerifyError> {
    let mut beef = Beef::from_binary(tx_bytes)
        .map_err(|e| PaymentVerifyError::BadBeef(format!("BEEF parse: {}", e)))?;

    // Structural completeness: offline and deterministic. Rejects BEEFs with
    // missing inputs, txid-only gaps, or a proof chain that does not verify.
    let validation = beef.verify_valid(false);
    if !validation.valid {
        return Err(PaymentVerifyError::BadBeef(
            "missing inputs, txid-only gaps, or broken proof chain".to_string(),
        ));
    }

    if header_url == DEFAULT_CHAINTRACKS_URL {
        if !validation.roots.is_empty() {
            warn_log(
                "[payment_verify] no header service configured (header_url is the placeholder): merkle roots not checked",
            );
        }
        return Ok(());
    }

    // SPV: every merkle root must match a real block header. Fail-closed on a
    // mismatch (fraud); fail-open on a service error (broadcast backstops).
    for (height, root) in &validation.roots {
        match check_merkle_root(header_url, root, *height).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(PaymentVerifyError::RootMismatch {
                    height: *height,
                    root: root.clone(),
                });
            }
            Err(e) => {
                warn_log(&format!(
                    "[payment_verify] SPV fail-open (accepting) at height {}: {}",
                    height, e
                ));
            }
        }
    }
    Ok(())
}

/// Compute the P2PKH locking script (hex) the sender must have paid for a
/// BRC-29 payment to (`server_key`, `sender_identity_key`, prefix, suffix).
pub fn expected_brc29_locking_script(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
) -> std::result::Result<String, PaymentVerifyError> {
    let private_key = PrivateKey::from_hex(server_key)
        .map_err(|e| PaymentVerifyError::KeyDerivation(format!("Invalid server key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key));
    let sender_pubkey = PublicKey::from_hex(sender_identity_key)
        .map_err(|e| PaymentVerifyError::KeyDerivation(format!("Invalid sender key: {}", e)))?;

    // The sender derived OUR child key with themselves as sender
    // (for_self=false from their side); we derive the same key from our
    // side with for_self=true. BRC-42 guarantees both derivations agree.
    let derived = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(Protocol::new(
                SecurityLevel::Counterparty,
                BRC29_PROTOCOL_ID,
            )),
            key_id: Some(format!("{} {}", derivation_prefix, derivation_suffix)),
            counterparty: Some(Counterparty::Other(sender_pubkey)),
            for_self: Some(true),
        })
        .map_err(|e| PaymentVerifyError::KeyDerivation(e.to_string()))?;

    let pubkey_bytes = hex::decode(&derived.public_key).map_err(|e| {
        PaymentVerifyError::KeyDerivation(format!("Invalid derived pubkey hex: {}", e))
    })?;
    let pkh = hash160(&pubkey_bytes);
    Ok(format!("76a914{}88ac", hex::encode(pkh)))
}

/// Verify that output `output_index` of the BEEF-encoded payment transaction
/// pays the server's BRC-29 derived key at least `required_satoshis`.
///
/// Call this AFTER nonce/quote verification and BEFORE `internalizeAction`.
/// Returns the actual satoshis carried by the output on success.
pub fn verify_brc29_payment_output(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> std::result::Result<u64, PaymentVerifyError> {
    let tx = Transaction::from_beef(tx_bytes, None)
        .map_err(|e| PaymentVerifyError::BadTransaction(e.to_string()))?;

    let output = tx
        .outputs
        .get(output_index)
        .ok_or(PaymentVerifyError::MissingOutput {
            index: output_index,
            output_count: tx.outputs.len(),
        })?;

    let expected_script = expected_brc29_locking_script(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
    )?;
    let actual_script = output.locking_script.to_hex();
    if actual_script != expected_script {
        return Err(PaymentVerifyError::WrongScript {
            expected: expected_script,
            actual: actual_script,
        });
    }

    let satoshis = output.satoshis.unwrap_or(0);
    if satoshis < required_satoshis {
        return Err(PaymentVerifyError::Underpaid {
            satoshis,
            required: required_satoshis,
        });
    }

    Ok(satoshis)
}

/// Full pre-service payment verification: pays-us-correctly **and**
/// real-and-confirmable. Call this AFTER nonce/quote verification and BEFORE
/// `internalizeAction`; on `Ok` the payment is safe to internalize and serve,
/// on `Err` reject without serving (no funds accepted, so no refund is owed).
///
/// Runs, in order:
///   1. script + amount ([`verify_brc29_payment_output`]): the output pays the
///      server's derived key at least `required_satoshis`.
///   2. BEEF structural completeness + SPV: the proof chain is complete and
///      each merkle root matches a real block header.
///
/// `header_url` selects the header service; `None` uses
/// [`DEFAULT_CHAINTRACKS_URL`], the placeholder under which step 2 performs
/// the structural check only (set your own header service for SPV). SPV is
/// fail-open on service errors and fail-closed on a root mismatch (see the
/// module docs).
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    header_url: Option<&str>,
) -> std::result::Result<u64, PaymentVerifyError> {
    // 1. Cheap, offline, deterministic: does it pay us the quoted amount?
    let satoshis = verify_brc29_payment_output(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )?;

    // 2. Is the payment real and confirmable? (structural + SPV)
    verify_payment_beef(tx_bytes, header_url.unwrap_or(DEFAULT_CHAINTRACKS_URL)).await?;

    Ok(satoshis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::script::LockingScript;
    use bsv_sdk::transaction::{TransactionInput, TransactionOutput};

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn sender_identity() -> String {
        let sender_priv = PrivateKey::from_hex(SENDER_KEY).unwrap();
        ProtoWallet::new(Some(sender_priv)).identity_key().to_hex()
    }

    /// A BEEF holding ONE transaction that spends an output this BEEF does not
    /// carry and pays `satoshis` to `script_hex`. `from_beef` resolves it (the
    /// output is readable), while `verify_valid` refuses it (missing input).
    fn beef_with_unproven_payment(script_hex: &str, satoshis: u64) -> Vec<u8> {
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_txid: Some("11".repeat(32)),
            source_output_index: 0,
            ..Default::default()
        })
        .unwrap();
        tx.add_output(TransactionOutput {
            satoshis: Some(satoshis),
            locking_script: LockingScript::from_hex(script_hex).unwrap(),
            change: false,
        })
        .unwrap();
        let mut beef = Beef::new();
        beef.merge_transaction(tx);
        beef.to_binary()
    }

    /// The script the SENDER computes (their wallet, for_self=false toward the
    /// server) must equal the script the SERVER expects (for_self=true).
    #[test]
    fn test_sender_and_server_derive_same_script() {
        let server_priv = PrivateKey::from_hex(SERVER_KEY).unwrap();
        let server_identity = ProtoWallet::new(Some(server_priv)).identity_key().to_hex();

        let prefix = "dGVzdC1wcmVmaXg=";
        let suffix = "dGVzdC1zdWZmaXg=";

        // Sender-side derivation of the server's receiving key
        let sender_wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SENDER_KEY).unwrap()));
        let derived = sender_wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(Protocol::new(
                    SecurityLevel::Counterparty,
                    BRC29_PROTOCOL_ID,
                )),
                key_id: Some(format!("{} {}", prefix, suffix)),
                counterparty: Some(Counterparty::Other(
                    PublicKey::from_hex(&server_identity).unwrap(),
                )),
                for_self: Some(false),
            })
            .unwrap();
        let pkh = hash160(&hex::decode(&derived.public_key).unwrap());
        let sender_script = format!("76a914{}88ac", hex::encode(pkh));

        // Server-side expectation
        let server_script =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), prefix, suffix).unwrap();

        assert_eq!(sender_script, server_script);
    }

    #[test]
    fn test_different_nonce_changes_script() {
        let a = expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefixA", "suffix")
            .unwrap();
        let b = expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefixB", "suffix")
            .unwrap();
        assert_ne!(
            a, b,
            "different derivation prefixes must produce different scripts"
        );
    }

    #[test]
    fn test_different_server_changes_script() {
        let a = expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix")
            .unwrap();
        let b = expected_brc29_locking_script(SENDER_KEY, &sender_identity(), "prefix", "suffix")
            .unwrap();
        assert_ne!(a, b, "different server keys must produce different scripts");
    }

    #[test]
    fn test_invalid_keys_are_key_derivation_errors() {
        let bad_server =
            expected_brc29_locking_script("zz", &sender_identity(), "prefix", "suffix")
                .unwrap_err();
        assert!(matches!(bad_server, PaymentVerifyError::KeyDerivation(_)));
        let bad_sender =
            expected_brc29_locking_script(SERVER_KEY, "not-a-pubkey", "prefix", "suffix")
                .unwrap_err();
        assert!(matches!(bad_sender, PaymentVerifyError::KeyDerivation(_)));
    }

    #[test]
    fn test_bad_tx_bytes_rejected() {
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::BadTransaction(_)));
    }

    #[test]
    fn test_output_check_accepts_exact_and_over_payment() {
        let script =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix")
                .unwrap();
        for paid in [1000u64, 1001, 50_000] {
            let beef = beef_with_unproven_payment(&script, paid);
            let sats = verify_brc29_payment_output(
                SERVER_KEY,
                &sender_identity(),
                "prefix",
                "suffix",
                &beef,
                0,
                1000,
            )
            .unwrap();
            assert_eq!(sats, paid);
        }
    }

    #[test]
    fn test_underpaid_output_rejected() {
        let script =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&script, 999);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaymentVerifyError::Underpaid {
                satoshis: 999,
                required: 1000
            }
        ));
    }

    #[test]
    fn test_output_for_another_nonce_or_server_rejected() {
        let other_nonce =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "stale", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&other_nonce, 5000);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::WrongScript { .. }));

        let other_server =
            expected_brc29_locking_script(SENDER_KEY, &sender_identity(), "prefix", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&other_server, 5000);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::WrongScript { .. }));
    }

    #[test]
    fn test_missing_output_index_rejected() {
        let script =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&script, 1000);
        let err = verify_brc29_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            3,
            1000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaymentVerifyError::MissingOutput {
                index: 3,
                output_count: 1
            }
        ));
    }

    /// The full check: a transaction that pays us correctly but whose BEEF
    /// carries no ancestry/proof is refused as `BadBeef` (never reaches the
    /// header service), so a bare, unconfirmable payment cannot buy service.
    #[tokio::test]
    async fn test_unproven_beef_fails_full_verification() {
        let script =
            expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix")
                .unwrap();
        let beef = beef_with_unproven_payment(&script, 1000);
        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::BadBeef(_)), "{err}");
    }

    /// Step 1 (script + amount) runs before any BEEF/SPV work, so garbage
    /// bytes surface as `BadTransaction` without a network round trip.
    #[tokio::test]
    async fn test_full_verification_bad_bytes_rejected_offline() {
        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
            Some("https://example.invalid"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::BadTransaction(_)));
    }

    #[test]
    fn test_default_header_url_is_a_reserved_placeholder() {
        assert!(DEFAULT_CHAINTRACKS_URL.ends_with(".invalid"));
    }

    #[test]
    fn test_parse_header_response_accepts_both_root_spellings() {
        let camel = r#"{"status":"success","value":{"merkleRoot":"AbCd"}}"#;
        assert_eq!(parse_header_response(camel, 7).unwrap(), "AbCd");
        let lower = r#"{"status":"success","value":{"merkleroot":"ef01"}}"#;
        assert_eq!(parse_header_response(lower, 7).unwrap(), "ef01");
    }

    #[test]
    fn test_parse_header_response_errors_are_service_errors() {
        let not_success = r#"{"status":"error","value":null}"#;
        assert!(parse_header_response(not_success, 7)
            .unwrap_err()
            .contains("status 'error'"));
        let no_value = r#"{"status":"success"}"#;
        assert!(parse_header_response(no_value, 7)
            .unwrap_err()
            .contains("no header at height 7"));
        let no_root = r#"{"status":"success","value":{"height":7}}"#;
        assert!(parse_header_response(no_root, 7)
            .unwrap_err()
            .contains("missing merkleRoot"));
        assert!(parse_header_response("not json", 7)
            .unwrap_err()
            .contains("parse response"));
    }

    #[test]
    fn test_error_display_names_the_fault() {
        let s = PaymentVerifyError::Underpaid {
            satoshis: 5,
            required: 10,
        }
        .to_string();
        assert!(
            s.contains("5 satoshis") && s.contains("10 are required"),
            "{s}"
        );
        let s = PaymentVerifyError::RootMismatch {
            height: 42,
            root: "ab".into(),
        }
        .to_string();
        assert!(s.contains("height 42"), "{s}");
        let boxed: Box<dyn std::error::Error> = Box::new(PaymentVerifyError::BadBeef("x".into()));
        assert!(boxed.to_string().contains("incomplete"));
    }
}
