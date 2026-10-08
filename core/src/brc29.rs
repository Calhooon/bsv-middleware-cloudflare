//! BRC-29 derivation and the pays-us-correctly check.
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
//! The check proves the payment *pays us correctly*; it does not prove the
//! payment transaction is *real and confirmable*. That is
//! [`verify_brc29_payment`](crate::verify_brc29_payment)'s second half.

use bsv_sdk::auth::utils::{create_nonce, verify_nonce};
use bsv_sdk::primitives::hash::hash160;
use bsv_sdk::primitives::{PrivateKey, PublicKey};
use bsv_sdk::transaction::Transaction;
use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};

use crate::verdict::{PaymentFault, PaymentVerdict};

/// BRC-29 payment protocol ID (security level 2, counterparty-scoped).
pub const BRC29_PROTOCOL_ID: &str = "3241645161d8";

/// The BRC-29 protocol: security level 2 (counterparty), `3241645161d8`.
pub fn brc29_protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, BRC29_PROTOCOL_ID)
}

/// The BRC-29 key ID for a derivation prefix and suffix: `"<prefix> <suffix>"`.
pub fn brc29_key_id(derivation_prefix: &str, derivation_suffix: &str) -> String {
    format!("{} {}", derivation_prefix, derivation_suffix)
}

/// The P2PKH locking script (hex) paying `pubkey` (compressed, bytes):
/// `76a914 <hash160(pubkey)> 88ac`.
pub fn p2pkh_locking_script_hex(pubkey: &[u8]) -> String {
    format!("76a914{}88ac", hex::encode(hash160(pubkey)))
}

/// Compute the P2PKH locking script (hex) the sender must have paid for a
/// BRC-29 payment to (`server_key`, `sender_identity_key`, prefix, suffix):
/// the server's child key for that counterparty and key ID, derived from
/// the server's side (`for_self = true`).
pub fn expected_locking_script(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
) -> Result<String, PaymentFault> {
    let private_key = PrivateKey::from_hex(server_key)
        .map_err(|e| PaymentFault::KeyDerivation(format!("Invalid server key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key));
    let sender_pubkey = PublicKey::from_hex(sender_identity_key)
        .map_err(|e| PaymentFault::KeyDerivation(format!("Invalid sender key: {}", e)))?;

    // The sender derived OUR child key with themselves as sender
    // (for_self=false from their side); we derive the same key from our
    // side with for_self=true. BRC-42 guarantees both derivations agree.
    let derived = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(brc29_protocol()),
            key_id: Some(brc29_key_id(derivation_prefix, derivation_suffix)),
            counterparty: Some(Counterparty::Other(sender_pubkey)),
            for_self: Some(true),
        })
        .map_err(|e| PaymentFault::KeyDerivation(e.to_string()))?;

    let pubkey_bytes = hex::decode(&derived.public_key)
        .map_err(|e| PaymentFault::KeyDerivation(format!("Invalid derived pubkey hex: {}", e)))?;
    Ok(p2pkh_locking_script_hex(&pubkey_bytes))
}

/// The same script from the SENDER's side: the payer's child key for the
/// server as counterparty (`for_self = false`). Equal to
/// [`expected_locking_script`] by BRC-42; what a client computes when it
/// builds the payment, and what a vector producer records.
pub fn sender_locking_script(
    sender_key: &str,
    server_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
) -> Result<String, PaymentFault> {
    let private_key = PrivateKey::from_hex(sender_key)
        .map_err(|e| PaymentFault::KeyDerivation(format!("Invalid sender key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key));
    let server_pubkey = PublicKey::from_hex(server_identity_key)
        .map_err(|e| PaymentFault::KeyDerivation(format!("Invalid server key: {}", e)))?;
    let derived = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(brc29_protocol()),
            key_id: Some(brc29_key_id(derivation_prefix, derivation_suffix)),
            counterparty: Some(Counterparty::Other(server_pubkey)),
            for_self: Some(false),
        })
        .map_err(|e| PaymentFault::KeyDerivation(e.to_string()))?;
    let pubkey_bytes = hex::decode(&derived.public_key)
        .map_err(|e| PaymentFault::KeyDerivation(format!("Invalid derived pubkey hex: {}", e)))?;
    Ok(p2pkh_locking_script_hex(&pubkey_bytes))
}

/// Does output `output_index` of the BEEF-encoded payment transaction pay the
/// server's BRC-29 derived key at least `required_satoshis`?
///
/// Offline and deterministic. Script is checked before amount. Answers
/// [`Verified`](PaymentVerdict::Verified) (with the output's satoshis),
/// [`WrongScript`](PaymentVerdict::WrongScript) or
/// [`Underpaid`](PaymentVerdict::Underpaid); a transaction that cannot be
/// read, has no such output, or whose keys do not derive is a
/// [`PaymentFault`]. Reference rule: the payment is the named output only,
/// never a search for one that would pay.
pub fn verify_payment_output(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> Result<PaymentVerdict, PaymentFault> {
    let tx = Transaction::from_beef(tx_bytes, None)
        .map_err(|e| PaymentFault::BadTransaction(e.to_string()))?;

    let output = tx
        .outputs
        .get(output_index)
        .ok_or(PaymentFault::MissingOutput {
            index: output_index,
            output_count: tx.outputs.len(),
        })?;

    let expected = expected_locking_script(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
    )?;
    let actual = output.locking_script.to_hex();
    if actual != expected {
        return Ok(PaymentVerdict::WrongScript { expected, actual });
    }

    let satoshis = output.satoshis.unwrap_or(0);
    if satoshis < required_satoshis {
        return Ok(PaymentVerdict::Underpaid {
            paid: satoshis,
            required: required_satoshis,
        });
    }

    Ok(PaymentVerdict::Verified { satoshis })
}

/// A fresh BRC-29 derivation prefix: an HMAC nonce the server can later
/// verify as its own without storing it (the reference's `createNonce`).
/// `originator` names the calling application to the wallet.
pub async fn create_derivation_prefix(
    wallet: &ProtoWallet,
    originator: &str,
) -> Result<String, bsv_sdk::Error> {
    create_nonce(wallet, None, originator).await
}

/// Whether `derivation_prefix` is a nonce this server minted under
/// `originator` (the reference's `verifyNonce`). A prefix that cannot be
/// checked is `false`, never an error.
pub async fn verify_derivation_prefix(
    derivation_prefix: &str,
    wallet: &ProtoWallet,
    originator: &str,
) -> bool {
    verify_nonce(derivation_prefix, wallet, None, originator)
        .await
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Synthetic payments for the core's own tests and the conformance runner.
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::script::LockingScript;
    use bsv_sdk::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    use bsv_sdk::wallet::ProtoWallet;

    pub const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    pub const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    /// Block height of the one-leaf proof in [`beef_with_proven_payment`].
    pub const PROOF_HEIGHT: u32 = 850_000;

    pub fn sender_identity() -> String {
        let sender_priv = PrivateKey::from_hex(SENDER_KEY).unwrap();
        ProtoWallet::new(Some(sender_priv)).identity_key().to_hex()
    }

    pub fn payment_tx(script_hex: &str, satoshis: u64) -> Transaction {
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
        tx
    }

    /// A BEEF holding ONE transaction that spends an output this BEEF does not
    /// carry and pays `satoshis` to `script_hex`. `from_beef` resolves it (the
    /// output is readable), while `verify_valid` refuses it (missing input).
    pub fn beef_with_unproven_payment(script_hex: &str, satoshis: u64) -> Vec<u8> {
        let mut beef = Beef::new();
        beef.merge_transaction(payment_tx(script_hex, satoshis));
        beef.to_binary()
    }

    /// A BEEF holding ONE transaction proven by a one-leaf BUMP at
    /// `PROOF_HEIGHT` (a block of one transaction, whose merkle root IS the
    /// txid), paying `satoshis` to `script_hex`. `verify_valid` accepts it and
    /// reports exactly one root, so SPV can be driven by a stub service.
    /// Returns the bytes and the txid (= the root the service must answer).
    pub fn beef_with_proven_payment(script_hex: &str, satoshis: u64) -> (Vec<u8>, String) {
        let tx = payment_tx(script_hex, satoshis);
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

    pub fn our_script() -> String {
        super::expected_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    /// The script the SENDER computes (their wallet, for_self=false toward the
    /// server) must equal the script the SERVER expects (for_self=true).
    #[test]
    fn test_sender_and_server_derive_same_script() {
        let server_identity = PrivateKey::from_hex(SERVER_KEY)
            .unwrap()
            .public_key()
            .to_hex();
        let prefix = "dGVzdC1wcmVmaXg=";
        let suffix = "dGVzdC1zdWZmaXg=";
        let sender_script =
            sender_locking_script(SENDER_KEY, &server_identity, prefix, suffix).unwrap();
        let server_script =
            expected_locking_script(SERVER_KEY, &sender_identity(), prefix, suffix).unwrap();
        assert_eq!(sender_script, server_script);
    }

    #[test]
    fn test_different_nonce_changes_script() {
        let a =
            expected_locking_script(SERVER_KEY, &sender_identity(), "prefixA", "suffix").unwrap();
        let b =
            expected_locking_script(SERVER_KEY, &sender_identity(), "prefixB", "suffix").unwrap();
        assert_ne!(
            a, b,
            "different derivation prefixes must produce different scripts"
        );
    }

    #[test]
    fn test_different_server_changes_script() {
        let a =
            expected_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix").unwrap();
        let b =
            expected_locking_script(SENDER_KEY, &sender_identity(), "prefix", "suffix").unwrap();
        assert_ne!(a, b, "different server keys must produce different scripts");
    }

    #[test]
    fn test_invalid_keys_are_key_derivation_faults() {
        let bad_server =
            expected_locking_script("zz", &sender_identity(), "prefix", "suffix").unwrap_err();
        assert!(matches!(bad_server, PaymentFault::KeyDerivation(_)));
        let bad_sender =
            expected_locking_script(SERVER_KEY, "not-a-pubkey", "prefix", "suffix").unwrap_err();
        assert!(matches!(bad_sender, PaymentFault::KeyDerivation(_)));
        let bad = sender_locking_script("zz", &sender_identity(), "p", "s").unwrap_err();
        assert!(matches!(bad, PaymentFault::KeyDerivation(_)));
        let bad = sender_locking_script(SENDER_KEY, "nope", "p", "s").unwrap_err();
        assert!(matches!(bad, PaymentFault::KeyDerivation(_)));
    }

    #[test]
    fn test_key_id_and_script_shape() {
        assert_eq!(brc29_key_id("p", "s"), "p s");
        let script = p2pkh_locking_script_hex(&[2u8; 33]);
        assert!(script.starts_with("76a914") && script.ends_with("88ac"));
        assert_eq!(script.len(), 50);
        assert_eq!(BRC29_PROTOCOL_ID, "3241645161d8");
    }

    #[test]
    fn test_bad_tx_bytes_is_a_fault() {
        let err = verify_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentFault::BadTransaction(_)));
    }

    #[test]
    fn test_output_check_accepts_exact_and_over_payment() {
        let script = our_script();
        for paid in [1000u64, 1001, 50_000] {
            let beef = beef_with_unproven_payment(&script, paid);
            let verdict = verify_payment_output(
                SERVER_KEY,
                &sender_identity(),
                "prefix",
                "suffix",
                &beef,
                0,
                1000,
            )
            .unwrap();
            assert_eq!(verdict, PaymentVerdict::Verified { satoshis: paid });
        }
    }

    #[test]
    fn test_underpaid_output_is_the_word() {
        let beef = beef_with_unproven_payment(&our_script(), 999);
        let verdict = verify_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap();
        assert_eq!(
            verdict,
            PaymentVerdict::Underpaid {
                paid: 999,
                required: 1000
            }
        );
    }

    #[test]
    fn test_output_for_another_nonce_or_server_is_wrong_script() {
        let other_nonce =
            expected_locking_script(SERVER_KEY, &sender_identity(), "stale", "suffix").unwrap();
        let beef = beef_with_unproven_payment(&other_nonce, 5000);
        let verdict = verify_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap();
        assert!(
            matches!(&verdict, PaymentVerdict::WrongScript { expected, actual }
                if *expected == our_script() && *actual == other_nonce),
            "{verdict:?}"
        );

        let other_server =
            expected_locking_script(SENDER_KEY, &sender_identity(), "prefix", "suffix").unwrap();
        let beef = beef_with_unproven_payment(&other_server, 5000);
        let verdict = verify_payment_output(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
        )
        .unwrap();
        assert!(matches!(verdict, PaymentVerdict::WrongScript { .. }));
    }

    #[test]
    fn test_missing_output_index_is_a_fault() {
        let beef = beef_with_unproven_payment(&our_script(), 1000);
        let err = verify_payment_output(
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
            PaymentFault::MissingOutput {
                index: 3,
                output_count: 1
            }
        ));
    }

    #[tokio::test]
    async fn test_derivation_prefix_round_trips_under_its_originator() {
        let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()));
        let prefix = create_derivation_prefix(&wallet, "core-test")
            .await
            .unwrap();
        assert!(verify_derivation_prefix(&prefix, &wallet, "core-test").await);
        let other = ProtoWallet::new(Some(PrivateKey::from_hex(SENDER_KEY).unwrap()));
        assert!(!verify_derivation_prefix(&prefix, &other, "core-test").await);
        assert!(!verify_derivation_prefix("not a nonce", &wallet, "core-test").await);
    }
}
