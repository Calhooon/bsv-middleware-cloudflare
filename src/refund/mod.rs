//! Server-to-client refund payments via BRC-29.
//!
//! This module provides a high-level `issue_refund()` function that creates a
//! BSV transaction paying the client back when a service fails after accepting
//! payment. The transaction is broadcast via the configured storage server and
//! returned as AtomicBEEF for the client to internalize.
//!
//! Three-step flow:
//!   1. `createAction` → storage server returns unsigned template + UTXO selection
//!   2. Sign locally → derive keys, compute BIP-143 sighash, build P2PKH unlock
//!   3. `processAction` → broadcast signed tx, get confirmation
//!
//! The result is an `AtomicBEEF` envelope that the client can pass to
//! `internalizeAction` to receive the refunded funds.

pub mod signer;

use crate::client::WorkerStorageClient;
use bsv_sdk::auth::utils::create_nonce;
use bsv_sdk::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_sdk::transaction::Beef;
use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};

/// Information about a completed refund, returned to the caller for inclusion
/// in the HTTP response to the client.
#[derive(Debug, Clone)]
pub struct RefundInfo {
    /// Base64-encoded AtomicBEEF transaction for the client to internalize.
    pub transaction: String,
    /// HMAC-derived nonce used as the derivation prefix.
    pub derivation_prefix: String,
    /// Random base64 string used as the derivation suffix.
    pub derivation_suffix: String,
    /// Server's identity public key (66-char hex compressed).
    pub sender_identity_key: String,
    /// Amount refunded in satoshis.
    pub satoshis: u64,
    /// Transaction ID of the refund (64-char hex).
    pub txid: String,
}

/// Errors that can occur during refund issuance.
#[derive(Debug)]
pub enum RefundError {
    /// Key derivation failed (invalid keys, nonce creation, etc.)
    KeyDerivation(String),
    /// createAction call to storage server failed.
    CreateAction(String),
    /// Local transaction signing failed.
    Signing(String),
    /// processAction call to storage server failed.
    ProcessAction(String),
    /// BEEF envelope construction failed.
    BeefConstruction(String),
}

impl std::fmt::Display for RefundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefundError::KeyDerivation(msg) => write!(f, "Key derivation: {}", msg),
            RefundError::CreateAction(msg) => write!(f, "createAction: {}", msg),
            RefundError::Signing(msg) => write!(f, "Signing: {}", msg),
            RefundError::ProcessAction(msg) => write!(f, "processAction: {}", msg),
            RefundError::BeefConstruction(msg) => write!(f, "BEEF construction: {}", msg),
        }
    }
}

/// Create a refund transaction paying the client back.
///
/// # Arguments
///
/// * `server_key` - Server's private key (64-char hex)
/// * `client_identity_key` - Client's identity public key (66-char hex)
/// * `satoshis` - Amount to refund
/// * `description` - Human-readable reason for the refund
/// * `originator` - Nonce originator string (agent name)
/// * `storage_url` - Storage server URL to use for `internalizeAction`.
///   If `None`, falls back to `https://storage.babbage.systems`.
///
/// # Returns
///
/// `RefundInfo` containing the AtomicBEEF transaction and derivation info
/// that the client needs to internalize the refund.
pub async fn issue_refund(
    server_key: &str,
    client_identity_key: &str,
    satoshis: u64,
    description: &str,
    originator: &str,
    storage_url: Option<&str>,
) -> Result<RefundInfo, RefundError> {
    // 1. Create wallet and derive client's receiving key
    let private_key = PrivateKey::from_hex(server_key)
        .map_err(|e| RefundError::KeyDerivation(format!("Invalid server key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key.clone()));
    let server_identity = wallet.identity_key().to_hex();

    let refund_prefix = create_nonce(&wallet, None, originator)
        .await
        .map_err(|e| RefundError::KeyDerivation(format!("Nonce creation: {}", e)))?;
    let mut suffix_bytes = [0u8; 32];
    getrandom::getrandom(&mut suffix_bytes)
        .map_err(|e| RefundError::KeyDerivation(format!("RNG: {}", e)))?;
    let refund_suffix = to_base64(&suffix_bytes);

    let key_id = format!("{} {}", refund_prefix, refund_suffix);
    let client_pubkey = PublicKey::from_hex(client_identity_key)
        .map_err(|e| RefundError::KeyDerivation(format!("Invalid client key: {}", e)))?;

    let derived = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, "3241645161d8")),
            key_id: Some(key_id),
            counterparty: Some(Counterparty::Other(client_pubkey)),
            for_self: Some(false),
        })
        .map_err(|e| RefundError::KeyDerivation(e.to_string()))?;

    // derived.public_key is a hex string
    let pubkey_bytes = hex::decode(&derived.public_key)
        .map_err(|e| RefundError::KeyDerivation(format!("Invalid derived pubkey hex: {}", e)))?;
    let pkh = signer::hash160(&pubkey_bytes);
    let locking_script = format!("76a914{}88ac", hex::encode(pkh));

    // 2. Create refund transaction via storage server
    let storage_wallet = ProtoWallet::new(Some(private_key));
    let mut storage_client = match storage_url {
        Some(url) => WorkerStorageClient::new(storage_wallet, url),
        None => WorkerStorageClient::mainnet(storage_wallet),
    };
    storage_client
        .make_available()
        .await
        .map_err(|e| RefundError::CreateAction(e.to_string()))?;
    let user_result = storage_client
        .find_or_insert_user(&server_identity)
        .await
        .map_err(|e| RefundError::CreateAction(e.to_string()))?;
    let user_id = user_result.get("userId").and_then(|v| v.as_i64());

    let auth_json = serde_json::json!({
        "identityKey": server_identity,
        "userId": user_id,
    });

    let create_args = serde_json::json!({
        "description": description,
        "version": 1, "lockTime": 0,
        "inputs": [], "labels": [],
        "outputs": [{
            "lockingScript": locking_script,
            "satoshis": satoshis,
            "outputDescription": "BRC-29 refund payment",
            "tags": [],
        }],
        "options": {
            "randomizeOutputs": false,
            "returnTXIDOnly": false,
            "knownTxids": [],
        },
        "isNewTx": true, "isNoSend": false, "isDelayed": false,
        "isSendWith": false, "isRemixChange": false,
        "isSignAction": false, "includeAllSourceTransactions": true,
    });

    let create_result = storage_client
        .create_action(auth_json.clone(), create_args)
        .await
        .map_err(|e| RefundError::CreateAction(e.to_string()))?;

    // 3. Sign the template
    let signing_wallet = ProtoWallet::new(Some(
        PrivateKey::from_hex(server_key).map_err(|e| RefundError::Signing(e.to_string()))?,
    ));
    let signed_tx = signer::sign_create_action_template(&signing_wallet, &create_result)
        .map_err(|e| RefundError::Signing(e))?;
    let txid = signer::compute_txid(&signed_tx);

    // 4. Broadcast via processAction
    let reference = create_result
        .get("reference")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let process_args = serde_json::json!({
        "reference": reference,
        "txid": txid,
        "rawTx": signed_tx,
        "sendWith": [],
        "isNewTx": true, "isNoSend": false,
        "isDelayed": false, "isSendWith": false,
    });
    storage_client
        .process_action(auth_json.clone(), process_args)
        .await
        .map_err(|e| RefundError::ProcessAction(e.to_string()))?;

    // 4b. Relinquish the refund output so the wallet doesn't track it as
    //     spendable — it belongs to the recipient, not us.
    let relinquish_args = serde_json::json!({
        "basket": "default",
        "output": format!("{}.0", txid),
    });
    // Best-effort: don't fail the refund if relinquish fails
    let _ = storage_client
        .relinquish_output(auth_json, relinquish_args)
        .await;

    // 5. Build AtomicBEEF
    let input_beef_array = create_result
        .get("inputBeef")
        .and_then(|v| v.as_array())
        .ok_or(RefundError::BeefConstruction("Missing inputBeef".into()))?;
    let input_beef_bytes: Vec<u8> = input_beef_array
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| {
                    RefundError::BeefConstruction(format!(
                        "inputBeef[{}]: invalid byte value: {}",
                        i, v
                    ))
                })
        })
        .collect::<std::result::Result<Vec<u8>, _>>()?;

    let mut beef = Beef::from_binary(&input_beef_bytes)
        .map_err(|e| RefundError::BeefConstruction(e.to_string()))?;
    beef.merge_raw_tx(signed_tx, None);
    let beef_bytes = beef
        .to_binary_atomic(&txid)
        .map_err(|e| RefundError::BeefConstruction(e.to_string()))?;

    Ok(RefundInfo {
        transaction: to_base64(&beef_bytes),
        derivation_prefix: refund_prefix,
        derivation_suffix: refund_suffix,
        sender_identity_key: server_identity,
        satoshis,
        txid,
    })
}
