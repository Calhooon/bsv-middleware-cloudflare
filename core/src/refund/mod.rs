//! BRC-29 refunds, the pure half: the key the client receives on, and the
//! signer for a `createAction` template (feature `refund`).
//!
//! Issuing a refund (asking a wallet storage server to build the transaction,
//! broadcasting it, wrapping it as AtomicBEEF) is the host's: it needs a
//! transport. What the host needs from here is the locking script for the
//! client's BRC-29 child key ([`refund_locking_script`]) and
//! [`signer::sign_create_action_template`] for the template that comes back.

pub mod signer;

use std::fmt;

use bsv_sdk::primitives::PublicKey;
use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet};

use crate::brc29::{brc29_key_id, brc29_protocol, p2pkh_locking_script_hex};

/// A refund's key derivation failed: an invalid client key or derivation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationError(pub String);

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyDerivationError {}

/// The P2PKH locking script (hex) a refund to `client_identity_key` pays:
/// the CLIENT's BRC-29 child key for (server as sender, prefix, suffix),
/// derived from the server's side (`for_self = false`, the server is the
/// payer). The client derives the same key with `for_self = true` and the
/// server as counterparty, and internalizes the output.
pub fn refund_locking_script(
    server_wallet: &ProtoWallet,
    client_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
) -> Result<String, KeyDerivationError> {
    let client_pubkey = PublicKey::from_hex(client_identity_key)
        .map_err(|e| KeyDerivationError(format!("Invalid client key: {}", e)))?;
    let derived = server_wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(brc29_protocol()),
            key_id: Some(brc29_key_id(derivation_prefix, derivation_suffix)),
            counterparty: Some(Counterparty::Other(client_pubkey)),
            for_self: Some(false),
        })
        .map_err(|e| KeyDerivationError(e.to_string()))?;
    let pubkey_bytes = hex::decode(&derived.public_key)
        .map_err(|e| KeyDerivationError(format!("Invalid derived pubkey hex: {}", e)))?;
    Ok(p2pkh_locking_script_hex(&pubkey_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brc29::expected_locking_script;
    use bsv_sdk::primitives::PrivateKey;

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    /// A refund is a BRC-29 payment with the roles swapped: the script the
    /// server pays the client is the script the CLIENT would expect as a
    /// server receiving from this server.
    #[test]
    fn a_refund_pays_the_clients_expected_script() {
        let server_wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()));
        let server_identity = server_wallet.identity_key().to_hex();
        let client_identity = PrivateKey::from_hex(CLIENT_KEY)
            .unwrap()
            .public_key()
            .to_hex();
        let refund = refund_locking_script(&server_wallet, &client_identity, "p", "s").unwrap();
        let client_expects =
            expected_locking_script(CLIENT_KEY, &server_identity, "p", "s").unwrap();
        assert_eq!(refund, client_expects);
        assert!(refund.starts_with("76a914") && refund.ends_with("88ac"));
    }

    #[test]
    fn a_bad_client_key_is_a_key_derivation_error() {
        let server_wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()));
        let err = refund_locking_script(&server_wallet, "nope", "p", "s").unwrap_err();
        assert!(err.to_string().contains("Invalid client key"), "{err}");
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(!boxed.to_string().is_empty());
    }
}
