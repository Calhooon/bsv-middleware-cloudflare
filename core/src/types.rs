//! The context a host attaches to a request once the rules have spoken.
//! Pure data, shared by every host.

use serde::Deserialize;

/// Authentication context attached to authenticated requests.
///
/// This provides information about the authenticated peer to request handlers.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated peer's identity key (compressed public key hex, 66 chars).
    pub identity_key: String,
    /// Whether the request is fully authenticated.
    pub is_authenticated: bool,
}

impl AuthContext {
    /// Creates an authenticated context with the given identity key.
    pub fn authenticated(identity_key: String) -> Self {
        Self {
            identity_key,
            is_authenticated: true,
        }
    }

    /// Creates an unauthenticated context (for requests allowed without auth).
    pub fn unauthenticated() -> Self {
        Self {
            identity_key: "unknown".to_string(),
            is_authenticated: false,
        }
    }
}

/// Payment context attached to requests that include payment.
///
/// Matches Express's `req.payment = { satoshisPaid, accepted, tx }`.
#[derive(Debug, Clone)]
pub struct PaymentContext {
    /// Amount paid in satoshis.
    /// Express: `satoshisPaid`
    pub satoshis_paid: u64,
    /// Whether payment was accepted by the wallet.
    /// Express: `accepted`
    pub accepted: bool,
    /// The base64-encoded transaction (from the payment header).
    /// Express: `tx`
    pub tx: Option<String>,
}

/// BSV Payment data from the `x-bsv-payment` header.
///
/// This structure represents the payment information sent by clients
/// in the `x-bsv-payment` header for paid requests.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BsvPayment {
    /// Derivation prefix from the 402 response.
    pub derivation_prefix: String,
    /// Derivation suffix chosen by the client.
    pub derivation_suffix: String,
    /// Base64 encoded BEEF transaction.
    pub transaction: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_carry_their_state() {
        let a = AuthContext::authenticated("02ab".into());
        assert!(a.is_authenticated);
        assert_eq!(a.identity_key, "02ab");
        let u = AuthContext::unauthenticated();
        assert!(!u.is_authenticated);
        assert_eq!(u.identity_key, "unknown");
    }

    #[test]
    fn a_payment_header_parses_camel_case() {
        let p: BsvPayment = serde_json::from_str(
            r#"{"derivationPrefix":"p","derivationSuffix":"s","transaction":"dHg="}"#,
        )
        .unwrap();
        assert_eq!(
            (p.derivation_prefix.as_str(), p.derivation_suffix.as_str()),
            ("p", "s")
        );
        assert_eq!(p.transaction, "dHg=");
        let c = PaymentContext {
            satoshis_paid: 5,
            accepted: true,
            tx: None,
        };
        assert_eq!(c.satoshis_paid, 5);
    }
}
