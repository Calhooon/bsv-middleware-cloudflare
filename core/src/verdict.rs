//! The words a BRC-29 payment check answers with: one enum, no booleans.
//! The rule behind it: a payment verifier answers in words, never a
//! boolean, fails closed without a header service, and never serves on a
//! root it could not check.
//!
//! A host collapses the words to "serve" or "refuse" in ONE visible match.
//! [`PaymentVerdict::NoHeaderService`] is the server's own fault and is
//! answered as a 5xx, never as a client error; [`PaymentVerdict::Unverifiable`]
//! is the word the host decides on (fail open with the carried amount, or
//! fail closed): the core never serves on it.

use std::fmt;

/// The verdict on one BRC-29 payment output: the six words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentVerdict {
    /// The output pays the server's derived key at least the quoted amount,
    /// the BEEF is structurally complete, and every merkle root in the proof
    /// matches the block header at its height (or the proof carries no root
    /// to check). `satoshis` is the output's amount, which may exceed the
    /// price.
    Verified { satoshis: u64 },
    /// The output pays the derived key, but less than required.
    Underpaid { paid: u64, required: u64 },
    /// The output's locking script is not the one derived for this
    /// (server, sender, prefix, suffix) tuple: it pays another server, an
    /// older quote, or the sender itself.
    WrongScript { expected: String, actual: String },
    /// No header service was supplied, so SPV cannot run. Fail closed: a
    /// deployment fault, refused BEFORE the script, amount or proof is looked
    /// at. Answer it as a 5xx server fault, never a 4xx client error.
    NoHeaderService,
    /// A merkle root in the proof differs from the block header at that
    /// height: a fraud signal, never an outage.
    RootMismatch { height: u32, root: String },
    /// The output pays correctly and the proof is complete, but at least one
    /// merkle root was NOT checked against a block header: the service could
    /// not answer, or the caller opted out of SPV by name
    /// ([`verify_brc29_payment_structural_only`](crate::verify_brc29_payment_structural_only)).
    /// `reason` says which. The host decides what to do with it; the core
    /// never serves on it.
    Unverifiable { satoshis: u64, reason: String },
}

impl PaymentVerdict {
    /// The word alone, for logs and conformance tables.
    pub fn word(&self) -> &'static str {
        match self {
            PaymentVerdict::Verified { .. } => "Verified",
            PaymentVerdict::Underpaid { .. } => "Underpaid",
            PaymentVerdict::WrongScript { .. } => "WrongScript",
            PaymentVerdict::NoHeaderService => "NoHeaderService",
            PaymentVerdict::RootMismatch { .. } => "RootMismatch",
            PaymentVerdict::Unverifiable { .. } => "Unverifiable",
        }
    }

    /// `true` only for [`Verified`](Self::Verified): the one word the core
    /// itself stands behind. Every other word is a refusal or a decision the
    /// host owns.
    pub fn is_verified(&self) -> bool {
        matches!(self, PaymentVerdict::Verified { .. })
    }
}

impl fmt::Display for PaymentVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentVerdict::Verified { satoshis } => {
                write!(f, "Verified: the output carries {} satoshis", satoshis)
            }
            PaymentVerdict::Underpaid { paid, required } => write!(
                f,
                "Payment output carries {} satoshis but {} are required",
                paid, required
            ),
            PaymentVerdict::WrongScript { expected, actual } => write!(
                f,
                "Payment output does not pay this server's BRC-29 derived key (expected script {}, got {})",
                expected, actual
            ),
            PaymentVerdict::NoHeaderService => write!(
                f,
                "No header service configured for SPV: supply one, or opt out by name with verify_brc29_payment_structural_only"
            ),
            PaymentVerdict::RootMismatch { height, root } => write!(
                f,
                "Payment merkle root {} at height {} does not match the block header",
                root, height
            ),
            PaymentVerdict::Unverifiable { satoshis, reason } => write!(
                f,
                "Payment output carries {} satoshis but its merkle root was not checked against a block header: {}",
                satoshis, reason
            ),
        }
    }
}

/// The input could not be judged at all: not a verdict on the payment but on
/// its shape. Every variant means refuse without internalizing; the
/// transaction never paid anything, so no refund is owed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentFault {
    /// The transaction could not be parsed from the BEEF bytes.
    BadTransaction(String),
    /// The transaction has no output at the required index.
    MissingOutput { index: usize, output_count: usize },
    /// Key derivation failed: an invalid server key, sender key or
    /// derivation input. A server-key failure is the server's own fault.
    KeyDerivation(String),
    /// The BEEF is structurally incomplete: missing inputs, txid-only gaps,
    /// or a proof chain that does not verify. The payment cannot be trusted
    /// to be real and confirmable.
    BadBeef(String),
}

impl fmt::Display for PaymentFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentFault::BadTransaction(msg) => {
                write!(f, "Payment transaction unparseable: {}", msg)
            }
            PaymentFault::MissingOutput {
                index,
                output_count,
            } => write!(
                f,
                "Payment transaction has no output at index {} ({} outputs present)",
                index, output_count
            ),
            PaymentFault::KeyDerivation(msg) => write!(f, "Key derivation failed: {}", msg),
            PaymentFault::BadBeef(msg) => {
                write!(f, "Payment proof is incomplete or unverifiable: {}", msg)
            }
        }
    }
}

impl std::error::Error for PaymentFault {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_six_words_are_the_six_words() {
        let words = [
            PaymentVerdict::Verified { satoshis: 1 }.word(),
            PaymentVerdict::Underpaid {
                paid: 1,
                required: 2,
            }
            .word(),
            PaymentVerdict::WrongScript {
                expected: "a".into(),
                actual: "b".into(),
            }
            .word(),
            PaymentVerdict::NoHeaderService.word(),
            PaymentVerdict::RootMismatch {
                height: 1,
                root: "c".into(),
            }
            .word(),
            PaymentVerdict::Unverifiable {
                satoshis: 1,
                reason: "d".into(),
            }
            .word(),
        ];
        assert_eq!(
            words,
            [
                "Verified",
                "Underpaid",
                "WrongScript",
                "NoHeaderService",
                "RootMismatch",
                "Unverifiable"
            ]
        );
    }

    #[test]
    fn only_verified_is_verified() {
        assert!(PaymentVerdict::Verified { satoshis: 5 }.is_verified());
        assert!(!PaymentVerdict::Unverifiable {
            satoshis: 5,
            reason: "x".into()
        }
        .is_verified());
        assert!(!PaymentVerdict::NoHeaderService.is_verified());
    }

    #[test]
    fn display_names_the_fault() {
        let s = PaymentVerdict::Underpaid {
            paid: 5,
            required: 10,
        }
        .to_string();
        assert!(
            s.contains("5 satoshis") && s.contains("10 are required"),
            "{s}"
        );
        let s = PaymentVerdict::RootMismatch {
            height: 42,
            root: "ab".into(),
        }
        .to_string();
        assert!(s.contains("height 42"), "{s}");
        let s = PaymentVerdict::NoHeaderService.to_string();
        assert!(
            s.contains("header service") && s.contains("structural_only"),
            "{s}"
        );
        let s = PaymentVerdict::Unverifiable {
            satoshis: 7,
            reason: "HTTP 503".into(),
        }
        .to_string();
        assert!(s.contains("not checked") && s.contains("HTTP 503"), "{s}");
        let boxed: Box<dyn std::error::Error> = Box::new(PaymentFault::BadBeef("x".into()));
        assert!(boxed.to_string().contains("incomplete"));
        let s = PaymentFault::MissingOutput {
            index: 3,
            output_count: 1,
        }
        .to_string();
        assert!(s.contains("index 3") && s.contains("1 outputs"), "{s}");
    }
}
