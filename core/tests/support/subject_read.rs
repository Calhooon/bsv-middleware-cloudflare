// The differential pin's two sides: the linking read the payment check used
// through core 0.4.2 (`Transaction::from_beef(bytes, None)`, kept here and
// nowhere else) against the crate's `verify_payment_output` and
// `payment_subject_txid`. Shared by `payment_subject_read.rs` and
// `work_budget.rs` through `#[path]`.
use bsv_middleware_core::{
    expected_locking_script, payment_subject_txid, verify_payment_output, PaymentVerdict,
    UnverifiableReason,
};
use bsv_sdk::transaction::Transaction;

/// Who pays whom, at which output, for how much.
pub struct Terms<'a> {
    pub server_key: &'a str,
    pub sender: &'a str,
    pub prefix: &'a str,
    pub suffix: &'a str,
    pub output_index: usize,
    pub required: u64,
}

/// The linking read: the subject with its input ancestry linked.
pub fn linked_subject(bytes: &[u8]) -> Result<Transaction, bsv_sdk::Error> {
    Transaction::from_beef(bytes, None)
}

/// The output check over the linking read, as core 0.4.2 wrote it: script
/// first, then amount, at the named output only.
pub fn linked_verdict(terms: &Terms, bytes: &[u8]) -> PaymentVerdict {
    verdict_of(terms, linked_subject(bytes))
}

/// The output check over a subject a read answered.
fn verdict_of(terms: &Terms, read: Result<Transaction, bsv_sdk::Error>) -> PaymentVerdict {
    let expected =
        expected_locking_script(terms.server_key, terms.sender, terms.prefix, terms.suffix)
            .expect("the terms derive");
    let tx = match read {
        Ok(tx) => tx,
        Err(e) => {
            return PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::MalformedTransaction(e.to_string()),
            }
        }
    };
    let Some(output) = tx.outputs.get(terms.output_index) else {
        return PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::OutputMissing {
                output_index: u32::try_from(terms.output_index).unwrap_or(u32::MAX),
                output_count: tx.outputs.len(),
            },
        };
    };
    let actual = hex::encode(output.locking_script.to_binary());
    let paid = output.satoshis.unwrap_or(0);
    if actual != expected {
        PaymentVerdict::WrongScript { expected, actual }
    } else if paid < terms.required {
        PaymentVerdict::Underpaid {
            paid,
            required: terms.required,
        }
    } else {
        PaymentVerdict::Verified { satoshis: paid }
    }
}

/// How the two reads compared on one body.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    /// Bodies compared.
    pub bodies: usize,
    /// The linking read verified; the crate read the same txid and verdict.
    pub verified: usize,
    /// The linking read read a subject that does not pay (wrong script,
    /// underpaid, no such output); the crate read the same txid and verdict.
    pub read_not_paying: usize,
    /// Neither read a subject; the same refusal, word for word.
    pub both_refused: usize,
    /// The linking read refused the body at its link bound; the crate read
    /// the subject.
    pub link_bound_only: usize,
}

impl Tally {
    pub fn add(&mut self, other: Tally) {
        self.bodies += other.bodies;
        self.verified += other.verified;
        self.read_not_paying += other.read_not_paying;
        self.both_refused += other.both_refused;
        self.link_bound_only += other.link_bound_only;
    }
}

/// Compare the two reads on one body. Wherever the linking read read a
/// subject, the crate reads the same txid and the same verdict; wherever it
/// refused, the crate refuses with the same reason, except a refusal at the
/// link bound, where the crate reads the subject the bytes name.
pub fn compare(label: &str, terms: &Terms, bytes: &[u8]) -> Tally {
    let verdict = verify_payment_output(
        terms.server_key,
        terms.sender,
        terms.prefix,
        terms.suffix,
        bytes,
        terms.output_index,
        terms.required,
    )
    .expect("the server key derives");
    let txid = payment_subject_txid(bytes);
    let mut tally = Tally {
        bodies: 1,
        ..Tally::default()
    };
    match linked_subject(bytes) {
        Ok(linked) => {
            assert_eq!(txid.as_deref(), Ok(linked.id().as_str()), "{label}: txid");
            let before = linked_verdict(terms, bytes);
            assert_eq!(verdict, before, "{label}: verdict");
            if matches!(verdict, PaymentVerdict::Verified { .. }) {
                tally.verified = 1;
            } else {
                tally.read_not_paying = 1;
            }
        }
        Err(bsv_sdk::Error::BeefResourceLimit(_)) => {
            let subject = Transaction::from_beef_subject(bytes, None)
                .unwrap_or_else(|e| panic!("{label}: the subject reads: {e}"));
            assert_eq!(txid.as_deref(), Ok(subject.id().as_str()), "{label}");
            assert_eq!(verdict, verdict_of(terms, Ok(subject)), "{label}");
            tally.link_bound_only = 1;
        }
        Err(e) => {
            let reason = UnverifiableReason::MalformedTransaction(e.to_string());
            assert_eq!(txid, Err(reason.clone()), "{label}: refusal");
            assert_eq!(
                verdict,
                PaymentVerdict::Unverifiable { reason },
                "{label}: refusal"
            );
            tally.both_refused = 1;
        }
    }
    tally
}
