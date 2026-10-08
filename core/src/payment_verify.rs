//! BRC-29 payment verification before internalize: pays-us-correctly
//! **and** real-and-confirmable, answered in the six words.
//!
//! [`verify_brc29_payment`] runs, in order:
//!   0. the service gate: `None` is
//!      [`NoHeaderService`](PaymentVerdict::NoHeaderService), before any
//!      other work, so a deployment with no header service never looks like
//!      one that verifies;
//!   1. script + amount ([`verify_payment_output`]):
//!      the output pays the server's derived key at least `required_satoshis`
//!      ([`WrongScript`](PaymentVerdict::WrongScript),
//!      [`Underpaid`](PaymentVerdict::Underpaid));
//!   2. BEEF structural completeness ([`beef_roots`]):
//!      missing inputs, txid-only gaps and a broken proof chain are a
//!      [`PaymentFault::BadBeef`];
//!   3. SPV through the [`HeaderService`]: a root that differs from its
//!      header is [`RootMismatch`](PaymentVerdict::RootMismatch); a root the
//!      service could not answer makes the verdict
//!      [`Unverifiable`](PaymentVerdict::Unverifiable), a refusal (the host
//!      fails closed: rule of 2026-10-08); every root matched is
//!      [`Verified`](PaymentVerdict::Verified).
//!
//! [`verify_brc29_payment_structural_only`] is the named opt-out: steps 1 and
//! 2 only. A proof with roots is answered `Unverifiable` with a reason that
//! says they went unchecked by choice. That is the one `Unverifiable` a host
//! may serve on, and only because its caller named the opt-out; through
//! [`verify_brc29_payment`] the same word is always a refusal.

use crate::brc29::verify_payment_output;
use crate::header_service::HeaderService;
use crate::spv::{beef_roots, check_roots, RootsOutcome};
use crate::verdict::{PaymentFault, PaymentVerdict};

/// Full pre-service payment verification: pays-us-correctly **and**
/// real-and-confirmable, through `service`. See the module docs for the
/// order of checks. `None` is `NoHeaderService` (fail closed); a service
/// that cannot answer for a root is `Unverifiable` (fail closed as well: the
/// host refuses and keeps the quote).
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment<H: HeaderService + ?Sized>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    service: Option<&H>,
) -> Result<PaymentVerdict, PaymentFault> {
    // 0. No header service, no verdict: refuse before any other work.
    let Some(service) = service else {
        return Ok(PaymentVerdict::NoHeaderService);
    };

    // 1. Cheap, offline, deterministic: does it pay us the quoted amount?
    let satoshis = match verify_payment_output(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )? {
        PaymentVerdict::Verified { satoshis } => satoshis,
        refusal => return Ok(refusal),
    };

    // 2. Is the payment real and confirmable? (structural, then SPV)
    let roots = beef_roots(tx_bytes)?;
    Ok(match check_roots(&roots, service).await {
        RootsOutcome::AllMatched => PaymentVerdict::Verified { satoshis },
        RootsOutcome::Mismatch { height, root } => PaymentVerdict::RootMismatch { height, root },
        RootsOutcome::Unanswered { reasons } => PaymentVerdict::Unverifiable {
            satoshis,
            reason: format!(
                "the header service could not answer for {} root(s): {}",
                reasons.len(),
                reasons.join("; ")
            ),
        },
    })
}

/// [`verify_brc29_payment`] **without SPV**: script + amount and BEEF
/// structural completeness only. The merkle roots in the proof are NOT
/// checked against block headers.
///
/// **Opt-in, by name, for hosts that have no header service.** A
/// structurally valid BEEF only proves its merkle paths compute *some* root,
/// so a forged parent transaction with a made-up proof passes this function
/// and is caught only by whatever the host's broadcast or internalize step
/// does later. A proof carrying roots is therefore answered
/// [`Unverifiable`](PaymentVerdict::Unverifiable), never
/// [`Verified`](PaymentVerdict::Verified), so the skip is visible in the
/// word; a host that serves on this answer does so because its caller named
/// this function. A proof with no root to check is `Verified`, as it would
/// be through a service.
pub fn verify_brc29_payment_structural_only(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> Result<PaymentVerdict, PaymentFault> {
    let satoshis = match verify_payment_output(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )? {
        PaymentVerdict::Verified { satoshis } => satoshis,
        refusal => return Ok(refusal),
    };
    let roots = beef_roots(tx_bytes)?;
    if roots.is_empty() {
        return Ok(PaymentVerdict::Verified { satoshis });
    }
    Ok(PaymentVerdict::Unverifiable {
        satoshis,
        reason: format!(
            "structural-only verification: {} merkle root(s) NOT checked against block headers (no SPV)",
            roots.len()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brc29::test_support::*;
    use crate::header_service::{LookupFn, MerkleRoot, NoService, ServiceError};
    use std::cell::RefCell;

    /// The full verification of a correct, proven 1000-sat payment with the
    /// header service replaced by `answer` (the same answer at every height);
    /// also returns the heights the service was asked for.
    async fn verify_proven_with(
        answer: Result<Option<MerkleRoot>, ServiceError>,
    ) -> (Result<PaymentVerdict, PaymentFault>, Vec<u32>) {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let asked = RefCell::new(Vec::new());
        let service = LookupFn(|height| {
            asked.borrow_mut().push(height);
            let answer = answer.clone();
            async move { answer }
        });
        let result = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&service),
        )
        .await;
        (result, asked.into_inner())
    }

    /// The full check: a transaction that pays us correctly but whose BEEF
    /// carries no ancestry/proof is refused as `BadBeef` (never reaches the
    /// header service), so a bare, unconfirmable payment cannot buy service.
    #[tokio::test]
    async fn test_unproven_beef_fails_full_verification() {
        let beef = beef_with_unproven_payment(&our_script(), 1000);
        let service = LookupFn(|_| async { panic!("the service must not be asked") });
        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&service),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PaymentFault::BadBeef(_)), "{err}");
    }

    /// Step 1 (script + amount) runs before any BEEF/SPV work, so garbage
    /// bytes surface as `BadTransaction` without a lookup.
    #[tokio::test]
    async fn test_full_verification_bad_bytes_rejected_offline() {
        let service = LookupFn(|_| async { panic!("the service must not be asked") });
        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
            Some(&service),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PaymentFault::BadTransaction(_)));
    }

    /// A refusal from step 1 is the word, and the service is never asked.
    #[tokio::test]
    async fn test_full_verification_refuses_before_spv() {
        let service = LookupFn(|_| async { panic!("the service must not be asked") });
        let (underpaid, _) = beef_with_proven_payment(&our_script(), 999);
        let verdict = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &underpaid,
            0,
            1000,
            Some(&service),
        )
        .await
        .unwrap();
        assert_eq!(
            verdict,
            PaymentVerdict::Underpaid {
                paid: 999,
                required: 1000
            }
        );
    }

    /// End to end on a correct, proven payment with the header service
    /// stubbed: the service is asked exactly once, at the proof's height; a
    /// matching header is `Verified`, a different one is `RootMismatch`
    /// naming the height and root, and a service that cannot answer is
    /// `Unverifiable` carrying the amount and the reason.
    #[tokio::test]
    async fn test_full_verification_spv_outcomes_table() {
        let (_, txid) = beef_with_proven_payment(&our_script(), 1000);

        let (ok, asked) = verify_proven_with(Ok(Some(MerkleRoot::new(txid.clone())))).await;
        assert_eq!(ok.unwrap(), PaymentVerdict::Verified { satoshis: 1000 });
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (ok, _) =
            verify_proven_with(Ok(Some(MerkleRoot::new(txid.to_ascii_uppercase())))).await;
        assert_eq!(
            ok.unwrap(),
            PaymentVerdict::Verified { satoshis: 1000 },
            "root compare is case-insensitive"
        );

        let (verdict, asked) = verify_proven_with(Ok(Some(MerkleRoot::new("00".repeat(32))))).await;
        assert_eq!(
            verdict.unwrap(),
            PaymentVerdict::RootMismatch {
                height: PROOF_HEIGHT,
                root: txid.clone()
            }
        );
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (verdict, asked) =
            verify_proven_with(Err(ServiceError::new("fetch height: timeout"))).await;
        match verdict.unwrap() {
            PaymentVerdict::Unverifiable { satoshis, reason } => {
                assert_eq!(satoshis, 1000);
                assert!(reason.contains("timeout"), "{reason}");
                assert!(reason.contains(&PROOF_HEIGHT.to_string()), "{reason}");
            }
            other => panic!("expected Unverifiable, got {other:?}"),
        }
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (verdict, _) = verify_proven_with(Ok(None)).await;
        assert!(
            matches!(
                verdict.unwrap(),
                PaymentVerdict::Unverifiable { satoshis: 1000, .. }
            ),
            "a height the service has not indexed is unanswered"
        );
    }

    /// `verify_brc29_payment` with no service is `NoHeaderService` for a
    /// payment that would otherwise pass: never `Verified`, never a skipped
    /// root check. The gate runs before step 1, so garbage bytes under a
    /// missing service are also `NoHeaderService`.
    #[tokio::test]
    async fn test_full_verification_without_header_service_fails_closed() {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let verdict = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            None::<&NoService>,
        )
        .await
        .unwrap();
        assert_eq!(verdict, PaymentVerdict::NoHeaderService);

        let verdict = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
            None::<&NoService>,
        )
        .await
        .unwrap();
        assert_eq!(
            verdict,
            PaymentVerdict::NoHeaderService,
            "the gate runs first"
        );

        // `Some(&NoService)` by mistake: every root goes unchecked, never Verified.
        let verdict = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(&NoService),
        )
        .await
        .unwrap();
        assert!(
            matches!(verdict, PaymentVerdict::Unverifiable { .. }),
            "{verdict:?}"
        );
    }

    /// The named opt-out keeps every offline check (script, amount, BEEF
    /// structure) and answers a proof with roots `Unverifiable`, by name.
    #[test]
    fn test_structural_only_keeps_offline_checks_and_names_the_skip() {
        let (proven, _) = beef_with_proven_payment(&our_script(), 1000);
        match verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &proven,
            0,
            1000,
        )
        .unwrap()
        {
            PaymentVerdict::Unverifiable { satoshis, reason } => {
                assert_eq!(satoshis, 1000);
                assert!(reason.contains("structural-only"), "{reason}");
                assert!(reason.contains("1 merkle root"), "{reason}");
            }
            other => panic!("expected Unverifiable, got {other:?}"),
        }

        let unproven = beef_with_unproven_payment(&our_script(), 1000);
        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &unproven,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentFault::BadBeef(_)), "{err}");

        let (underpaid, _) = beef_with_proven_payment(&our_script(), 999);
        let verdict = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &underpaid,
            0,
            1000,
        )
        .unwrap();
        assert!(
            matches!(verdict, PaymentVerdict::Underpaid { .. }),
            "{verdict:?}"
        );

        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentFault::BadTransaction(_)), "{err}");
    }
}
