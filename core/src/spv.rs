//! The SPV decision, pure: what one merkle root's header lookup means, and
//! the loop over a proof's roots through a [`HeaderService`].

use std::collections::BTreeMap;

use bsv_sdk::transaction::Beef;

use crate::header_service::{HeaderService, MerkleRoot, ServiceError};
use crate::verdict::PaymentFault;

/// What one merkle root's header lookup means for the payment: the pure half
/// of SPV, pinned by table tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootDecision {
    /// The header at this height carries the proof's root: it ties to the chain.
    Match,
    /// The header at this height carries a DIFFERENT root: fraud, reject.
    Mismatch,
    /// The service could not answer (outage, timeout, HTTP error, height not
    /// yet indexed, unparseable body): the root goes unchecked; the carried
    /// reason names the height and the cause.
    Unanswered(String),
}

/// The per-root decision. `answer` is the header service's reply for
/// `height`: `Ok(Some(root))` compares case-insensitively, `Ok(None)` (no
/// header at that height yet) and `Err` are unanswered.
pub fn decide_root(
    height: u32,
    root: &str,
    answer: Result<Option<MerkleRoot>, ServiceError>,
) -> RootDecision {
    match answer {
        Ok(Some(header_root)) if header_root.matches(root) => RootDecision::Match,
        Ok(Some(_)) => RootDecision::Mismatch,
        Ok(None) => RootDecision::Unanswered(format!("no header at height {}", height)),
        Err(reason) => RootDecision::Unanswered(format!("height {}: {}", height, reason)),
    }
}

/// Parse the BEEF and check it is structurally complete: offline and
/// deterministic. Rejects missing inputs, txid-only gaps, and a proof chain
/// that does not verify. Returns the merkle roots the proofs compute, by
/// block height (lowest first), for SPV.
pub fn beef_roots(tx_bytes: &[u8]) -> Result<BTreeMap<u32, String>, PaymentFault> {
    let mut beef = Beef::from_binary(tx_bytes)
        .map_err(|e| PaymentFault::BadBeef(format!("BEEF parse: {}", e)))?;
    let validation = beef.verify_valid(false);
    if !validation.valid {
        return Err(PaymentFault::BadBeef(
            "missing inputs, txid-only gaps, or broken proof chain".to_string(),
        ));
    }
    Ok(validation.roots.into_iter().collect())
}

/// The outcome of checking every root of a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootsOutcome {
    /// Every root matched its header (or there was no root to check).
    AllMatched,
    /// A root differs from its header: the first mismatch, lowest height first.
    Mismatch { height: u32, root: String },
    /// No root mismatched, but at least one went unanswered; `reasons` lists
    /// every unanswered height.
    Unanswered { reasons: Vec<String> },
}

/// SPV over every root, lowest height first, through `service`. The first
/// mismatch decides (a mismatch at a later height is never masked by an
/// unanswered lookup at an earlier one); otherwise any unanswered root makes
/// the outcome [`RootsOutcome::Unanswered`].
pub async fn check_roots<H: HeaderService + ?Sized>(
    roots: &BTreeMap<u32, String>,
    service: &H,
) -> RootsOutcome {
    let mut reasons = Vec::new();
    for (height, root) in roots {
        match decide_root(*height, root, service.merkle_root(*height).await) {
            RootDecision::Match => {}
            RootDecision::Mismatch => {
                return RootsOutcome::Mismatch {
                    height: *height,
                    root: root.clone(),
                }
            }
            RootDecision::Unanswered(reason) => reasons.push(reason),
        }
    }
    if reasons.is_empty() {
        RootsOutcome::AllMatched
    } else {
        RootsOutcome::Unanswered { reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brc29::test_support::*;
    use crate::header_service::LookupFn;

    /// The per-root decision, as a table: match (case-insensitive) accepts,
    /// a different root rejects, an unparseable or empty root rejects, no
    /// header and a service error go unanswered with a reason naming the
    /// height and the cause.
    #[test]
    fn test_decide_root_table() {
        let root = |s: &str| Ok(Some(MerkleRoot::new(s)));
        assert_eq!(decide_root(7, "abcd", root("abcd")), RootDecision::Match);
        assert_eq!(decide_root(7, "abcd", root("ABCD")), RootDecision::Match);
        assert_eq!(decide_root(7, "abcd", root("abce")), RootDecision::Mismatch);
        assert_eq!(
            decide_root(7, "abcd", root("")),
            RootDecision::Mismatch,
            "an empty root from the service is not a match"
        );
        match decide_root(7, "abcd", Ok(None)) {
            RootDecision::Unanswered(reason) => assert!(reason.contains("height 7"), "{reason}"),
            other => panic!("expected Unanswered, got {other:?}"),
        }
        match decide_root(7, "abcd", Err(ServiceError::new("header service HTTP 503"))) {
            RootDecision::Unanswered(reason) => {
                assert!(reason.contains("height 7"), "{reason}");
                assert!(reason.contains("HTTP 503"), "{reason}");
            }
            other => panic!("expected Unanswered, got {other:?}"),
        }
    }

    /// The SPV loop over several roots: all matching accepts; one mismatch
    /// rejects naming its height and root; unanswered lookups collect their
    /// reasons; and an unanswered lookup at one height never masks a
    /// mismatch at another.
    #[tokio::test]
    async fn test_check_roots_table() {
        let roots: BTreeMap<u32, String> =
            BTreeMap::from([(100, "aa".to_string()), (200, "bb".to_string())]);
        let answer = |table: &'static [(u32, Result<&'static str, &'static str>)]| {
            LookupFn(move |height: u32| {
                let found = table
                    .iter()
                    .find(|(h, _)| *h == height)
                    .map(|(_, r)| {
                        r.map(|s| Some(MerkleRoot::new(s)))
                            .map_err(ServiceError::new)
                    })
                    .unwrap_or(Ok(None));
                async move { found }
            })
        };

        assert_eq!(
            check_roots(&roots, &answer(&[(100, Ok("aa")), (200, Ok("bb"))])).await,
            RootsOutcome::AllMatched
        );

        assert_eq!(
            check_roots(&roots, &answer(&[(100, Ok("aa")), (200, Ok("zz"))])).await,
            RootsOutcome::Mismatch {
                height: 200,
                root: "bb".into()
            }
        );

        match check_roots(
            &roots,
            &answer(&[(100, Err("timeout")), (200, Err("HTTP 503"))]),
        )
        .await
        {
            RootsOutcome::Unanswered { reasons } => {
                assert_eq!(reasons.len(), 2);
                assert!(reasons[0].contains("height 100") && reasons[0].contains("timeout"));
                assert!(reasons[1].contains("height 200") && reasons[1].contains("HTTP 503"));
            }
            other => panic!("expected Unanswered, got {other:?}"),
        }

        assert_eq!(
            check_roots(&roots, &answer(&[(100, Err("timeout")), (200, Ok("zz"))])).await,
            RootsOutcome::Mismatch {
                height: 200,
                root: "bb".into()
            },
            "an unanswered root never masks a mismatch"
        );

        match check_roots(&roots, &answer(&[(100, Ok("aa"))])).await {
            RootsOutcome::Unanswered { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert!(
                    reasons[0].contains("no header at height 200"),
                    "{reasons:?}"
                );
            }
            other => panic!("expected Unanswered, got {other:?}"),
        }

        assert_eq!(
            check_roots(&BTreeMap::new(), &answer(&[])).await,
            RootsOutcome::AllMatched,
            "no roots: nothing to check"
        );
    }

    #[test]
    fn test_beef_roots_reports_the_proof_and_refuses_the_unproven() {
        let (proven, txid) = beef_with_proven_payment(&our_script(), 1000);
        let roots = beef_roots(&proven).unwrap();
        assert_eq!(roots, BTreeMap::from([(PROOF_HEIGHT, txid)]));

        let unproven = beef_with_unproven_payment(&our_script(), 1000);
        assert!(matches!(
            beef_roots(&unproven),
            Err(PaymentFault::BadBeef(_))
        ));
        assert!(matches!(
            beef_roots(&[0u8; 16]),
            Err(PaymentFault::BadBeef(_))
        ));
    }
}
