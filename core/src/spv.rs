//! The SPV decision, pure: what one merkle root's header lookup means, and
//! the loop over a proof's roots through a [`HeaderService`].
//!
//! The roots come from the streaming reader
//! ([`verify_brc29_payment`](crate::verify_brc29_payment) reads them with
//! every root granted and asks them here afterwards, lowest height first);
//! nothing in this module parses a BEEF.

use crate::header_service::{HeaderService, MerkleRoot, ServiceError};

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
    /// reason is the cause as the service said it.
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
        Err(reason) => RootDecision::Unanswered(reason.reason().to_string()),
    }
}

/// The outcome of checking every root of a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootsOutcome {
    /// Every root matched its header (or there was no root to check).
    AllMatched,
    /// A root differs from its header: the first mismatch, lowest height first.
    Mismatch { height: u32, root: String },
    /// No root mismatched, but at least one went unanswered: the lowest such
    /// height and what the service said for it.
    Unanswered { height: u32, reason: String },
}

/// SPV over every root, lowest height first, through `service`. `roots` is
/// `(height, root hex)` pairs sorted by height (two BUMPs that claim one
/// height with two roots are two questions, and one of them is a mismatch).
/// The first mismatch decides (a mismatch at a later height is never masked
/// by an unanswered lookup at an earlier one); otherwise the lowest
/// unanswered root makes the outcome [`RootsOutcome::Unanswered`].
pub async fn check_roots<H: HeaderService + ?Sized>(
    roots: &[(u32, String)],
    service: &H,
) -> RootsOutcome {
    let mut first_unanswered: Option<(u32, String)> = None;
    for (height, root) in roots {
        match decide_root(*height, root, service.merkle_root(*height).await) {
            RootDecision::Match => {}
            RootDecision::Mismatch => {
                return RootsOutcome::Mismatch {
                    height: *height,
                    root: root.clone(),
                }
            }
            RootDecision::Unanswered(reason) => {
                first_unanswered.get_or_insert((*height, reason));
            }
        }
    }
    match first_unanswered {
        None => RootsOutcome::AllMatched,
        Some((height, reason)) => RootsOutcome::Unanswered { height, reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_service::LookupFn;

    /// The per-root decision, as a table: match (case-insensitive) accepts,
    /// a different root rejects, an unparseable or empty root rejects, no
    /// header and a service error go unanswered with the cause.
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
        assert_eq!(
            decide_root(7, "abcd", Err(ServiceError::new("header service HTTP 503"))),
            RootDecision::Unanswered("header service HTTP 503".into()),
            "the service's own words, the height carried beside them"
        );
    }

    /// The SPV loop over several roots: all matching accepts; one mismatch
    /// rejects naming its height and root; unanswered lookups report the
    /// lowest height and its cause; an unanswered lookup at one height never
    /// masks a mismatch at another; two roots at one height are two
    /// questions.
    #[tokio::test]
    async fn test_check_roots_table() {
        let roots: Vec<(u32, String)> = vec![(100, "aa".to_string()), (200, "bb".to_string())];
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

        assert_eq!(
            check_roots(
                &roots,
                &answer(&[(100, Err("timeout")), (200, Err("HTTP 503"))]),
            )
            .await,
            RootsOutcome::Unanswered {
                height: 100,
                reason: "timeout".into()
            },
            "the lowest unanswered height, with what the service said"
        );

        assert_eq!(
            check_roots(&roots, &answer(&[(100, Err("timeout")), (200, Ok("zz"))])).await,
            RootsOutcome::Mismatch {
                height: 200,
                root: "bb".into()
            },
            "an unanswered root never masks a mismatch"
        );

        match check_roots(&roots, &answer(&[(100, Ok("aa"))])).await {
            RootsOutcome::Unanswered { height, reason } => {
                assert_eq!(height, 200);
                assert!(reason.contains("no header at height 200"), "{reason}");
            }
            other => panic!("expected Unanswered, got {other:?}"),
        }

        assert_eq!(
            check_roots(&[], &answer(&[])).await,
            RootsOutcome::AllMatched,
            "no roots: nothing to check"
        );

        let two_at_one_height = vec![(100, "aa".to_string()), (100, "cc".to_string())];
        assert_eq!(
            check_roots(&two_at_one_height, &answer(&[(100, Ok("aa"))])).await,
            RootsOutcome::Mismatch {
                height: 100,
                root: "cc".into()
            },
            "two roots at one height are two questions; the one the header does not carry is a mismatch"
        );
    }
}
