//! BRC-29 payment verification before internalize: the Workers adapter over
//! `bsv_middleware_core`.
//!
//! The rules live in the core: the pays-us-correctly check
//! ([`bsv_middleware_core::brc29`]), BEEF completeness and the SPV decision
//! ([`bsv_middleware_core::spv`]), and the six-word verdict
//! ([`PaymentVerdict`]). This module keeps what is bound to this runtime and
//! to the 0.3 API:
//!
//! - [`UrlHeaderService`]: the core's [`HeaderService`] over a
//!   ChainTracks-compatible base URL fetched with Workers `fetch`, behind the
//!   0.3.6 configuration gate (below);
//! - [`PaymentVerifyError`], the 0.3 error type, and [`accept_verdict`], the
//!   one visible match that maps the core's words onto it;
//! - the 0.3 functions, name for name and signature for signature.
//!
//! ## What the words map to (0.4 policy)
//!
//! | core | adapter |
//! |---|---|
//! | `Verified { satoshis }` | `Ok(satoshis)` |
//! | `Unverifiable { satoshis, reason }` | `Ok(satoshis)`, warning logged (**fail-open**, see below) |
//! | `Underpaid { paid, required }` | `Err(Underpaid { satoshis: paid, required })` |
//! | `WrongScript { expected, actual }` | `Err(WrongScript { expected, actual })` |
//! | `NoHeaderService` | `Err(NoHeaderService)` |
//! | `RootMismatch { height, root }` | `Err(RootMismatch { height, root })` |
//! | `PaymentFault::BadTransaction` / `MissingOutput` / `KeyDerivation` / `BadBeef` | the same-named `Err` |
//!
//! **Fail-open on a service error stays this adapter's documented policy in
//! 0.4**, unchanged from 0.3.6: once a header service is named, a lookup it
//! cannot answer (unreachable, HTTP error, unparseable body, height not yet
//! indexed) still accepts the payment with a logged warning, the upstream
//! broadcast as the backstop. The core hands that case to the host as the
//! word `Unverifiable`; hosts that want to decide it themselves call the
//! core (or [`verify_brc29_payment_verdict`]) and match the word. A root
//! that differs from the header is `RootMismatch`, fail-closed, as before.
//!
//! ## Header service: required
//!
//! This crate ships **no** header service of its own, and it never skips SPV
//! silently. `header_url` must name your own ChainTracks-compatible service
//! (for example a ChainTracks deployment you run). `None`, an empty string,
//! [`DEFAULT_CHAINTRACKS_URL`], any other `.invalid` host, a value without
//! an `http://` / `https://` scheme, or a value whose host the gate cannot
//! classify as a real hostname is refused with
//! [`PaymentVerifyError::NoHeaderService`] BEFORE anything else is checked, so
//! a misconfigured deployment rejects every payment loudly instead of
//! accepting unverified ones. The host is normalised (lowercased, trailing
//! dot stripped) before the placeholder comparison, and spellings that would
//! need a URL parser to decode or rewrite (percent-encoding, backslashes,
//! userinfo, whitespace, non-ASCII) are refused rather than guessed at, so
//! no spelling of the placeholder reaches DNS and fails open. Adopters that
//! truly have no header service opt out *by name* with
//! [`verify_brc29_payment_structural_only`].
//!
//! | `header_url` | outcome |
//! |---|---|
//! | `None`, `Some("")`, whitespace only | `Err(NoHeaderService)` |
//! | the `.invalid` placeholder (trailing slash or dot or not, any case), any `.invalid` host | `Err(NoHeaderService)` |
//! | no `http://` / `https://` scheme, no host | `Err(NoHeaderService)` |
//! | userinfo (`@`), `%`, `\`, whitespace, control or non-ASCII characters, a non-numeric port, a label that is not a hostname | `Err(NoHeaderService)` |
//! | service unreachable, HTTP error, unparseable answer | `Ok`, warning logged (fail-open) |
//! | the header at that height carries a different root | `Err(RootMismatch)` (fail-closed) |
//! | the header carries the proof's root | `Ok(satoshis)` |
//!
//! The configuration gate (`resolve_header_service`) is a pure function,
//! pinned by table tests; the per-root decision is the core's
//! (`bsv_middleware_core::spv::decide_root`), pinned there.
//!
//! ## Relation to the payment middleware
//!
//! [`process_payment_with_storage`](crate::process_payment_with_storage)
//! verifies the derivation-prefix HMAC, runs [`verify_brc29_payment_output`]
//! on output 0 (script and amount; 0.3.7), consumes the prefix once, and
//! hands the transaction to the wallet storage server. The storage server's
//! `internalizeAction` checks neither the script nor the amount (the
//! reference keeps the script check in its signer, which is not on this
//! path), so the middleware's check is the only one on it. The middleware
//! does not run BEEF structure or SPV. The full [`verify_brc29_payment`] is
//! for callers that run their **own** payment flow (a custom 402 handler, a
//! pre-charge + refund model, a non-wallet settlement path) and want, locally
//! and before any remote call, an output that pays this server's derived key,
//! carrying at least the quoted satoshis, inside a complete proof.

use std::future::Future;

use bsv_middleware_core::{
    HeaderService, LookupFn, MerkleRoot, PaymentFault, PaymentVerdict, ServiceError,
};
use serde::Deserialize;

/// Placeholder header-service base URL: **never a working default.**
///
/// `.invalid` is a reserved top-level domain (RFC 2606) that never resolves.
/// [`verify_brc29_payment`] refuses this value, and every other `.invalid`
/// host, with [`PaymentVerifyError::NoHeaderService`]; the constant exists so
/// a configuration that was never filled in reads as such. Point `header_url`
/// at your own service, one that answers
/// `GET {base}/findHeaderHexForHeight?height={h}` with
/// `{"status":"success","value":{"merkleRoot":"<hex>", ...}}`.
pub const DEFAULT_CHAINTRACKS_URL: &str = "https://chaintracks.invalid";

/// Errors from BRC-29 payment verification.
///
/// Every variant means: reject without internalizing, and no refund is owed
/// (no funds were accepted). Most are client-fault, a 400/402-class answer.
/// Two are the SERVER's own: [`NoHeaderService`](Self::NoHeaderService) (no
/// usable `header_url`) and a [`KeyDerivation`](Self::KeyDerivation) error
/// naming the server key; answer those 500-class and fix the deployment.
///
/// Since 0.4.0 this is the adapter's rendering of the core's
/// [`PaymentVerdict`] and [`PaymentFault`] (see the module docs for the
/// mapping); the variants and their messages are the 0.3 ones.
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
    /// No usable header service was configured (`header_url` was `None`,
    /// empty, the `.invalid` placeholder, or not an `http(s)://` URL), so SPV
    /// cannot run. Fail-closed: a deployment misconfiguration, never a silent
    /// skip. Pass your own header service, or opt out of SPV by name with
    /// [`verify_brc29_payment_structural_only`].
    NoHeaderService,
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
            PaymentVerifyError::NoHeaderService => write!(
                f,
                "No header service configured for SPV: pass your own ChainTracks-compatible base URL as header_url, or opt out by name with verify_brc29_payment_structural_only"
            ),
        }
    }
}

impl std::error::Error for PaymentVerifyError {}

/// The core's faults, variant for variant.
impl From<PaymentFault> for PaymentVerifyError {
    fn from(fault: PaymentFault) -> Self {
        match fault {
            PaymentFault::BadTransaction(m) => PaymentVerifyError::BadTransaction(m),
            PaymentFault::MissingOutput {
                index,
                output_count,
            } => PaymentVerifyError::MissingOutput {
                index,
                output_count,
            },
            PaymentFault::KeyDerivation(m) => PaymentVerifyError::KeyDerivation(m),
            PaymentFault::BadBeef(m) => PaymentVerifyError::BadBeef(m),
        }
    }
}

/// The one visible match that collapses the core's words to
/// this adapter's 0.3 result: `Verified` is `Ok(satoshis)`; `Unverifiable` is
/// `Ok(satoshis)` with the reason logged as a warning (the adapter's
/// documented **fail-open** policy in 0.4; see the module docs); every other
/// word is the same-named `Err`.
pub fn accept_verdict(verdict: PaymentVerdict) -> std::result::Result<u64, PaymentVerifyError> {
    match verdict {
        PaymentVerdict::Verified { satoshis } => Ok(satoshis),
        PaymentVerdict::Unverifiable { satoshis, reason } => {
            warn_log(&format!(
                "[payment_verify] SPV fail-open (accepting {} satoshis): {}",
                satoshis, reason
            ));
            Ok(satoshis)
        }
        PaymentVerdict::Underpaid { paid, required } => Err(PaymentVerifyError::Underpaid {
            satoshis: paid,
            required,
        }),
        PaymentVerdict::WrongScript { expected, actual } => {
            Err(PaymentVerifyError::WrongScript { expected, actual })
        }
        PaymentVerdict::NoHeaderService => Err(PaymentVerifyError::NoHeaderService),
        PaymentVerdict::RootMismatch { height, root } => {
            Err(PaymentVerifyError::RootMismatch { height, root })
        }
    }
}

// ─── Header-service configuration (pure) ────────────────────────────

/// The normalised host of an `http://` / `https://` base URL, or `None` when
/// the value cannot be classified as such a URL naming a real host.
///
/// This is deliberately stricter than a WHATWG URL parse. The gate compares
/// the host against the `.invalid` placeholder, so any spelling that a URL
/// parser would decode or rewrite into a different host than this function
/// sees could slip past that comparison and then fail open at lookup time
/// (a trailing-dot FQDN, a percent-encoded dot, a backslash before an `@`).
/// The rule is therefore: normalise what can be normalised, refuse what
/// would need decoding, and never guess. After the scheme:
///
/// - the authority is the text up to the first `/`, `?` or `#`;
/// - the whole value must be free of `\`, whitespace and control characters;
/// - the authority must be ASCII and carry no `@` (userinfo: the Fetch
///   standard rejects URL credentials, so an `@` can only be a trick) and
///   no `%` (the gate does not decode, so it accepts nothing that needs it);
/// - the host is either a bracketed IPv6 literal that `Ipv6Addr` parses, or
///   dot-separated labels of ASCII letters, digits and hyphens (no hyphen at
///   a label's ends), with one optional trailing dot (the FQDN marker);
/// - an optional `:port` is a run of decimal digits that fits in 16 bits.
///
/// The host comes back lowercased, without the port, with the trailing dot
/// stripped and an IPv6 literal unbracketed, so the `.invalid` test sees one
/// spelling of each host.
fn header_service_host(base: &str) -> Option<String> {
    if base
        .chars()
        .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (scheme, rest) = base.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || !authority.is_ascii() || authority.contains(['@', '%']) {
        return None;
    }
    let (host, port_suffix) = match authority.strip_prefix('[') {
        Some(after_bracket) => {
            let (literal, after) = after_bracket.split_once(']')?;
            literal.parse::<std::net::Ipv6Addr>().ok()?;
            (literal, after)
        }
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    match port_suffix.strip_prefix(':') {
        Some(port) => {
            if port.is_empty()
                || !port.bytes().all(|b| b.is_ascii_digit())
                || port.parse::<u16>().is_err()
            {
                return None;
            }
        }
        None if port_suffix.is_empty() => {}
        None => return None,
    }
    let host = host.to_ascii_lowercase();
    if authority.starts_with('[') {
        return Some(host);
    }
    let name = host.strip_suffix('.').unwrap_or(&host);
    let label_ok = |label: &str| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if name.is_empty() || !name.split('.').all(label_ok) {
        return None;
    }
    Some(name.to_string())
}

/// The pure configuration gate: the base URL SPV will query, or
/// [`PaymentVerifyError::NoHeaderService`].
///
/// Trims surrounding whitespace and trailing slashes, then refuses `None`,
/// the empty string, anything [`header_service_host`] cannot classify as an
/// `http://` / `https://` URL naming a real host (no scheme, no host,
/// userinfo, percent-encoding, backslashes, whitespace, a port that is not a
/// number, labels that are not a hostname), and any host that normalises
/// (lowercased, trailing dot stripped) to the reserved `.invalid` TLD, which
/// covers [`DEFAULT_CHAINTRACKS_URL`] in any case, with or without a trailing
/// slash or dot. The normalisation runs BEFORE the placeholder comparison, so
/// no spelling of the placeholder reaches DNS. A real but wrong host is NOT
/// caught here: that surfaces as a service error at lookup time and fails
/// open, by design (see the module docs).
fn resolve_header_service(
    header_url: Option<&str>,
) -> std::result::Result<&str, PaymentVerifyError> {
    let base = header_url
        .map(str::trim)
        .unwrap_or("")
        .trim_end_matches('/');
    if base.is_empty() {
        return Err(PaymentVerifyError::NoHeaderService);
    }
    let host = header_service_host(base).ok_or(PaymentVerifyError::NoHeaderService)?;
    if host == "invalid" || host.ends_with(".invalid") {
        return Err(PaymentVerifyError::NoHeaderService);
    }
    Ok(base)
}

// ─── The URL-configured header service ──────────────────────────────

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

/// The network half of the header lookup: the merkle root the header service
/// reports for the block at `height`, or why it could not answer.
async fn fetch_header_root(base_url: &str, height: u32) -> std::result::Result<String, String> {
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
    parse_header_response(&body, height)
}

/// The core's [`HeaderService`] over a ChainTracks-compatible base URL,
/// fetched with Workers `fetch`: `GET {base}/findHeaderHexForHeight?height={h}`.
///
/// Built only through [`UrlHeaderService::resolve`], which is the 0.3.6
/// configuration gate: a value the gate refuses (see the module docs) is
/// `Err(NoHeaderService)`, so no unclassifiable URL ever becomes a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlHeaderService {
    base_url: String,
}

impl UrlHeaderService {
    /// The gate: a header service for `header_url`, or
    /// [`PaymentVerifyError::NoHeaderService`] for every shape of "no
    /// service" (`None`, blank, the `.invalid` placeholder in any spelling, no
    /// `http(s)://` scheme, a host the gate cannot classify).
    pub fn resolve(header_url: Option<&str>) -> std::result::Result<Self, PaymentVerifyError> {
        let base = resolve_header_service(header_url)?;
        Ok(Self {
            base_url: base.to_string(),
        })
    }

    /// The base URL SPV queries: trimmed, without trailing slashes.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl HeaderService for UrlHeaderService {
    async fn merkle_root(
        &self,
        height: u32,
    ) -> std::result::Result<Option<MerkleRoot>, ServiceError> {
        fetch_header_root(&self.base_url, height)
            .await
            .map(|root| Some(MerkleRoot::new(root)))
            .map_err(ServiceError::new)
    }
}

/// Logs through the Workers console on wasm32; a no-op under native tests.
fn warn_log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

// ─── The 0.3 functions over the core ────────────────────────────────

/// Compute the P2PKH locking script (hex) the sender must have paid for a
/// BRC-29 payment to (`server_key`, `sender_identity_key`, prefix, suffix)
/// (`bsv_middleware_core::brc29::expected_locking_script`).
pub fn expected_brc29_locking_script(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
) -> std::result::Result<String, PaymentVerifyError> {
    Ok(bsv_middleware_core::expected_locking_script(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
    )?)
}

/// Verify that output `output_index` of the BEEF-encoded payment transaction
/// pays the server's BRC-29 derived key at least `required_satoshis`
/// (`bsv_middleware_core::brc29::verify_payment_output`, rendered through
/// [`accept_verdict`]).
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
    accept_verdict(bsv_middleware_core::verify_payment_output(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )?)
}

/// The core's verdict on a payment through `service`
/// (`bsv_middleware_core::verify_brc29_payment`), for callers that want to
/// decide the words themselves (in particular `Unverifiable`) instead of
/// taking this adapter's [`accept_verdict`] policy. `None` is
/// `NoHeaderService`.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_verdict<H: HeaderService + ?Sized>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    service: Option<&H>,
) -> std::result::Result<PaymentVerdict, PaymentVerifyError> {
    Ok(bsv_middleware_core::verify_brc29_payment(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        service,
    )
    .await?)
}

/// Steps 1 and 2 of [`verify_brc29_payment`] with the header lookup supplied
/// by the caller instead of a `header_url`: script + amount, BEEF structure,
/// then SPV through `lookup`.
///
/// `lookup(height)` is your header service: `Ok(merkle_root_hex)` for the
/// block at `height` (compared case-insensitively; a different root is
/// [`PaymentVerifyError::RootMismatch`], fail-closed) or `Err(reason)` when it
/// cannot answer (fail-open: the payment is accepted and a warning logged).
/// There is no configuration gate here, since there is no URL to check: a
/// lookup that always errors makes this the structural-only check. For a
/// service binding, a cached header store, or a conformance runner
/// (`conformance/brc29-payment-vectors.json`) that answers from a fixture.
#[allow(clippy::too_many_arguments)]
pub async fn verify_brc29_payment_with_header_lookup<F, Fut>(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
    lookup: F,
) -> std::result::Result<u64, PaymentVerifyError>
where
    F: Fn(u32) -> Fut,
    Fut: Future<Output = std::result::Result<String, String>>,
{
    let service = LookupFn(|height| {
        let answer = lookup(height);
        async move {
            answer
                .await
                .map(|root| Some(MerkleRoot::new(root)))
                .map_err(ServiceError::new)
        }
    });
    let verdict = verify_brc29_payment_verdict(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        Some(&service),
    )
    .await?;
    accept_verdict(verdict)
}

/// Full pre-service payment verification: pays-us-correctly **and**
/// real-and-confirmable. Call this AFTER nonce/quote verification and BEFORE
/// `internalizeAction`; on `Ok` the payment is safe to internalize and serve,
/// on `Err` reject without serving (no funds accepted, so no refund is owed).
///
/// Runs, in order:
///   0. configuration gate: `header_url` must name a header service (below).
///   1. script + amount ([`verify_brc29_payment_output`]): the output pays the
///      server's derived key at least `required_satoshis`.
///   2. BEEF structural completeness + SPV: the proof chain is complete and
///      each merkle root matches a real block header.
///
/// **`header_url` is required.** Pass the base URL of your own
/// ChainTracks-compatible header service (for example a ChainTracks deployment
/// you run). `None`, `Some("")`, [`DEFAULT_CHAINTRACKS_URL`], any `.invalid`
/// host (in any case, with or without a trailing dot), a value without an
/// `http(s)://` scheme, or a value whose host cannot be classified as a real
/// hostname (userinfo, percent-encoding, backslashes, whitespace) returns
/// [`PaymentVerifyError::NoHeaderService`] before any other check: fail-closed,
/// never a silent skip. Once a service is named, SPV is fail-open on a service
/// error (unreachable, HTTP error, unparseable answer: accept and warn) and
/// fail-closed on a root mismatch. Adopters with no header service opt out of
/// SPV by name with [`verify_brc29_payment_structural_only`].
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
    // 0. No header service, no verdict: the gate classifies the URL, and the
    //    core refuses `None` before any other work, so a misconfigured
    //    deployment never looks like one that verifies.
    let service = UrlHeaderService::resolve(header_url).ok();
    let verdict = verify_brc29_payment_verdict(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
        service.as_ref(),
    )
    .await?;
    accept_verdict(verdict)
}

/// [`verify_brc29_payment`] **without SPV**: script + amount and BEEF
/// structural completeness only. The merkle roots in the proof are NOT
/// checked against block headers.
///
/// **Opt-in, by name, for adopters that have no header service.** Prefer
/// [`verify_brc29_payment`] with your own header service: a structurally
/// valid BEEF only proves its merkle paths compute *some* root, so a forged
/// parent transaction with a made-up proof passes this function and is caught
/// only by whatever your broadcast or internalize step does later. Callers
/// that serve before those steps are exposed to that forgery. A warning is
/// logged whenever roots go unchecked (the core answers `Unverifiable`, which
/// [`accept_verdict`] accepts by this adapter's policy).
pub fn verify_brc29_payment_structural_only(
    server_key: &str,
    sender_identity_key: &str,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: &[u8],
    output_index: usize,
    required_satoshis: u64,
) -> std::result::Result<u64, PaymentVerifyError> {
    accept_verdict(bsv_middleware_core::verify_brc29_payment_structural_only(
        server_key,
        sender_identity_key,
        derivation_prefix,
        derivation_suffix,
        tx_bytes,
        output_index,
        required_satoshis,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_middleware_core::BRC29_PROTOCOL_ID;
    use bsv_sdk::primitives::hash::hash160;
    use bsv_sdk::primitives::{PrivateKey, PublicKey};
    use bsv_sdk::script::LockingScript;
    use bsv_sdk::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    use bsv_sdk::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
    use std::cell::RefCell;

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    /// A real-looking (non-`.invalid`) base URL for tests that must never
    /// reach the network: they fail before SPV, or inject their lookup.
    const HEADERS_URL: &str = "https://headers.example";

    /// Block height of the one-leaf proof in [`beef_with_proven_payment`].
    const PROOF_HEIGHT: u32 = 850_000;

    fn sender_identity() -> String {
        let sender_priv = PrivateKey::from_hex(SENDER_KEY).unwrap();
        ProtoWallet::new(Some(sender_priv)).identity_key().to_hex()
    }

    fn payment_tx(script_hex: &str, satoshis: u64) -> Transaction {
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
    fn beef_with_unproven_payment(script_hex: &str, satoshis: u64) -> Vec<u8> {
        let mut beef = Beef::new();
        beef.merge_transaction(payment_tx(script_hex, satoshis));
        beef.to_binary()
    }

    /// A BEEF holding ONE transaction proven by a one-leaf BUMP at
    /// `PROOF_HEIGHT` (a block of one transaction, whose merkle root IS the
    /// txid), paying `satoshis` to `script_hex`. `verify_valid` accepts it and
    /// reports exactly one root, so SPV can be driven by an injected lookup.
    /// Returns the bytes and the txid (= the root the lookup must answer).
    fn beef_with_proven_payment(script_hex: &str, satoshis: u64) -> (Vec<u8>, String) {
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

    fn our_script() -> String {
        expected_brc29_locking_script(SERVER_KEY, &sender_identity(), "prefix", "suffix").unwrap()
    }

    /// The full verification of a correct, proven 1000-sat payment with the
    /// header service replaced by `answer` (the same answer at every height);
    /// also returns the heights the lookup was asked for.
    async fn verify_proven_with(
        answer: std::result::Result<String, String>,
    ) -> (std::result::Result<u64, PaymentVerifyError>, Vec<u32>) {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let asked = RefCell::new(Vec::new());
        let result = verify_brc29_payment_with_header_lookup(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            |height| {
                asked.borrow_mut().push(height);
                let answer = answer.clone();
                async move { answer }
            },
        )
        .await;
        (result, asked.into_inner())
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
        let script = our_script();
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
        let beef = beef_with_unproven_payment(&our_script(), 999);
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
        let beef = beef_with_unproven_payment(&our_script(), 1000);
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
        let beef = beef_with_unproven_payment(&our_script(), 1000);
        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &beef,
            0,
            1000,
            Some(HEADERS_URL),
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
            Some(HEADERS_URL),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::BadTransaction(_)));
    }

    #[test]
    fn test_default_header_url_is_a_reserved_placeholder_and_is_refused() {
        assert!(DEFAULT_CHAINTRACKS_URL.ends_with(".invalid"));
        assert!(matches!(
            resolve_header_service(Some(DEFAULT_CHAINTRACKS_URL)),
            Err(PaymentVerifyError::NoHeaderService)
        ));
    }

    /// The configuration gate, as a table: every shape of "no header service"
    /// is `NoHeaderService` (never fail-open, never a skip), including the
    /// placeholder spellings a URL parser would have decoded or rewritten
    /// into the placeholder after our comparison (the re-review's R1: a
    /// trailing-dot FQDN, a percent-encoded dot, a backslash before an `@`)
    /// and every host form the gate declines to classify; a real base URL
    /// comes back trimmed, without trailing slashes.
    #[test]
    fn test_resolve_header_service_table() {
        let refused: &[Option<&str>] = &[
            // nothing
            None,
            Some(""),
            Some("   "),
            Some("/"),
            // the placeholder, in every spelling
            Some(DEFAULT_CHAINTRACKS_URL),
            Some("https://chaintracks.invalid/"),
            Some("HTTPS://CHAINTRACKS.INVALID"),
            Some("http://CHAINTRACKS.INVALID:443/"),
            Some("HTTPS://Chaintracks.Invalid///"),
            Some("https://invalid"),
            Some("https://invalid."),
            // R1: trailing-dot FQDN, with and without a path
            Some("https://chaintracks.invalid."),
            Some("https://chaintracks.invalid./"),
            Some("https://chaintracks.invalid./v1"),
            Some("HTTPS://CHAINTRACKS.INVALID.:8443/"),
            Some("https://chaintracks.invalid.."),
            // R1: percent-encoding (a URL parser decodes it to the placeholder)
            Some("https://chaintracks%2Einvalid"),
            Some("https://chaintracks%2einvalid/"),
            Some("https://chaintracks.invalid%2F"),
            Some("https://%63haintracks.invalid"),
            // R1: backslash parser differential (WHATWG reads `\` as `/`,
            // so the fetch would have gone to the placeholder)
            Some("https://chaintracks.invalid\\@real.example"),
            Some("https://real.example\\@chaintracks.invalid"),
            Some("https://chaintracks.invalid\\real.example"),
            Some("https:\\\\chaintracks.invalid"),
            Some("https://headers.example\\v1"),
            // userinfo, on the placeholder and on a real host alike
            Some("https://user@chaintracks.invalid"),
            Some("https://user:pw@headers.invalid:8443/v1/"),
            Some("https://user:pw@CHAINTRACKS.invalid:8443/x"),
            Some("https://chaintracks.invalid@real.example"),
            Some("https://user:pw@headers.example"),
            Some("https://@headers.example"),
            Some("https://@"),
            // whitespace and control characters inside the value
            Some("https://chain tracks.invalid"),
            Some("https://chaintracks.invalid\t"),
            Some("https://chaintracks.invalid\n/"),
            Some("https://headers.example/v1 /x"),
            Some("https://headers.example\u{0}"),
            Some("https://headers\u{a0}.example"),
            Some("\0\u{ff}garbage"),
            // non-ASCII (an IDNA mapping could fold it onto the placeholder)
            Some("https://chaintracks\u{ff0e}invalid"),
            Some("https://h\u{e9}aders.example"),
            // no scheme, the wrong scheme, no host
            Some("headers.example"),
            Some("ftp://headers.example"),
            Some("https:/headers.example"),
            Some("https:///headers.example"),
            Some("https://"),
            Some("https://:443"),
            Some("https://[]"),
            Some("https://[::1"),
            Some("https://[::1]x"),
            Some("https://[zz::1]"),
            Some("https://[fe80::1%25eth0]"),
            // a port that is not a port
            Some("https://headers.example:"),
            Some("https://headers.example:abc"),
            Some("https://headers.example:+80"),
            Some("https://headers.example:99999"),
            Some("https://chaintracks.invalid:"),
            // labels that are not a hostname
            Some("https://-headers.example"),
            Some("https://headers-.example"),
            Some("https://headers..example"),
            Some("https://.headers.example"),
            Some("https://headers_svc.example"),
            Some("https://."),
        ];
        for url in refused {
            assert!(
                matches!(
                    resolve_header_service(*url),
                    Err(PaymentVerifyError::NoHeaderService)
                ),
                "{url:?} must be refused as NoHeaderService"
            );
        }

        let accepted = [
            ("https://headers.example", "https://headers.example"),
            ("https://headers.example/", "https://headers.example"),
            (
                "  https://headers.example/v1//  ",
                "https://headers.example/v1",
            ),
            ("HTTPS://Headers.Example", "HTTPS://Headers.Example"),
            ("https://headers.example.", "https://headers.example."),
            (
                "https://headers.example.:8443/v1",
                "https://headers.example.:8443/v1",
            ),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://localhost:3000/", "http://localhost:3000"),
            ("https://[::1]:8080/", "https://[::1]:8080"),
            ("https://[::ffff:10.0.0.1]", "https://[::ffff:10.0.0.1]"),
            ("https://invalid.example", "https://invalid.example"),
            (
                "https://chaintracks.invalid.example.com",
                "https://chaintracks.invalid.example.com",
            ),
            (
                "https://xn--hders-kva.example",
                "https://xn--hders-kva.example",
            ),
            (
                "https://headers.example/v1?x=1",
                "https://headers.example/v1?x=1",
            ),
        ];
        for (url, base) in accepted {
            assert_eq!(resolve_header_service(Some(url)).unwrap(), base, "{url:?}");
        }
    }

    /// The host classifier normalises BEFORE the gate compares: case,
    /// port, trailing dot, brackets and path all fold away, so every spelling
    /// of one host is one string, and the forms it will not classify are
    /// `None` rather than a guess.
    #[test]
    fn test_header_service_host_normalises_before_comparison() {
        let normalised = [
            ("https://chaintracks.invalid", "chaintracks.invalid"),
            ("HTTPS://CHAINTRACKS.INVALID.:8443/x", "chaintracks.invalid"),
            ("http://chaintracks.invalid./", "chaintracks.invalid"),
            ("https://Headers.Example.", "headers.example"),
            ("https://headers.example:443/v1", "headers.example"),
            ("https://[::1]:8080", "::1"),
            ("https://[FE80::1]", "fe80::1"),
            ("http://127.0.0.1", "127.0.0.1"),
            ("https://invalid.", "invalid"),
        ];
        for (url, host) in normalised {
            assert_eq!(header_service_host(url).as_deref(), Some(host), "{url:?}");
        }
        for url in [
            "https://chaintracks%2Einvalid",
            "https://chaintracks.invalid\\@real.example",
            "https://user@headers.example",
            "https://headers.example:",
            "https://headers..example",
            "https://headers.example..",
            "ftp://headers.example",
            "https://",
        ] {
            assert_eq!(header_service_host(url), None, "{url:?}");
        }
    }

    /// The one visible match, as a table: every core word lands on its 0.3
    /// result, and `Unverifiable` is accepted (this adapter's documented
    /// fail-open policy) with the amount the core carried.
    #[test]
    fn test_accept_verdict_table() {
        assert_eq!(
            accept_verdict(PaymentVerdict::Verified { satoshis: 7 }).unwrap(),
            7
        );
        assert_eq!(
            accept_verdict(PaymentVerdict::Unverifiable {
                satoshis: 9,
                reason: "HTTP 503".into()
            })
            .unwrap(),
            9,
            "fail-open: the host serves on the carried amount"
        );
        assert!(matches!(
            accept_verdict(PaymentVerdict::Underpaid {
                paid: 5,
                required: 10
            }),
            Err(PaymentVerifyError::Underpaid {
                satoshis: 5,
                required: 10
            })
        ));
        assert!(matches!(
            accept_verdict(PaymentVerdict::WrongScript {
                expected: "a".into(),
                actual: "b".into()
            }),
            Err(PaymentVerifyError::WrongScript { expected, actual }) if expected == "a" && actual == "b"
        ));
        assert!(matches!(
            accept_verdict(PaymentVerdict::NoHeaderService),
            Err(PaymentVerifyError::NoHeaderService)
        ));
        assert!(matches!(
            accept_verdict(PaymentVerdict::RootMismatch {
                height: 4,
                root: "r".into()
            }),
            Err(PaymentVerifyError::RootMismatch { height: 4, root }) if root == "r"
        ));
    }

    /// The core's faults land on the same-named 0.3 errors, message intact.
    #[test]
    fn test_fault_mapping_table() {
        let faults = [
            PaymentFault::BadTransaction("x".into()),
            PaymentFault::MissingOutput {
                index: 2,
                output_count: 1,
            },
            PaymentFault::KeyDerivation("k".into()),
            PaymentFault::BadBeef("b".into()),
        ];
        for fault in faults {
            let text = fault.to_string();
            let err = PaymentVerifyError::from(fault.clone());
            let same_variant = match (&fault, &err) {
                (PaymentFault::BadTransaction(a), PaymentVerifyError::BadTransaction(b)) => a == b,
                (
                    PaymentFault::MissingOutput {
                        index: a,
                        output_count: b,
                    },
                    PaymentVerifyError::MissingOutput {
                        index: c,
                        output_count: d,
                    },
                ) => a == c && b == d,
                (PaymentFault::KeyDerivation(a), PaymentVerifyError::KeyDerivation(b)) => a == b,
                (PaymentFault::BadBeef(a), PaymentVerifyError::BadBeef(b)) => a == b,
                _ => false,
            };
            assert!(same_variant, "{fault:?} -> {err:?}");
            assert_eq!(err.to_string(), text, "the message is the core's");
        }
    }

    /// The URL service is built only through the gate, and keeps the trimmed
    /// base the gate resolved.
    #[test]
    fn test_url_header_service_is_gated() {
        let service = UrlHeaderService::resolve(Some("  https://headers.example/v1/ ")).unwrap();
        assert_eq!(service.base_url(), "https://headers.example/v1");
        assert!(matches!(
            UrlHeaderService::resolve(Some(DEFAULT_CHAINTRACKS_URL)),
            Err(PaymentVerifyError::NoHeaderService)
        ));
        assert!(matches!(
            UrlHeaderService::resolve(None),
            Err(PaymentVerifyError::NoHeaderService)
        ));
    }

    /// End to end on a correct, proven payment with the header service
    /// injected: the lookup is asked exactly once, at the proof's height; a
    /// matching header accepts, a different one is `RootMismatch` naming the
    /// height and root, and a service error fails open to the paid amount.
    #[tokio::test]
    async fn test_full_verification_spv_outcomes_table() {
        let (_, txid) = beef_with_proven_payment(&our_script(), 1000);

        let (ok, asked) = verify_proven_with(Ok(txid.clone())).await;
        assert_eq!(ok.unwrap(), 1000);
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (ok, _) = verify_proven_with(Ok(txid.to_ascii_uppercase())).await;
        assert_eq!(ok.unwrap(), 1000, "root compare is case-insensitive");

        let (err, asked) = verify_proven_with(Ok("00".repeat(32))).await;
        let err = err.unwrap_err();
        assert!(
            matches!(&err, PaymentVerifyError::RootMismatch { height, root }
                if *height == PROOF_HEIGHT && *root == txid),
            "{err}"
        );
        assert_eq!(asked, vec![PROOF_HEIGHT]);

        let (ok, asked) = verify_proven_with(Err("fetch height: timeout".to_string())).await;
        assert_eq!(ok.unwrap(), 1000, "a service error fails open");
        assert_eq!(asked, vec![PROOF_HEIGHT]);
    }

    /// `verify_brc29_payment` with no usable header service is
    /// `NoHeaderService` for a payment that would otherwise pass: never `Ok`,
    /// never a skipped root check. The gate runs before step 1, so garbage
    /// bytes under a missing service are also `NoHeaderService`.
    #[tokio::test]
    async fn test_full_verification_without_header_service_fails_closed() {
        let (beef, _) = beef_with_proven_payment(&our_script(), 1000);
        let no_service: [Option<&str>; 7] = [
            None,
            Some(""),
            Some("  "),
            Some(DEFAULT_CHAINTRACKS_URL),
            Some("https://chaintracks.invalid/"),
            Some("https://headers.invalid"),
            Some("headers.example"),
        ];
        for header_url in no_service {
            let err = verify_brc29_payment(
                SERVER_KEY,
                &sender_identity(),
                "prefix",
                "suffix",
                &beef,
                0,
                1000,
                header_url,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, PaymentVerifyError::NoHeaderService),
                "{header_url:?}: {err}"
            );
        }

        let err = verify_brc29_payment(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &[0u8; 16],
            0,
            1000,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, PaymentVerifyError::NoHeaderService),
            "the gate runs first: {err}"
        );
    }

    /// The named opt-out keeps every offline check (script, amount, BEEF
    /// structure) and only drops the root-vs-header comparison.
    #[test]
    fn test_structural_only_keeps_offline_checks_and_skips_spv() {
        let (proven, _) = beef_with_proven_payment(&our_script(), 1000);
        let sats = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &proven,
            0,
            1000,
        )
        .unwrap();
        assert_eq!(sats, 1000);

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
        assert!(matches!(err, PaymentVerifyError::BadBeef(_)), "{err}");

        let (underpaid, _) = beef_with_proven_payment(&our_script(), 999);
        let err = verify_brc29_payment_structural_only(
            SERVER_KEY,
            &sender_identity(),
            "prefix",
            "suffix",
            &underpaid,
            0,
            1000,
        )
        .unwrap_err();
        assert!(matches!(err, PaymentVerifyError::Underpaid { .. }), "{err}");

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
        assert!(
            matches!(err, PaymentVerifyError::BadTransaction(_)),
            "{err}"
        );
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
        let s = PaymentVerifyError::NoHeaderService.to_string();
        assert!(
            s.contains("header service") && s.contains("structural_only"),
            "{s}"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(PaymentVerifyError::BadBeef("x".into()));
        assert!(boxed.to_string().contains("incomplete"));
    }
}
