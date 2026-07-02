//! BRC-29 Payment middleware for Cloudflare Workers.
//!
//! This is a 1:1 port of payment-express-middleware, adapted for Cloudflare Workers.
//! It implements the same payment flow:
//! 1. Requires auth middleware to run first (checks auth_context)
//! 2. Calculates request price via user-provided function
//! 3. If price = 0: free pass
//! 4. If no x-bsv-payment header: returns 402 with derivation prefix (nonce)
//! 5. If payment header present: verifies nonce, internalizes payment via storage server
//!
//! Payment internalization uses `WorkerStorageClient` to talk to a remote storage
//! server (e.g. `storage.babbage.systems`) over BRC-103/104, matching how the TypeScript
//! Express middleware uses a `WalletInterface` (which is a remote wallet client).

use crate::client::WorkerStorageClient;
use crate::error::{AuthCloudflareError, Result};
use crate::middleware::auth::add_cors_headers;
use crate::storage::{KvSessionStorage, SessionStorage};
use crate::types::{AuthContext, BsvPayment, ErrorResponse, PaymentContext};
use bsv_sdk::auth::utils::{create_nonce, verify_nonce};
use bsv_sdk::primitives::{from_base64, PrivateKey};
use bsv_sdk::wallet::ProtoWallet;
use worker::{Headers, Request, Response};

/// Payment header names (BRC-29).
pub mod payment_headers {
    /// Payment data (JSON).
    pub const PAYMENT: &str = "x-bsv-payment";
    /// Payment protocol version.
    pub const VERSION: &str = "x-bsv-payment-version";
    /// Amount required in satoshis.
    pub const SATOSHIS_REQUIRED: &str = "x-bsv-payment-satoshis-required";
    /// Derivation prefix for payment address.
    pub const DERIVATION_PREFIX: &str = "x-bsv-payment-derivation-prefix";
    /// Amount paid in satoshis (response header).
    pub const SATOSHIS_PAID: &str = "x-bsv-payment-satoshis-paid";
    /// Transaction ID of the accepted payment (response header).
    pub const TXID: &str = "x-bsv-payment-txid";
    /// Supported payment transports (BRC-105 negotiation).
    pub const TRANSPORTS: &str = "x-bsv-payment-transports";
}

const PAYMENT_VERSION: &str = "1.0";
const ORIGINATOR: &str = "bsv-auth-cloudflare";

/// Nonce scope under which consumed BRC-29 payment derivation prefixes are
/// recorded in the [`SessionStorage`] nonce store.
pub const PAYMENT_NONCE_SCOPE: &str = "payment-derivation-prefix";

/// Options for payment middleware.
///
/// Mirrors payment-express-middleware's `PaymentMiddlewareOptions`:
/// - `server_private_key` for nonce operations (HMAC-based derivation prefix)
/// - `calculate_price` to determine per-request pricing
/// - `storage_url` for the remote storage server that handles `internalizeAction`
///
/// In the TypeScript middleware, a `WalletInterface` is passed in — typically a
/// `WalletClient` connected to `storage.babbage.systems`. Here, we use
/// `WorkerStorageClient` (created internally from the server key + storage URL)
/// to achieve the same thing.
pub struct PaymentMiddlewareOptions<F> {
    /// Server's private key (64-char hex). Used for:
    /// - Creating `ProtoWallet` for nonce operations (create_nonce/verify_nonce)
    /// - Authenticating to the storage server via BRC-103/104
    pub server_private_key: String,
    /// Function to calculate price for a request (in satoshis).
    /// Return 0 for free requests.
    /// Express equivalent: `calculateRequestPrice`
    pub calculate_price: F,
    /// URL of the storage server for payment internalization.
    /// Defaults to `WorkerStorageClient::MAINNET_URL` (<https://storage.babbage.systems>).
    pub storage_url: String,
}

impl<F> PaymentMiddlewareOptions<F> {
    /// Creates new payment middleware options with mainnet storage.
    pub fn new(server_private_key: String, calculate_price: F) -> Self {
        Self {
            server_private_key,
            calculate_price,
            storage_url: WorkerStorageClient::MAINNET_URL.to_string(),
        }
    }

    /// Creates new payment middleware options with a custom storage URL.
    pub fn with_storage_url(
        server_private_key: String,
        calculate_price: F,
        storage_url: String,
    ) -> Self {
        Self {
            server_private_key,
            calculate_price,
            storage_url,
        }
    }
}

/// Result of payment processing.
pub enum PaymentResult {
    /// No payment needed (price was 0).
    /// Express equivalent: `req.payment = { satoshisPaid: 0 }`, then `next()`
    Free,
    /// Payment required - return this 402 response.
    /// Express equivalent: `res.status(402).set({...}).json({...})`
    Required(Response),
    /// Payment verified successfully.
    /// Express equivalent: `req.payment = { satoshisPaid, accepted, tx }`, then `next()`
    Verified(PaymentContext),
    /// Payment verification failed - return this error response.
    Failed(Response),
}

/// Process payment for a request **without** single-use nonce tracking.
///
/// This is the original port of payment-express-middleware's
/// `createPaymentMiddleware`, kept for backward compatibility. It now gates
/// on the wallet's `accepted` flag (the-composer audit #44) but — like the TS
/// reference — verifies the derivation prefix with a **stateless HMAC only**:
/// nothing stops the same `X-BSV-Payment` header from being internalized
/// again except the upstream wallet's own duplicate handling.
///
/// Use [`process_payment_with_storage`] instead, which additionally enforces
/// single-use derivation prefixes through the pluggable [`SessionStorage`]
/// nonce store.
#[deprecated(
    since = "0.3.0",
    note = "stateless: payment derivation prefixes are not single-use (replay relies on the \
            upstream wallet); use process_payment_with_storage"
)]
pub async fn process_payment<F>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
{
    process_payment_inner(
        req,
        auth_context,
        options,
        Option::<&KvSessionStorage>::None,
    )
    .await
}

/// Process payment for a request, with single-use derivation prefixes.
///
/// This is a port of payment-express-middleware's `createPaymentMiddleware`
/// with two deliberate hardening divergences from the TS reference
/// (`@bsv/payment-express-middleware` 1.2.3), per the-composer audit #44:
///
/// 1. **`accepted` gate.** The reference destructures `accepted` from
///    `wallet.internalizeAction(...)` and calls `next()` regardless of its
///    value (index.ts:100-124). Here, `accepted != true` returns a **402**
///    ([`PaymentResult::Failed`]) carrying a fresh payment challenge —
///    a rejected payment never reaches the handler.
/// 2. **Single-use derivation prefix.** The reference's `verifyNonce` is a
///    stateless HMAC check — a captured `X-BSV-Payment` header can be
///    internalized repeatedly (bounded only by the upstream wallet's
///    duplicate handling). Here, each verified prefix is consumed through
///    [`SessionStorage::try_consume_nonce`] under [`PAYMENT_NONCE_SCOPE`]
///    with **no expiry** (the HMAC itself never expires); a reused prefix is
///    rejected with `400 ERR_INVALID_DERIVATION_PREFIX` before touching the
///    wallet.
///
/// Consumption ordering (money path):
/// - The prefix is consumed **before** `internalizeAction`, so concurrent
///   duplicates cannot both reach the wallet (subject to the storage
///   backend's consistency — see [`KvSessionStorage::try_consume_nonce`] for
///   the KV residual window).
/// - If `internalizeAction` fails with an **error**, the prefix is released
///   (best-effort) so an honest client can retry the same real payment.
/// - If the wallet returns **`accepted: false`** or the call succeeds, the
///   prefix stays consumed; the client must obtain a fresh 402 challenge.
///
/// **IMPORTANT**: Auth middleware MUST run before this. The `auth_context`
/// parameter must come from successful authentication. If `auth_context` is
/// not properly authenticated, this returns ERR_SERVER_MISCONFIGURED
/// (matching Express behavior when `req.auth.identityKey` is missing).
pub async fn process_payment_with_storage<F, S>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
    session_storage: &S,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
    S: SessionStorage + ?Sized,
{
    process_payment_inner(req, auth_context, options, Some(session_storage)).await
}

/// Shared implementation. `nonce_store: None` = legacy stateless behavior
/// (deprecated [`process_payment`]); `Some(_)` = single-use enforcement.
///
/// Thin `worker::Request`/`Response` shell: extracts the price closure and
/// `x-bsv-payment` header from the request, delegates every money-path
/// decision to [`decide_payment`] (request-free, so `cargo test` executes
/// it natively), then renders the returned [`PaymentDecision`] into the
/// exact HTTP responses this function historically built inline.
async fn process_payment_inner<F, S>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
    nonce_store: Option<&S>,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
    S: SessionStorage + ?Sized,
{
    let payment_header = req.headers().get(payment_headers::PAYMENT).ok().flatten();
    let decision = decide_payment(
        auth_context,
        || (options.calculate_price)(req),
        payment_header,
        &options.server_private_key,
        nonce_store,
        |derivation_prefix, derivation_suffix, tx_bytes| async move {
            internalize_payment(
                options,
                auth_context,
                &derivation_prefix,
                &derivation_suffix,
                tx_bytes,
            )
            .await
        },
    )
    .await?;
    decision_into_result(decision)
}

/// Pure-data outcome of the payment decision core ([`decide_payment`]).
///
/// Each variant maps 1:1 onto a [`PaymentResult`] (see
/// [`decision_into_result`]); the split exists so the money path can be
/// executed under native `cargo test` — `worker::Response`/`Headers` wrap
/// `web_sys` types that only function on a live Workers runtime.
#[derive(Debug, PartialEq, Eq)]
enum PaymentDecision {
    /// Auth middleware didn't run first → 500 `ERR_SERVER_MISCONFIGURED`
    /// ([`PaymentResult::Failed`]).
    Misconfigured,
    /// Price was 0 → [`PaymentResult::Free`].
    Free,
    /// No `x-bsv-payment` header → 402 `ERR_PAYMENT_REQUIRED` challenge
    /// ([`PaymentResult::Required`]).
    Challenge {
        price: u64,
        derivation_prefix: String,
    },
    /// Header is not valid JSON → 400 `ERR_MALFORMED_PAYMENT`
    /// ([`PaymentResult::Failed`]).
    MalformedHeader,
    /// Derivation prefix failed HMAC verification → 400
    /// `ERR_INVALID_DERIVATION_PREFIX` ([`PaymentResult::Failed`]).
    InvalidPrefix,
    /// Derivation prefix was already consumed (single-use enforcement,
    /// audit #44) → 400 `ERR_INVALID_DERIVATION_PREFIX` "(already used)"
    /// ([`PaymentResult::Failed`]). Only reachable with a nonce store.
    ReplayedPrefix,
    /// Wallet did not affirmatively accept (`accepted != true`) → 402
    /// `ERR_PAYMENT_FAILED` with a fresh challenge; the old prefix stays
    /// consumed ([`PaymentResult::Failed`]).
    WalletRejected { price: u64, fresh_prefix: String },
    /// `internalizeAction` errored (payment NOT processed; prefix released
    /// best-effort) → 400 `ERR_PAYMENT_FAILED` ([`PaymentResult::Failed`]).
    InternalizeError { description: String },
    /// Wallet accepted → [`PaymentResult::Verified`].
    Verified { price: u64, tx: String },
}

/// Request/`Response`-free core of BRC-29 payment processing.
///
/// Owns every ordering decision on the money path — auth gate → price →
/// challenge → header parse → HMAC verify → base64 decode → **consume
/// prefix** → internalize → **accepted gate / release** — over plain data,
/// so the whole path executes under native `cargo test` (the-composer #29
/// lesson: handler logic must be executed by tests, not just its pure
/// helpers).
///
/// Parameters that exist purely as seams:
/// - `calculate_price` is lazy so the Express ordering is preserved
///   exactly: the reference errors on a missing `req.auth` *before*
///   calling `calculateRequestPrice`.
/// - `internalize` abstracts the wallet-communication phase
///   ([`internalize_payment`] in production, whose `WorkerStorageClient`
///   HTTP transport cannot run off-Workers). It receives
///   `(derivation_prefix, derivation_suffix, tx_bytes)` and returns the
///   wallet's `internalizeAction` JSON.
async fn decide_payment<P, S, I, Fut>(
    auth_context: &AuthContext,
    calculate_price: P,
    payment_header: Option<String>,
    server_private_key: &str,
    nonce_store: Option<&S>,
    internalize: I,
) -> Result<PaymentDecision>
where
    P: FnOnce() -> u64,
    S: SessionStorage + ?Sized,
    I: FnOnce(String, String, Vec<u8>) -> Fut,
    Fut: core::future::Future<Output = Result<serde_json::Value>>,
{
    // Step 1: Verify auth middleware ran first (matches Express check for req.auth.identityKey)
    if !auth_context.is_authenticated || auth_context.identity_key == "unknown" {
        return Ok(PaymentDecision::Misconfigured);
    }

    // Step 2: Calculate price
    let price = calculate_price();

    // Step 3: If price is 0, proceed immediately (matches Express: `req.payment = { satoshisPaid: 0 }`)
    if price == 0 {
        return Ok(PaymentDecision::Free);
    }

    // Create wallet for nonce operations
    let private_key = PrivateKey::from_hex(server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Step 4: Check for payment header
    let Some(payment_json) = payment_header else {
        // No payment provided - generate nonce and return 402
        // Matches Express: `const derivationPrefix = await createNonce(wallet)`
        let derivation_prefix = create_nonce(&wallet, None, ORIGINATOR).await?;
        return Ok(PaymentDecision::Challenge {
            price,
            derivation_prefix,
        });
    };

    // Payment provided - parse and verify
    // Step 5: Parse payment JSON
    // Express: `paymentData = JSON.parse(String(bsvPaymentHeader))`
    let payment: BsvPayment = match serde_json::from_str(&payment_json) {
        Ok(p) => p,
        // Express catches parse error and returns ERR_MALFORMED_PAYMENT
        Err(_) => return Ok(PaymentDecision::MalformedHeader),
    };

    // Step 6: Verify derivation prefix (nonce)
    // Express: `const valid = await verifyNonce(paymentData.derivationPrefix, wallet)`
    let nonce_valid = verify_nonce(&payment.derivation_prefix, &wallet, None, ORIGINATOR)
        .await
        .unwrap_or_default();

    if !nonce_valid {
        // Express: returns ERR_INVALID_DERIVATION_PREFIX
        return Ok(PaymentDecision::InvalidPrefix);
    }

    // Decode the transaction BEFORE consuming the prefix — a
    // malformed payload must not burn the client's derivation prefix.
    let tx_bytes = from_base64(&payment.transaction).map_err(|_| {
        AuthCloudflareError::MalformedPayment("Invalid base64 transaction data".to_string())
    })?;

    // Step 6b (hardening divergence from the TS reference — audit #44):
    // consume the derivation prefix BEFORE internalizing, so a
    // captured X-BSV-Payment header cannot be internalized twice.
    // No TTL: the HMAC prefix never expires, so its consumption
    // record must not either. Storage errors fail closed (`?`).
    if let Some(store) = nonce_store {
        let fresh = store
            .try_consume_nonce(PAYMENT_NONCE_SCOPE, &payment.derivation_prefix, None)
            .await?;
        if !fresh {
            // Wire code matches the reference's invalid-prefix error;
            // the description distinguishes reuse.
            return Ok(PaymentDecision::ReplayedPrefix);
        }
    }

    // Step 7: internalize the payment (see `internalize_payment`).
    // The whole wallet-communication phase maps to the reference's
    // try/catch around `wallet.internalizeAction(...)`.
    let internalize_result = internalize(
        payment.derivation_prefix.clone(),
        payment.derivation_suffix.clone(),
        tx_bytes,
    )
    .await;

    match internalize_result {
        Ok(result) => {
            // Gate on the wallet's `accepted` flag (hardening
            // divergence — audit #44). The TS reference
            // (payment-express-middleware 1.2.3, index.ts:100-124)
            // passes `accepted` through to `req.payment` and calls
            // `next()` even when the wallet rejected the payment.
            // Here a rejected payment returns 402 with a FRESH
            // challenge (the old prefix stays consumed).
            // A missing/non-boolean `accepted` field counts as
            // rejected — never fail open on the money path.
            if !internalize_accepted(&result) {
                let fresh_prefix = create_nonce(&wallet, None, ORIGINATOR).await?;
                return Ok(PaymentDecision::WalletRejected {
                    price,
                    fresh_prefix,
                });
            }

            // Success - matches Express: req.payment = { satoshisPaid, accepted, tx }
            Ok(PaymentDecision::Verified {
                price,
                tx: payment.transaction,
            })
        }
        Err(e) => {
            // The payment was NOT processed to acceptance — release
            // the consumed prefix (best-effort) so an honest client
            // can retry the same real payment after a transient
            // fault. If the failure was actually post-internalize
            // (response lost), the retry hits the upstream wallet's
            // own duplicate handling — same reliance as the TS
            // reference's only line of defense.
            if let Some(store) = nonce_store {
                if let Err(release_err) = store
                    .release_nonce(PAYMENT_NONCE_SCOPE, &payment.derivation_prefix)
                    .await
                {
                    warn_log(&format!(
                        "payment nonce release failed (prefix stays consumed; client must re-challenge): {release_err:?}"
                    ));
                }
            }

            // Express: catch(err) => res.status(400).json({ code: err.code ?? 'ERR_PAYMENT_FAILED', description: err.message ?? 'Payment failed.' })
            Ok(PaymentDecision::InternalizeError {
                description: e.to_string(),
            })
        }
    }
}

/// Renders a [`PaymentDecision`] into the [`PaymentResult`] (and its HTTP
/// `Response` bodies/headers) that `process_payment_inner` historically
/// built inline. Wire bytes are unchanged: identical JSON constructors,
/// identical header sets, identical statuses, identical CORS wrapping.
fn decision_into_result(decision: PaymentDecision) -> Result<PaymentResult> {
    match decision {
        PaymentDecision::Misconfigured => failed_json_response(
            500,
            "ERR_SERVER_MISCONFIGURED",
            "The payment middleware must be executed after the Auth middleware.",
        ),
        PaymentDecision::Free => Ok(PaymentResult::Free),
        PaymentDecision::Challenge {
            price,
            derivation_prefix,
        } => {
            // Build 402 response with payment headers
            // Matches Express response exactly
            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": price,
                "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
            });

            let response = Response::from_json(&body)
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                .with_status(402)
                .with_headers(challenge_headers(price, &derivation_prefix));

            Ok(PaymentResult::Required(add_cors_headers(response)))
        }
        PaymentDecision::MalformedHeader => failed_json_response(
            400,
            "ERR_MALFORMED_PAYMENT",
            "The X-BSV-Payment header is not valid JSON.",
        ),
        PaymentDecision::InvalidPrefix => failed_json_response(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid.",
        ),
        PaymentDecision::ReplayedPrefix => failed_json_response(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid (already used).",
        ),
        PaymentDecision::WalletRejected {
            price,
            fresh_prefix,
        } => {
            let response = Response::from_json(&ErrorResponse::new(
                "ERR_PAYMENT_FAILED",
                "The BSV payment was not accepted by the wallet. A fresh payment challenge is provided in the response headers.",
            ))
            .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
            .with_status(402)
            .with_headers(challenge_headers(price, &fresh_prefix));
            Ok(PaymentResult::Failed(add_cors_headers(response)))
        }
        PaymentDecision::InternalizeError { description } => {
            failed_json_response(400, "ERR_PAYMENT_FAILED", &description)
        }
        PaymentDecision::Verified { price, tx } => Ok(PaymentResult::Verified(PaymentContext {
            satoshis_paid: price,
            accepted: true,
            tx: Some(tx),
        })),
    }
}

/// The BRC-29 payment-challenge header set (402 responses, both the
/// no-payment challenge and the wallet-rejected fresh challenge).
fn challenge_headers(price: u64, derivation_prefix: &str) -> Headers {
    let h = Headers::new();
    let _ = h.set(payment_headers::VERSION, PAYMENT_VERSION);
    let _ = h.set(payment_headers::SATOSHIS_REQUIRED, &price.to_string());
    let _ = h.set(payment_headers::DERIVATION_PREFIX, derivation_prefix);
    let _ = h.set(payment_headers::TRANSPORTS, "header,multipart");
    h
}

/// `PaymentResult::Failed` with the standard `ErrorResponse` JSON body.
fn failed_json_response(status: u16, code: &str, description: &str) -> Result<PaymentResult> {
    let response = Response::from_json(&ErrorResponse::new(code, description))
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(status);
    Ok(PaymentResult::Failed(add_cors_headers(response)))
}

/// Warn on the Workers console; no-op under native `cargo test` (the
/// `console_*` macros call wasm-bindgen imports that panic off-WASM, and
/// the decision core executes natively in tests).
fn warn_log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

/// Wallet-communication phase of payment processing.
///
/// Creates a BRC-103/104 session with the storage server on first RPC call.
/// Sequence: makeAvailable → findOrInsertUser → internalizeAction (matches
/// wallet-toolbox StorageClient initialization pattern). Any failure here is
/// the equivalent of the TS reference's `catch` around
/// `wallet.internalizeAction(...)` and maps to a 400 `ERR_PAYMENT_FAILED`
/// (after releasing the consumed prefix).
///
/// The server identity is derived from `options.server_private_key` — the
/// same key the decision core's nonce wallet uses.
async fn internalize_payment<F>(
    options: &PaymentMiddlewareOptions<F>,
    auth_context: &AuthContext,
    derivation_prefix: &str,
    derivation_suffix: &str,
    tx_bytes: Vec<u8>,
) -> Result<serde_json::Value> {
    let storage_wallet = ProtoWallet::new(Some(
        PrivateKey::from_hex(&options.server_private_key).map_err(|e| {
            AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
        })?,
    ));
    let server_identity = storage_wallet.identity_key().to_hex();
    let mut storage_client = WorkerStorageClient::new(storage_wallet, &options.storage_url);

    // Initialize connection and register user
    storage_client.make_available().await?;
    let user_result: serde_json::Value =
        storage_client.find_or_insert_user(&server_identity).await?;
    let user_id = user_result.get("userId").and_then(|v| v.as_i64());

    let auth_json = serde_json::json!({
        "identityKey": server_identity,
        "userId": user_id
    });
    // Express equivalent:
    //   const { accepted } = await wallet.internalizeAction({
    //     tx: Utils.toArray(paymentData.transaction, 'base64'),
    //     outputs: [{ paymentRemittance: { derivationPrefix, derivationSuffix, senderIdentityKey }, outputIndex: 0, protocol: 'wallet payment' }],
    //     description: 'Payment for request'
    //   })
    let args_json = serde_json::json!({
        "tx": tx_bytes,
        "outputs": [{
            "outputIndex": 0,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": derivation_prefix,
                "derivationSuffix": derivation_suffix,
                "senderIdentityKey": auth_context.identity_key
            },
            "insertionRemittance": null
        }],
        "description": "Payment for request"
    });

    storage_client
        .internalize_action(auth_json, args_json)
        .await
}

/// Whether an `internalizeAction` response affirmatively accepted the payment.
///
/// Only a literal `"accepted": true` counts; missing or non-boolean values
/// are treated as rejected (never fail open on the money path). The TS
/// reference performs no such gate at all — see
/// [`process_payment_with_storage`] for the divergence note.
fn internalize_accepted(result: &serde_json::Value) -> bool {
    result
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Add payment success headers to response.
///
/// Express equivalent: `res.set({ 'x-bsv-payment-satoshis-paid': String(requestPrice) })`
pub fn add_payment_headers(response: Response, payment: &PaymentContext) -> Response {
    let headers = Headers::new();
    let _ = headers.set(
        payment_headers::SATOSHIS_PAID,
        &payment.satoshis_paid.to_string(),
    );
    response.with_headers(headers)
}

/// Creates a payment failed response.
pub fn payment_failed_response(error: &str) -> worker::Result<Response> {
    let response =
        Response::from_json(&ErrorResponse::new("ERR_PAYMENT_FAILED", error))?.with_status(400);
    Ok(add_cors_headers(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_sdk::primitives::PrivateKey;

    const TEST_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    // ===========================================
    // Payment header constant tests
    // ===========================================

    #[test]
    fn test_payment_header_constants() {
        // Verify header names match BRC-29 spec exactly
        assert_eq!(payment_headers::PAYMENT, "x-bsv-payment");
        assert_eq!(payment_headers::VERSION, "x-bsv-payment-version");
        assert_eq!(
            payment_headers::SATOSHIS_REQUIRED,
            "x-bsv-payment-satoshis-required"
        );
        assert_eq!(
            payment_headers::DERIVATION_PREFIX,
            "x-bsv-payment-derivation-prefix"
        );
        assert_eq!(
            payment_headers::SATOSHIS_PAID,
            "x-bsv-payment-satoshis-paid"
        );
    }

    #[test]
    fn test_payment_version() {
        assert_eq!(PAYMENT_VERSION, "1.0");
    }

    // ===========================================
    // HMAC nonce tests (stateless derivation prefix)
    // ===========================================

    #[tokio::test]
    async fn test_create_and_verify_nonce() {
        let pk = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        // Create a nonce (derivation prefix)
        let nonce = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();
        assert!(!nonce.is_empty(), "Nonce should not be empty");

        // Verify the nonce - should succeed
        let valid = verify_nonce(&nonce, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(valid, "Valid nonce should verify");
    }

    #[tokio::test]
    async fn test_nonce_verification_fails_for_different_key() {
        let pk1 = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet1 = ProtoWallet::new(Some(pk1));

        let pk2 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let wallet2 = ProtoWallet::new(Some(pk2));

        // Create with wallet1
        let nonce = create_nonce(&wallet1, None, ORIGINATOR).await.unwrap();

        // Verify with wallet2 - should fail
        let valid = verify_nonce(&nonce, &wallet2, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(!valid, "Nonce created with different key should not verify");
    }

    #[tokio::test]
    async fn test_nonce_verification_fails_for_tampered_nonce() {
        let pk = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        let nonce = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();

        // Tamper with the nonce
        let tampered = format!("x{}", &nonce[1..]);

        let valid = verify_nonce(&tampered, &wallet, None, ORIGINATOR)
            .await
            .unwrap_or(false);
        assert!(!valid, "Tampered nonce should not verify");
    }

    #[tokio::test]
    async fn test_nonce_uniqueness() {
        let pk = PrivateKey::from_hex(TEST_KEY_HEX).unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        let nonce1 = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();
        let nonce2 = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();

        assert_ne!(nonce1, nonce2, "Each nonce should be unique");

        // Both should still verify
        let valid1 = verify_nonce(&nonce1, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        let valid2 = verify_nonce(&nonce2, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(valid1 && valid2, "Both nonces should verify");
    }

    // ===========================================
    // accepted-gate tests (audit #44)
    // ===========================================
    // The TS reference (payment-express-middleware 1.2.3) proceeds to next()
    // regardless of `accepted`. We gate: only a literal `accepted: true`
    // counts, and anything else is a rejected payment.

    #[test]
    fn test_internalize_accepted_true() {
        let result = serde_json::json!({ "accepted": true, "satoshisPaid": 100 });
        assert!(internalize_accepted(&result));
    }

    #[test]
    fn test_internalize_accepted_false_is_rejected() {
        let result = serde_json::json!({ "accepted": false });
        assert!(
            !internalize_accepted(&result),
            "accepted=false must NOT be treated as success (audit #44)"
        );
    }

    #[test]
    fn test_internalize_accepted_missing_is_rejected() {
        let result = serde_json::json!({ "satoshisPaid": 100 });
        assert!(
            !internalize_accepted(&result),
            "missing accepted field must fail closed"
        );
    }

    #[test]
    fn test_internalize_accepted_non_bool_is_rejected() {
        for v in [
            serde_json::json!({ "accepted": "true" }),
            serde_json::json!({ "accepted": 1 }),
            serde_json::json!({ "accepted": null }),
        ] {
            assert!(
                !internalize_accepted(&v),
                "non-boolean accepted must fail closed: {v}"
            );
        }
    }

    #[test]
    fn test_payment_nonce_scope_constant() {
        // Consumed derivation prefixes are recorded under this scope in the
        // SessionStorage nonce store; changing it orphans consumption records.
        assert_eq!(PAYMENT_NONCE_SCOPE, "payment-derivation-prefix");
    }

    // ===========================================
    // BsvPayment deserialization tests
    // ===========================================

    #[test]
    fn test_bsv_payment_deserialization() {
        let json = r#"{
            "derivationPrefix": "test-prefix",
            "derivationSuffix": "test-suffix",
            "transaction": "AQAAAA=="
        }"#;

        let payment: BsvPayment = serde_json::from_str(json).unwrap();
        assert_eq!(payment.derivation_prefix, "test-prefix");
        assert_eq!(payment.derivation_suffix, "test-suffix");
        assert_eq!(payment.transaction, "AQAAAA==");
    }

    #[test]
    fn test_bsv_payment_camel_case() {
        // Verify camelCase deserialization matches Express's JSON.parse()
        let json = r#"{"derivationPrefix":"p","derivationSuffix":"s","transaction":"dHg="}"#;
        let payment: BsvPayment = serde_json::from_str(json).unwrap();
        assert_eq!(payment.derivation_prefix, "p");
        assert_eq!(payment.derivation_suffix, "s");
        assert_eq!(payment.transaction, "dHg=");
    }

    #[test]
    fn test_bsv_payment_missing_field_fails() {
        let json = r#"{"derivationPrefix":"p","derivationSuffix":"s"}"#;
        let result: std::result::Result<BsvPayment, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Missing transaction field should fail");
    }

    #[test]
    fn test_bsv_payment_invalid_json_fails() {
        let result: std::result::Result<BsvPayment, _> = serde_json::from_str("not json");
        assert!(result.is_err(), "Invalid JSON should fail");
    }

    // ===========================================
    // PaymentContext tests
    // ===========================================

    #[test]
    fn test_payment_context_with_tx() {
        let ctx = PaymentContext {
            satoshis_paid: 500,
            accepted: true,
            tx: Some("base64tx".to_string()),
        };
        assert_eq!(ctx.satoshis_paid, 500);
        assert!(ctx.accepted);
        assert_eq!(ctx.tx.as_deref(), Some("base64tx"));
    }

    #[test]
    fn test_payment_context_free() {
        let ctx = PaymentContext {
            satoshis_paid: 0,
            accepted: true,
            tx: None,
        };
        assert_eq!(ctx.satoshis_paid, 0);
        assert!(ctx.tx.is_none());
    }

    // ===========================================
    // ErrorResponse tests
    // ===========================================

    #[test]
    fn test_error_response_serialization() {
        let err = ErrorResponse::new("ERR_PAYMENT_REQUIRED", "Payment needed");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "ERR_PAYMENT_REQUIRED");
        assert_eq!(parsed["description"], "Payment needed");
    }

    #[test]
    fn test_error_response_matches_express_format() {
        // Express returns: { status: 'error', code: '...', description: '...' }
        let err = ErrorResponse::new("ERR_MALFORMED_PAYMENT", "Bad JSON");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Must have exactly these fields (matching Express)
        assert!(parsed.get("status").is_some());
        assert!(parsed.get("code").is_some());
        assert!(parsed.get("description").is_some());
    }

    // ===========================================
    // PaymentMiddlewareOptions tests
    // ===========================================

    #[test]
    fn test_payment_middleware_options_construction() {
        let opts = PaymentMiddlewareOptions::new("key".to_string(), |_req: &Request| 100u64);
        assert_eq!(opts.server_private_key, "key");
        assert_eq!(opts.storage_url, WorkerStorageClient::MAINNET_URL);
    }

    #[test]
    fn test_payment_middleware_options_custom_storage_url() {
        let opts = PaymentMiddlewareOptions::with_storage_url(
            "key".to_string(),
            |_req: &Request| 100u64,
            "https://custom-storage.example.com".to_string(),
        );
        assert_eq!(opts.storage_url, "https://custom-storage.example.com");
    }

    // ===========================================
    // Executed money-path tests (the-composer #62)
    // ===========================================
    // `decide_payment` is the whole payment decision path over plain data
    // (no worker::Request/Response, which only exist on a live Workers
    // runtime), so these tests EXECUTE the ordering that matters on the
    // money path — consume-before-internalize, replay rejection, release
    // on wallet error, keep-consumed on wallet rejection, fail-closed on
    // storage faults — instead of only covering pure helpers (#29 lesson).

    mod decide {
        use super::*;
        use crate::storage::session_storage::MemorySessionStorage;
        use crate::types::AuthContext;

        /// Arbitrary but well-formed compressed pubkey for the paying client.
        const CLIENT_IDENTITY: &str =
            "028d37b941214cd53b6a1a02b4a9e1f0e0047e02f0acdb7bb0ac4a0212eab3ca10";
        /// Arbitrary bytes; the core only base64-decodes, never parses BEEF.
        const TX_B64: &str = "AQIDBA==";
        const PRICE: u64 = 500;

        fn server_wallet() -> ProtoWallet {
            ProtoWallet::new(Some(PrivateKey::from_hex(TEST_KEY_HEX).unwrap()))
        }

        fn auth() -> AuthContext {
            AuthContext::authenticated(CLIENT_IDENTITY.to_string())
        }

        /// A server-issued 402 challenge prefix, exactly as `Challenge`
        /// (and the deployed 402 builders) would hand to a client.
        async fn issued_prefix() -> String {
            create_nonce(&server_wallet(), None, ORIGINATOR)
                .await
                .unwrap()
        }

        fn header_for(prefix: &str) -> Option<String> {
            Some(
                serde_json::json!({
                    "derivationPrefix": prefix,
                    "derivationSuffix": "c3VmZml4",
                    "transaction": TX_B64,
                })
                .to_string(),
            )
        }

        /// Internalizer for paths that must reject BEFORE the wallet.
        async fn wallet_unreachable(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            panic!("internalizeAction must not be reached on this path");
        }

        async fn wallet_accepts(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "accepted": true }))
        }

        async fn wallet_rejects(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            Ok(serde_json::json!({ "accepted": false }))
        }

        async fn wallet_errors(
            _prefix: String,
            _suffix: String,
            _tx: Vec<u8>,
        ) -> Result<serde_json::Value> {
            Err(AuthCloudflareError::TransportError("wallet down".into()))
        }

        #[tokio::test]
        async fn misconfigured_auth_rejects_before_price_calculation() {
            // Express errors on missing req.auth BEFORE calling
            // calculateRequestPrice — the panicking closure pins the order.
            for ctx in [
                AuthContext::unauthenticated(),
                AuthContext {
                    identity_key: "unknown".to_string(),
                    is_authenticated: true,
                },
            ] {
                let decision = decide_payment(
                    &ctx,
                    || -> u64 { panic!("price must not be calculated without auth") },
                    None,
                    TEST_KEY_HEX,
                    Option::<&MemorySessionStorage>::None,
                    wallet_unreachable,
                )
                .await
                .unwrap();
                assert_eq!(decision, PaymentDecision::Misconfigured);
            }
        }

        #[tokio::test]
        async fn price_zero_is_free_before_header_inspection() {
            // Express short-circuits on requestPrice === 0 before ever
            // reading x-bsv-payment — even a garbage header passes.
            let store = MemorySessionStorage::default();
            let decision = decide_payment(
                &auth(),
                || 0,
                Some("garbage, never parsed".to_string()),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(decision, PaymentDecision::Free);
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn missing_header_yields_verifiable_challenge() {
            let store = MemorySessionStorage::default();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                None,
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap();
            match decision {
                PaymentDecision::Challenge {
                    price,
                    derivation_prefix,
                } => {
                    assert_eq!(price, PRICE);
                    let valid =
                        verify_nonce(&derivation_prefix, &server_wallet(), None, ORIGINATOR)
                            .await
                            .unwrap();
                    assert!(valid, "issued challenge prefix must verify");
                }
                other => panic!("expected Challenge, got {other:?}"),
            }
            // Challenges are consumed at redemption, not issuance.
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn malformed_header_rejected_without_store_writes() {
            let store = MemorySessionStorage::default();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                Some("not json".to_string()),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(decision, PaymentDecision::MalformedHeader);
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn foreign_prefix_fails_hmac_before_store_and_wallet() {
            let store = MemorySessionStorage::default();
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for("bm90LWEtcmVhbC1ub25jZQ=="),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(decision, PaymentDecision::InvalidPrefix);
            assert_eq!(store.consumed_count(), 0);
        }

        #[tokio::test]
        async fn bad_base64_tx_errs_without_burning_the_prefix() {
            // Decode happens BEFORE consumption: a malformed payload must
            // not burn the client's one-shot derivation prefix.
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            let header = serde_json::json!({
                "derivationPrefix": prefix,
                "derivationSuffix": "c3VmZml4",
                "transaction": "!!!not-base64!!!",
            })
            .to_string();
            let err = decide_payment(
                &auth(),
                || PRICE,
                Some(header),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, AuthCloudflareError::MalformedPayment(_)),
                "expected MalformedPayment, got {err:?}"
            );
            assert!(
                !store.is_consumed(PAYMENT_NONCE_SCOPE, &prefix),
                "prefix must survive a malformed transaction payload"
            );
        }

        #[tokio::test]
        async fn prefix_is_consumed_before_the_wallet_is_called() {
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            let wallet_called = std::cell::Cell::new(false);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                |seen_prefix: String, seen_suffix: String, tx: Vec<u8>| {
                    wallet_called.set(true);
                    assert_eq!(seen_prefix, prefix);
                    assert_eq!(seen_suffix, "c3VmZml4");
                    assert_eq!(tx, vec![1, 2, 3, 4], "decoded base64 of TX_B64");
                    assert!(
                        store.is_consumed(PAYMENT_NONCE_SCOPE, &prefix),
                        "prefix must already be consumed when internalize runs \
                         (concurrent duplicates must not both reach the wallet)"
                    );
                    async { Ok(serde_json::json!({ "accepted": true })) }
                },
            )
            .await
            .unwrap();
            assert!(wallet_called.get(), "accepting path must reach the wallet");
            assert_eq!(
                decision,
                PaymentDecision::Verified {
                    price: PRICE,
                    tx: TX_B64.to_string()
                }
            );
        }

        #[tokio::test]
        async fn redeemed_header_replay_is_rejected_before_the_wallet() {
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            let first = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_accepts,
            )
            .await
            .unwrap();
            assert!(matches!(first, PaymentDecision::Verified { .. }));

            // Byte-identical replay of the captured X-BSV-Payment header:
            // rejected pre-wallet (the shim's stateless path deferred this
            // to the upstream wallet's duplicate handling — issue #44).
            let replay = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(replay, PaymentDecision::ReplayedPrefix);
        }

        #[tokio::test]
        async fn wallet_rejection_keeps_prefix_consumed_and_issues_fresh_challenge() {
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_rejects,
            )
            .await
            .unwrap();
            match decision {
                PaymentDecision::WalletRejected {
                    price,
                    fresh_prefix,
                } => {
                    assert_eq!(price, PRICE);
                    assert_ne!(fresh_prefix, prefix, "challenge must be fresh");
                    let valid = verify_nonce(&fresh_prefix, &server_wallet(), None, ORIGINATOR)
                        .await
                        .unwrap();
                    assert!(valid, "fresh challenge prefix must verify");
                }
                other => panic!("expected WalletRejected, got {other:?}"),
            }
            assert!(
                store.is_consumed(PAYMENT_NONCE_SCOPE, &prefix),
                "a wallet-REJECTED payment's prefix stays consumed"
            );

            // Retrying the rejected payment replays a consumed prefix.
            let retry = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap();
            assert_eq!(retry, PaymentDecision::ReplayedPrefix);
        }

        #[tokio::test]
        async fn missing_accepted_field_fails_closed_end_to_end() {
            // internalize_accepted's fail-closed contract, executed through
            // the full decision path: no `accepted: true`, no Verified.
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                |_p: String, _s: String, _t: Vec<u8>| async {
                    Ok(serde_json::json!({ "satoshisPaid": PRICE }))
                },
            )
            .await
            .unwrap();
            assert!(matches!(decision, PaymentDecision::WalletRejected { .. }));
        }

        #[tokio::test]
        async fn wallet_error_releases_prefix_so_honest_retry_succeeds() {
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_errors,
            )
            .await
            .unwrap();
            match decision {
                PaymentDecision::InternalizeError { description } => {
                    assert!(
                        description.contains("wallet down"),
                        "error detail must flow to the 400 body: {description}"
                    );
                }
                other => panic!("expected InternalizeError, got {other:?}"),
            }
            assert!(
                !store.is_consumed(PAYMENT_NONCE_SCOPE, &prefix),
                "prefix released after a wallet ERROR (payment not processed)"
            );

            // The honest client retries the SAME real payment and succeeds.
            let retry = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_accepts,
            )
            .await
            .unwrap();
            assert!(matches!(retry, PaymentDecision::Verified { .. }));
        }

        #[tokio::test]
        async fn release_failure_is_best_effort_error_still_reported() {
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            store.fail_release(true);
            let decision = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_errors,
            )
            .await
            .unwrap();
            assert!(matches!(decision, PaymentDecision::InternalizeError { .. }));
            assert!(
                store.is_consumed(PAYMENT_NONCE_SCOPE, &prefix),
                "when release fails the prefix stays consumed (client must re-challenge)"
            );
        }

        #[tokio::test]
        async fn store_fault_during_consume_fails_closed() {
            // A storage fault must surface as Err (→ 500 ERR_STORAGE), never
            // silently disable replay protection.
            let store = MemorySessionStorage::default();
            let prefix = issued_prefix().await;
            store.fail_consume(true);
            let err = decide_payment(
                &auth(),
                || PRICE,
                header_for(&prefix),
                TEST_KEY_HEX,
                Some(&store),
                wallet_unreachable,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, AuthCloudflareError::KvError(_)),
                "expected KvError, got {err:?}"
            );
        }

        #[tokio::test]
        async fn stateless_path_still_permits_replay() {
            // The deprecated process_payment (nonce_store: None) semantics —
            // the boundary the storage worker's #[allow(deprecated)] shim
            // sat on until the-composer #62: a byte-identical replay reaches
            // the wallet again, bounded only by its duplicate handling.
            let prefix = issued_prefix().await;
            for _ in 0..2 {
                let decision = decide_payment(
                    &auth(),
                    || PRICE,
                    header_for(&prefix),
                    TEST_KEY_HEX,
                    Option::<&MemorySessionStorage>::None,
                    wallet_accepts,
                )
                .await
                .unwrap();
                assert!(matches!(decision, PaymentDecision::Verified { .. }));
            }
        }
    }
}
