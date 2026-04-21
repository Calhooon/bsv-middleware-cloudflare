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
    /// Defaults to `WorkerStorageClient::MAINNET_URL` ("https://storage.babbage.systems").
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

/// Process payment for a request.
///
/// This is a 1:1 port of payment-express-middleware's `createPaymentMiddleware`.
///
/// **IMPORTANT**: Auth middleware MUST run before this. The `auth_context` parameter
/// must come from successful authentication. If `auth_context` is not properly
/// authenticated, this returns ERR_SERVER_MISCONFIGURED (matching Express behavior
/// when `req.auth.identityKey` is missing).
pub async fn process_payment<F>(
    req: &Request,
    auth_context: &AuthContext,
    options: &PaymentMiddlewareOptions<F>,
) -> Result<PaymentResult>
where
    F: Fn(&Request) -> u64,
{
    // Step 1: Verify auth middleware ran first (matches Express check for req.auth.identityKey)
    if !auth_context.is_authenticated || auth_context.identity_key == "unknown" {
        let response = Response::from_json(&ErrorResponse::new(
            "ERR_SERVER_MISCONFIGURED",
            "The payment middleware must be executed after the Auth middleware.",
        ))
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(500);
        return Ok(PaymentResult::Failed(add_cors_headers(response)));
    }

    // Step 2: Calculate price
    let price = (options.calculate_price)(req);

    // Step 3: If price is 0, proceed immediately (matches Express: `req.payment = { satoshisPaid: 0 }`)
    if price == 0 {
        return Ok(PaymentResult::Free);
    }

    // Create wallet for nonce operations
    let private_key = PrivateKey::from_hex(&options.server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Step 4: Check for payment header
    let payment_header = req.headers().get(payment_headers::PAYMENT).ok().flatten();

    match payment_header {
        None => {
            // No payment provided - generate nonce and return 402
            // Matches Express: `const derivationPrefix = await createNonce(wallet)`
            let derivation_prefix = create_nonce(&wallet, None, ORIGINATOR).await?;

            // Build 402 response with payment headers
            // Matches Express response exactly
            let headers = {
                let h = Headers::new();
                let _ = h.set(payment_headers::VERSION, PAYMENT_VERSION);
                let _ = h.set(payment_headers::SATOSHIS_REQUIRED, &price.to_string());
                let _ = h.set(payment_headers::DERIVATION_PREFIX, &derivation_prefix);
                let _ = h.set(payment_headers::TRANSPORTS, "header,multipart");
                h
            };

            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": price,
                "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
            });

            let response = Response::from_json(&body)
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                .with_status(402)
                .with_headers(headers);

            Ok(PaymentResult::Required(add_cors_headers(response)))
        }
        Some(payment_json) => {
            // Payment provided - parse and verify
            // Step 5: Parse payment JSON
            // Express: `paymentData = JSON.parse(String(bsvPaymentHeader))`
            let payment: BsvPayment = match serde_json::from_str(&payment_json) {
                Ok(p) => p,
                Err(_) => {
                    // Express catches parse error and returns ERR_MALFORMED_PAYMENT
                    let response = Response::from_json(&ErrorResponse::new(
                        "ERR_MALFORMED_PAYMENT",
                        "The X-BSV-Payment header is not valid JSON.",
                    ))
                    .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                    .with_status(400);
                    return Ok(PaymentResult::Failed(add_cors_headers(response)));
                }
            };

            // Step 6: Verify derivation prefix (nonce)
            // Express: `const valid = await verifyNonce(paymentData.derivationPrefix, wallet)`
            let nonce_valid = verify_nonce(&payment.derivation_prefix, &wallet, None, ORIGINATOR)
                .await
                .unwrap_or_default();

            if !nonce_valid {
                // Express: returns ERR_INVALID_DERIVATION_PREFIX
                let response = Response::from_json(&ErrorResponse::new(
                    "ERR_INVALID_DERIVATION_PREFIX",
                    "The X-BSV-Payment-Derivation-Prefix header is not valid.",
                ))
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                .with_status(400);
                return Ok(PaymentResult::Failed(add_cors_headers(response)));
            }

            // Step 7: Process payment via WorkerStorageClient.internalizeAction()
            // This mirrors how the TS Express middleware calls wallet.internalizeAction(),
            // where the wallet is a remote client (WalletClient) to storage.babbage.systems.
            //
            // Express equivalent:
            //   const { accepted } = await wallet.internalizeAction({
            //     tx: Utils.toArray(paymentData.transaction, 'base64'),
            //     outputs: [{ paymentRemittance: { derivationPrefix, derivationSuffix, senderIdentityKey }, outputIndex: 0, protocol: 'wallet payment' }],
            //     description: 'Payment for request'
            //   })
            let tx_bytes = from_base64(&payment.transaction).map_err(|_| {
                AuthCloudflareError::MalformedPayment("Invalid base64 transaction data".to_string())
            })?;

            // Create storage client for this request.
            // Creates a BRC-103/104 session with the storage server on first RPC call.
            // Sequence: makeAvailable → findOrInsertUser → internalizeAction
            // (matches wallet-toolbox StorageClient initialization pattern)
            let storage_wallet = ProtoWallet::new(Some(
                PrivateKey::from_hex(&options.server_private_key).map_err(|e| {
                    AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
                })?,
            ));
            let mut storage_client = WorkerStorageClient::new(storage_wallet, &options.storage_url);

            // Initialize connection and register user
            storage_client.make_available().await?;
            let server_identity = wallet.identity_key().to_hex();
            let user_result: serde_json::Value =
                storage_client.find_or_insert_user(&server_identity).await?;
            let user_id = user_result.get("userId").and_then(|v| v.as_i64());

            let auth_json = serde_json::json!({
                "identityKey": server_identity,
                "userId": user_id
            });
            let args_json = serde_json::json!({
                "tx": tx_bytes,
                "outputs": [{
                    "outputIndex": 0,
                    "protocol": "wallet payment",
                    "paymentRemittance": {
                        "derivationPrefix": payment.derivation_prefix,
                        "derivationSuffix": payment.derivation_suffix,
                        "senderIdentityKey": auth_context.identity_key
                    },
                    "insertionRemittance": null
                }],
                "description": "Payment for request"
            });

            let internalize_result: std::result::Result<serde_json::Value, _> = storage_client
                .internalize_action(auth_json, args_json)
                .await;

            match internalize_result {
                Ok(result) => {
                    // Success - matches Express: req.payment = { satoshisPaid, accepted, tx }
                    let accepted = result
                        .get("accepted")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    Ok(PaymentResult::Verified(PaymentContext {
                        satoshis_paid: price,
                        accepted,
                        tx: Some(payment.transaction),
                    }))
                }
                Err(e) => {
                    // Express: catch(err) => res.status(400).json({ code: err.code ?? 'ERR_PAYMENT_FAILED', description: err.message ?? 'Payment failed.' })
                    let response = Response::from_json(&ErrorResponse::new(
                        "ERR_PAYMENT_FAILED",
                        e.to_string(),
                    ))
                    .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                    .with_status(400);
                    Ok(PaymentResult::Failed(add_cors_headers(response)))
                }
            }
        }
    }
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
}
