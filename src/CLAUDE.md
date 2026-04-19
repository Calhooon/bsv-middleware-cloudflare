# bsv-middleware-cloudflare/src

> BSV blockchain authentication and payment middleware for Cloudflare Workers.

## Overview

This crate provides BRC-103/104 authentication and BRC-29 (Direct Payment) middleware for Cloudflare Workers. It enables building authenticated and paid APIs using BSV blockchain-based identity and micropayments. The implementation uses Cloudflare KV for session and payment storage, with built-in CORS support for browser clients.

This is a 1:1 port of the Express-based `auth-express-middleware` and `payment-express-middleware`, adapted for Cloudflare Workers. Error codes and response formats match the Express versions exactly.

## Architecture

```
lib.rs                    # Crate entry point, re-exports, init_panic_hook()
├── env.rs               # Cloudflare environment helpers (WorkerEnv)
├── error.rs             # AuthCloudflareError enum with HTTP status codes
├── types.rs             # Core data structures and current_time_ms()
├── client/              # Storage server RPC client
│   ├── json_rpc.rs      # JSON-RPC 2.0 request/response types
│   └── storage.rs       # WorkerStorageClient with BRC-103/104 auth
├── middleware/          # Request processing middleware
│   ├── auth.rs          # BRC-103/104 authentication + response signing + CORS
│   └── payment.rs       # BRC-29 payment verification and 402 responses
├── storage/             # Cloudflare KV persistence
│   ├── kv_session.rs    # Session storage with TTL
│   └── kv_payment.rs    # Payment storage with duplicate detection
├── transport/           # HTTP transport layer
│   └── cloudflare.rs    # BRC-104 header handling + payload serialization
└── utils/               # Utilities
    └── cors.rs          # CorsConfig and CORS header helpers
```

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root with re-exports and `init_panic_hook()` for WASM error handling |
| `env.rs` | `WorkerEnv` wrapper for accessing Cloudflare secrets and KV bindings |
| `error.rs` | `AuthCloudflareError` enum with HTTP status codes, error codes, and JSON serialization |
| `types.rs` | Core types: `AuthContext`, `PaymentContext`, `BsvPayment`, `ErrorResponse`, `StoredSession`, `StoredPayment`, `current_time_ms()` |
| `client/mod.rs` | Re-exports `WorkerStorageClient`, `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError` |
| `client/json_rpc.rs` | JSON-RPC 2.0 types with tolerant deserialization (handles non-standard `{isError, name, message}` format from storage servers) |
| `client/storage.rs` | `WorkerStorageClient` - WASM-compatible storage client with BRC-103/104 auth handshake |
| `middleware/mod.rs` | Re-exports for auth and payment middleware |
| `middleware/auth.rs` | BRC-103/104 authentication, `sign_response()`, `sign_json_response()`, inline CORS (`add_cors_headers`, `handle_cors_preflight`), handshake handling (InitialRequest, CertificateRequest, CertificateResponse). `process_auth` returns raw body bytes via `AuthResult::Authenticated { body }` for General messages. |
| `middleware/payment.rs` | BRC-29 payment verification, 402 response generation, `payment_headers` module (incl. `TXID`), `payment_failed_response()` |
| `storage/mod.rs` | Re-exports for KV storage implementations |
| `storage/kv_session.rs` | `KvSessionStorage` for BRC-103/104 session persistence with identity index |
| `storage/kv_payment.rs` | `KvPaymentStorage` for payment records with unspent/derivation tracking |
| `transport/mod.rs` | Re-exports for transport layer |
| `transport/cloudflare.rs` | `CloudflareTransport` for BRC-104 header extraction (incl. `content-type` media type), payload building, varint encoding. `extract_auth_message()` returns `(AuthMessage, Vec<u8>)` with raw body passthrough. |
| `utils/mod.rs` | Re-exports for utility functions |
| `utils/cors.rs` | `CorsConfig`, `cors_headers()`, preflight handlers, response helpers |

## Key Exports

### Main Entry Points (from `lib.rs`)

| Export | Description |
|--------|-------------|
| `process_auth` | Main authentication middleware function |
| `process_payment` | Main payment middleware function |
| `sign_response` | Sign a response for BRC-103/104 interop (required for authenticated clients) |
| `sign_json_response` | Sign a JSON response with body bytes included in signed payload (recommended over `sign_response`) |
| `WorkerStorageClient` | Storage server RPC client with BRC-103/104 authentication (re-exported from `client`) |
| `init_panic_hook` | Initialize WASM panic hook for better error messages |

### Middleware Types

| Type | Description |
|------|-------------|
| `AuthMiddlewareOptions` | Config: `server_private_key`, `allow_unauthenticated`, `certificates_to_request`, `session_ttl_seconds`, `on_certificates_received` |
| `AuthResult` | Enum: `Authenticated { context, request, session, body }` or `Response(Response)`. `body` is the raw request body bytes (populated for General messages, empty for handshake/unauthenticated). |
| `AuthSession` | Session info for signing responses: `server_private_key`, `session_nonce`, `peer_nonce`, `peer_identity_key`, `request_id` |
| `PaymentMiddlewareOptions<F>` | Config: `server_private_key`, `calculate_price` function (`Fn(&Request) -> u64`), `storage_url` (defaults to mainnet). Constructors: `new()`, `with_storage_url()` |
| `PaymentResult` | Enum: `Free`, `Required(Response)`, `Verified(PaymentContext)`, `Failed(Response)` |

### Context Types

| Type | Description |
|------|-------------|
| `AuthContext` | Authenticated peer info: `identity_key: String`, `is_authenticated: bool`. Factory methods: `authenticated()`, `unauthenticated()` |
| `PaymentContext` | Payment info: `satoshis_paid: u64`, `accepted: bool`, `tx: Option<String>` (base64 transaction) |

### Storage Types

| Type | Description |
|------|-------------|
| `KvSessionStorage` | Session manager backed by Cloudflare KV with TTL expiration and identity index |
| `KvPaymentStorage` | Payment storage with duplicate detection, unspent tracking, and derivation prefix management |
| `StoredSession` | Persisted session: `session_nonce`, `peer_identity_key`, `peer_nonce`, `is_authenticated`, `certificates_required`, `certificates_validated`, timestamps |
| `StoredPayment` | Persisted payment: `txid`, `vout`, `satoshis`, `sender_identity_key`, derivation info, `spent` flag |

### Transport Types

| Type | Description |
|------|-------------|
| `CloudflareTransport` | Static methods for BRC-104 header extraction, message construction, payload building, and `create_headers()` helper. `extract_auth_message()` returns `(AuthMessage, Vec<u8>)` where the second element is raw body bytes (populated for General messages, empty for handshake). |
| `HttpRequestData` | Deserialized request from General message payload: `request_id`, `method`, `path`, `search`, `headers`, `body`. Has `url()` method combining path + search. |
| `HttpResponseData` | HTTP response data for General message serialization: `request_id`, `status`, `headers`, `body` |
| `auth_headers` | Module with BRC-104 header name constants (including `INITIAL_NONCE`) |

### Client Types

| Type | Description |
|------|-------------|
| `WorkerStorageClient` | WASM-compatible RPC client for `storage.babbage.systems` with BRC-103/104 auth. Uses `worker::Fetch` for HTTP. Methods: `rpc_call()`, `make_available()`, `find_or_insert_user()`, `internalize_action()`, `list_outputs()` |
| `JsonRpcRequest` | JSON-RPC 2.0 request: `jsonrpc`, `method`, `params`, `id`. Factory: `new(id, method, params)` |
| `JsonRpcResponse` | JSON-RPC 2.0 response: `result`, `error`, `id` |
| `JsonRpcError` | JSON-RPC error with optional fields: `code`, `message`, `data`, `name`. Handles both standard and non-standard (storage server) error formats. Implements `Display`. |

`WorkerStorageClient` endpoints:
- `WorkerStorageClient::mainnet(wallet)` - connects to `https://storage.babbage.systems`
- `WorkerStorageClient::testnet(wallet)` - connects to `https://staging-storage.babbage.systems`
- `WorkerStorageClient::new(wallet, url)` - connects to custom endpoint

### Error Handling

| Type | Description |
|------|-------------|
| `AuthCloudflareError` | Error enum with variants for auth, payment, and infrastructure errors |
| `Result<T>` | Alias for `std::result::Result<T, AuthCloudflareError>` |

### Utility Types and Functions

| Export | Description |
|--------|-------------|
| `CorsConfig` | Configurable CORS settings: origins, methods, headers, expose headers, max age |
| `cors_headers()` | Create CORS headers with default config (from `utils::cors`) |
| `cors_headers_with_config()` | Create CORS headers with custom config (from `utils::cors`) |
| `handle_cors_preflight()` | Handle OPTIONS preflight with default CORS (from `utils::cors`) |
| `handle_cors_preflight_with_config()` | Handle OPTIONS preflight with custom CORS config |
| `add_cors_to_response()` | Add default CORS headers to existing response |
| `add_cors_to_response_with_config()` | Add custom CORS headers to existing response |
| `add_cors_headers()` | Inline CORS from `middleware::auth` (includes all BSV auth + payment headers, including `x-bsv-payment-txid`). Appends to existing response headers (does not replace). |
| `add_payment_headers()` | Add payment success headers (`x-bsv-payment-satoshis-paid`) to response |
| `payment_headers` | Module with BRC-29 payment header name constants (including `TXID`) |
| `payment_failed_response()` | Creates a 400 error response for payment failures with CORS |
| `ErrorResponse` | Serializable error body: `status`, `code`, `description` |

## Usage

### Authentication with Response Signing

```rust
use bsv_middleware_cloudflare::{
    process_auth, sign_json_response, AuthMiddlewareOptions, AuthResult,
    utils::handle_cors_preflight,
};
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Handle CORS preflight
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    let auth_options = AuthMiddlewareOptions {
        server_private_key: env.secret("SERVER_PRIVATE_KEY")?.to_string(),
        allow_unauthenticated: false,
        ..Default::default()
    };

    let (auth_context, req, session, _body) = match process_auth(req, &env, &auth_options).await
        .map_err(|e| Error::from(e.to_string()))?
    {
        AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
        AuthResult::Response(response) => return Ok(response),
    };

    // Build response data
    let data = serde_json::json!({
        "identity": auth_context.identity_key
    });

    // Sign the response before returning (recommended: includes body in signed payload)
    if let Some(ref session) = session {
        sign_json_response(&data, 200, &[], session)
            .map_err(|e| Error::from(e.to_string()))
    } else {
        Response::from_json(&data)
    }
}
```

### Adding Payment Verification

```rust
use bsv_middleware_cloudflare::{
    process_auth, process_payment, sign_json_response,
    AuthMiddlewareOptions, PaymentMiddlewareOptions,
    AuthResult, PaymentResult,
};

// After authentication...
let payment_options = PaymentMiddlewareOptions::new(
    server_key,
    |req: &Request| {
        // Price function: return satoshis required for this request
        if req.path().starts_with("/premium") { 1000 } else { 100 }
    },
);

// Note: process_payment takes (&Request, &AuthContext, &PaymentMiddlewareOptions)
match process_payment(&req, &auth_context, &payment_options).await
    .map_err(|e| Error::from(e.to_string()))?
{
    PaymentResult::Free => { /* No payment needed */ }
    PaymentResult::Verified(payment_ctx) => {
        // payment_ctx.satoshis_paid, payment_ctx.tx
    }
    PaymentResult::Required(response) => return Ok(response), // 402
    PaymentResult::Failed(response) => return Ok(response),   // 400
}
```

### Environment Wrapper

```rust
use bsv_middleware_cloudflare::env::WorkerEnv;

let worker_env = WorkerEnv::new(&env);
let server_key = worker_env.get_server_private_key()?;
let auth_kv = worker_env.get_auth_sessions_kv()?;
let payments_kv = worker_env.get_payments_kv()?;
let environment = worker_env.get_environment(); // "production" default
```

### Storage Client

```rust
use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_sdk::wallet::ProtoWallet;

// Create client (performs BRC-103/104 handshake on first RPC call)
let wallet = ProtoWallet::from_private_key(&server_key)?;
let mut client = WorkerStorageClient::mainnet(wallet);

// Make authenticated RPC calls to storage server
let result = client.make_available().await?;
let user = client.find_or_insert_user(&identity_key).await?;
let internalized = client.internalize_action(auth_json, args_json).await?;
let outputs = client.list_outputs(auth_json, args_json).await?;
```

## Response Signing: `sign_response` vs `sign_json_response`

Two functions exist for signing responses. Prefer `sign_json_response` when possible.

| Function | Body in Signature | Use Case |
|----------|-------------------|----------|
| `sign_response(response, session)` | No (empty body in payload) | Legacy; when you already have a `Response` object |
| `sign_json_response(data, status, extra_headers, session)` | Yes (actual JSON bytes) | Recommended; matches Express `res.json()` hijacking behavior |

`sign_json_response` also filters `extra_headers` for signing: only `x-bsv-*` (excluding `x-bsv-auth-*`) and `authorization` headers are included in the signed payload, matching `SimplifiedFetchTransport` rules. All extra headers appear in the HTTP response regardless.

Note: `extract_signable_headers` in the transport layer also includes the `content-type` header (stripped to media type only, params like `; charset=utf-8` removed), matching TS SDK behavior.

## BRC Standards Implementation

### BRC-103/104

The authentication flow handles:
1. **Initial handshake** at `/.well-known/auth` - exchanges nonces and identity keys
2. **Certificate exchange** - CertificateRequest/CertificateResponse for identity verification (both directions)
3. **General requests** - signature verification using session nonces
4. **Response signing** - `sign_json_response()` / `sign_response()` signs outgoing responses for BRC-103/104 interop

Message types handled:
- `InitialRequest` / `InitialResponse` - session establishment
- `CertificateRequest` / `CertificateResponse` - certificate exchange (both directions)
- `General` - authenticated API requests (via headers) and signed responses

Key difference from Express: Express uses response hijacking (`res.send`/`res.json` interception). Workers cannot do this, so `sign_json_response()` (or `sign_response()`) must be called explicitly before returning responses to authenticated clients.

### BRC-29 (Direct Payment)

Payment flow:
1. Client makes request without payment
2. Server returns **402 Payment Required** with `derivation_prefix` and `satoshis_required`
3. Client constructs payment transaction, sends with `x-bsv-payment` header (JSON)
4. Server verifies derivation prefix via HMAC nonce, internalizes payment via `WorkerStorageClient::internalize_action()`, returns success

Payment uses `ProtoWallet` for nonce creation/verification and `WorkerStorageClient` (connected to `storage.babbage.systems` by default) for transaction processing. The `storage_url` field on `PaymentMiddlewareOptions` controls the storage server endpoint.

### BRC-104 (HTTP Headers)

Auth headers (in `transport::auth_headers`):
- `x-bsv-auth-version` - Protocol version
- `x-bsv-auth-identity-key` - Sender's public key (66-char hex)
- `x-bsv-auth-nonce` / `x-bsv-auth-your-nonce` - Session nonces
- `x-bsv-auth-initial-nonce` - Initial handshake nonce
- `x-bsv-auth-signature` - Message signature (hex)
- `x-bsv-auth-message-type` - Message type string
- `x-bsv-auth-request-id` - 32-byte request correlation ID (base64)
- `x-bsv-auth-requested-certificates` - Certificate specification (JSON)

Payment headers (in `middleware::payment::payment_headers`):
- `x-bsv-payment` - Payment JSON (derivation info + base64 BEEF transaction)
- `x-bsv-payment-version` - Payment protocol version ("1.0")
- `x-bsv-payment-satoshis-required` - Amount required
- `x-bsv-payment-derivation-prefix` - Server-generated nonce for address derivation
- `x-bsv-payment-satoshis-paid` - Amount paid (response)
- `x-bsv-payment-txid` - Transaction ID of the accepted payment (response)

## Critical Implementation Notes

### Nonce Handling (TS SDK Compatibility)

**Never update `peer_nonce` after handshake for General messages.** The TS SDK sets `peerSession.peerNonce` once during handshake and never updates it for General messages. The per-message nonce in General messages is a random value (not HMAC-derived). Storing it as `peer_nonce` causes:
1. Response `yourNonce` mismatch -> client's `verifyNonce` fails
2. `processGeneralMessage` throws -> general message callbacks never fire
3. `AuthFetch` Promise never resolves -> 402 payment handling breaks
4. Signature `keyID` mismatch (uses `peer_nonce`, client expects handshake nonce)

### InitialResponse Signature Verification (TS SDK Compatibility)

The TS SDK computes signing data as `Buffer.from(clientNonce + serverNonce, 'base64')`, which due to Node.js `Buffer.from` stopping at the first `=` padding, only decodes the first nonce's raw bytes (32 bytes). The Rust client (`WorkerStorageClient`) matches this by using only the client's session nonce as signing data, not the concatenation of both nonces.

### Raw Body Passthrough

`process_auth` now returns raw request body bytes via `AuthResult::Authenticated { body }`. For General (authenticated) messages, this contains the original request body consumed during auth payload construction. For handshake and unauthenticated requests, this is empty (`vec![]`). This allows downstream handlers to access the body without re-reading the request (which would fail since Workers consume the body stream).

### CORS Headers (add_cors_headers)

The `add_cors_headers()` function in `middleware::auth` uses `response.headers()` to append to existing headers rather than creating new `Headers` and calling `with_headers()`. This is critical because `with_headers()` replaces all existing headers, which would strip auth headers added by `sign_json_response`.

## Error Handling

`AuthCloudflareError` provides:
- `status_code()` - HTTP status (400, 401, 402, 500)
- `error_code()` - Machine-readable code matching Express middleware exactly
- `to_json()` - JSON response body with `{ status, code, description }`

Error variants and their codes (matching Express middleware):

| Variant | Status | Code | Category |
|---------|--------|------|----------|
| `Unauthorized` | 401 | `UNAUTHORIZED` | Auth |
| `InvalidAuthentication(String)` | 401 | `ERR_INVALID_AUTH` | Auth |
| `SessionNotFound(String)` | 401 | `ERR_SESSION_NOT_FOUND` | Auth |
| `ServerMisconfigured` | 500 | `ERR_SERVER_MISCONFIGURED` | Payment |
| `PaymentInternal(String)` | 500 | `ERR_PAYMENT_INTERNAL` | Payment |
| `PaymentRequired { satoshis, derivation_prefix }` | 402 | `ERR_PAYMENT_REQUIRED` | Payment |
| `MalformedPayment(String)` | 400 | `ERR_MALFORMED_PAYMENT` | Payment |
| `InvalidDerivationPrefix` | 400 | `ERR_INVALID_DERIVATION_PREFIX` | Payment |
| `PaymentFailed(String)` | 400 | `ERR_PAYMENT_FAILED` | Payment |
| `InvalidPayment(String)` | 400 | `ERR_INVALID_PAYMENT` | Payment |
| `KvError(String)` | 500 | `ERR_STORAGE` | Infra |
| `SdkError(String)` | 500 | `ERR_SDK` | Infra |
| `TransportError(String)` | 500 | `ERR_TRANSPORT` | Infra |
| `ConfigError(String)` | 500 | `ERR_CONFIG` | Infra |
| `SerializationError(String)` | 400 | `ERR_SERIALIZATION` | Infra |

Automatic `From` conversions: `bsv_sdk::Error` -> `SdkError`, `worker::Error` -> `KvError`, `serde_json::Error` -> `SerializationError`.

## Cloudflare Configuration

### Required KV Namespaces

Add to `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "AUTH_SESSIONS"
id = "your-kv-id-here"

[[kv_namespaces]]
binding = "PAYMENTS"
id = "your-payments-kv-id-here"
```

### Required Secrets

```bash
wrangler secret put SERVER_PRIVATE_KEY
# Enter 64-character hex secp256k1 private key
```

### Optional Environment Variables

- `ENVIRONMENT` - Runtime environment name (default: `"production"`)

## Storage Schema

### Session Keys (KvSessionStorage)

- `{prefix}:session:{session_nonce}` - Session JSON with TTL
- `{prefix}:identity:{identity_key}:{session_nonce}` - Index for identity lookups (value = session_nonce)

### Payment Keys (KvPaymentStorage)

- `{prefix}:payment:{txid}:{vout}` - Payment record JSON (no TTL)
- `{prefix}:unspent:{txid}:{vout}` - Unspent output index
- `{prefix}:derivation:{derivation_prefix}` - One-time derivation prefix with TTL

## Dependencies

- `bsv_sdk` - BSV primitives, wallet (`ProtoWallet`, `WalletInterface`), auth protocol, nonce utils
- `worker` - Cloudflare Workers runtime (Request, Response, KV, Headers)
- `serde` / `serde_json` - Serialization
- `thiserror` - Error derive macros
- `hex` - Hex encoding/decoding
- `js_sys` - JavaScript interop for `Date.now()`
- `rand` - Random number generation (used by client for request IDs)
- `getrandom` - Random nonce generation
- `console_error_panic_hook` - WASM panic handling (optional, gated on `wasm32`)

## Related

- `../Cargo.toml` - Crate dependencies and features
- `../../bsv-sdk/` - Core BSV SDK with auth protocol implementation
