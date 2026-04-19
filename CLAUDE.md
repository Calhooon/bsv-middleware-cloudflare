# bsv-middleware-cloudflare

BSV authentication and payment middleware for Cloudflare Workers. Rust compiled to WASM.
Port of `auth-express-middleware` (BRC-103/104) and `payment-express-middleware` (BRC-29),
adapted for the Workers runtime (KV for state, async everywhere, explicit response signing).

**Detailed module-level docs are in `src/CLAUDE.md`.** This file is a quick orientation.

## Build

```bash
cargo check --target wasm32-unknown-unknown
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo test --lib
worker-build --release           # WASM binary (only for the example server)
```

No CI — you enforce the gates.

## Layout

```
src/
├── lib.rs              — crate entry, re-exports, init_panic_hook()
├── env.rs              — WorkerEnv: wraps Env for KV + secret access
├── error.rs            — AuthCloudflareError with Express-compatible codes
├── types.rs            — AuthContext, PaymentContext, StoredSession, StoredPayment
├── middleware/
│   ├── auth.rs         — process_auth(), sign_response(), sign_json_response(),
│   │                     CORS helpers (add_cors_headers, handle_cors_preflight)
│   ├── payment.rs      — process_payment(), 402 response builder, payment headers
│   └── multipart.rs    — BRC-105 multipart payment transport parsing
├── storage/
│   ├── kv_session.rs   — BRC-103/104 session persistence, identity index
│   └── kv_payment.rs   — payment records, unspent tracking, derivation prefix lifecycle
├── client/
│   ├── json_rpc.rs     — JSON-RPC 2.0 types with tolerant deserialization
│   └── storage.rs      — WorkerStorageClient: auth'd RPC to a wallet storage server
├── transport/
│   └── cloudflare.rs   — CloudflareTransport: BRC-104 header extraction, payload build
├── refund/             — feature-gated BRC-41 refund builder
└── utils/
    └── cors.rs         — CorsConfig and preflight helpers
```

## Key patterns

- **Raw body passthrough.** `process_auth` returns the original request bytes via
  `AuthResult::Authenticated { body }`. Workers consume the body stream during auth
  payload construction, so downstream handlers must use this `body` instead of
  re-reading the request.
- **Never update `peer_nonce` for General messages.** The TS SDK sets `peerNonce`
  once at handshake and treats the per-message nonce as random. Storing the
  per-message nonce breaks `yourNonce` verification and kills the AuthFetch promise.
  See nonce handling notes in `src/CLAUDE.md`.
- **`sign_json_response` over `sign_response`.** The former includes body bytes in
  the signed payload, matching Express's `res.json` hijacking behavior. Use it
  unless you already have a constructed `Response`.
- **`add_cors_headers` appends.** It uses `response.headers()` rather than
  `with_headers()` so it doesn't strip auth headers added by `sign_json_response`.
- **InitialResponse signing data = client nonce only.** The TS SDK's
  `Buffer.from(clientNonce + serverNonce, 'base64')` stops at the first `=` padding
  and effectively only decodes the client nonce. `WorkerStorageClient` matches.
- **Dual-license.** `MIT OR Apache-2.0`. Both LICENSE files live at the crate root.

## Error codes (Express parity)

| Status | Code | Variant |
|---|---|---|
| 400 | `ERR_MALFORMED_PAYMENT` / `ERR_INVALID_DERIVATION_PREFIX` / `ERR_PAYMENT_FAILED` / `ERR_INVALID_PAYMENT` / `ERR_SERIALIZATION` | payment / serialization |
| 401 | `UNAUTHORIZED` / `ERR_INVALID_AUTH` / `ERR_SESSION_NOT_FOUND` | auth |
| 402 | `ERR_PAYMENT_REQUIRED` | payment |
| 500 | `ERR_SERVER_MISCONFIGURED` / `ERR_PAYMENT_INTERNAL` / `ERR_STORAGE` / `ERR_SDK` / `ERR_TRANSPORT` / `ERR_CONFIG` | payment / infra |

Full table with `From` conversions in `src/CLAUDE.md`.

## Headers (BRC-104 + BRC-29)

All headers match the Express middleware. See `transport::auth_headers` and
`middleware::payment::payment_headers` for constants.

Auth: `x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-nonce`,
`x-bsv-auth-your-nonce`, `x-bsv-auth-initial-nonce`, `x-bsv-auth-signature`,
`x-bsv-auth-message-type`, `x-bsv-auth-request-id`, `x-bsv-auth-requested-certificates`.

Payment: `x-bsv-payment`, `x-bsv-payment-version`, `x-bsv-payment-satoshis-required`,
`x-bsv-payment-derivation-prefix`, `x-bsv-payment-satoshis-paid`, `x-bsv-payment-txid`,
`x-bsv-payment-transports` (BRC-105 negotiation).

## Reference code

| What | Where |
|---|---|
| Express auth middleware (reference) | `~/bsv/auth-express-middleware/` |
| Express payment middleware (reference) | `~/bsv/payment-express-middleware/` |
| BSV SDK (used for auth, wallet, transaction) | `~/bsv/bsv-rs/` (crates.io: `bsv-rs = "0.3"`) |
| Consumer example | `~/bsv/rust-message-box/` |
| Agent consumers | `~/bsv/agents/{banana-agent,claude-agent,...}` |
