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
│   ├── auth.rs         — process_auth[_with_storage](), sign_response(), sign_json_response(),
│   │                     per-request nonce replay protection, CORS helpers
│   ├── payment.rs      — process_payment_with_storage() (accepted gate + single-use
│   │                     prefixes), deprecated stateless process_payment(), 402 builder
│   └── multipart.rs    — BRC-105 multipart payment transport parsing
├── storage/
│   ├── session_storage.rs — SessionStorage trait (sessions + single-use nonce store)
│   ├── kv_session.rs   — BRC-103/104 session persistence, identity index, nonce consumption
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
- **Replay protection is a deliberate hardening divergence from the TS reference**
  (the-composer audit #30/#44). The TS stack (`@bsv/sdk` `Peer.processGeneralMessage`,
  checked through v2.0.13) never records consumed per-request nonces; this crate
  consumes `(session_nonce, x-bsv-auth-nonce)` via `SessionStorage::try_consume_nonce`
  after signature verification and 401s reuse with `ERR_REPLAYED_REQUEST`. Payment
  derivation prefixes are likewise single-use: consumed (no expiry) *before*
  internalize, kept consumed on `accepted:false`, released best-effort on internalize
  *error* only. Residual window under eventually-consistent KV is documented in the
  `middleware/auth.rs` module docs and `KvSessionStorage::try_consume_nonce`.
- **`accepted` gate on internalize** (audit #44). `PaymentResult::Verified` implies the
  wallet affirmatively returned `accepted: true`; anything else 402s with a fresh
  challenge. The TS reference calls `next()` regardless of `accepted`.
- **`process_payment` is deprecated** (stateless — no single-use prefixes). Use
  `process_payment_with_storage`; the `SessionStorage` doubles as the nonce store.
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
| 401 | `UNAUTHORIZED` / `ERR_INVALID_AUTH` / `ERR_SESSION_NOT_FOUND` / `ERR_REPLAYED_REQUEST`¹ | auth |
| 402 | `ERR_PAYMENT_REQUIRED` / `ERR_PAYMENT_FAILED`¹ (wallet rejected, fresh challenge attached) | payment |
| 500 | `ERR_SERVER_MISCONFIGURED` / `ERR_PAYMENT_INTERNAL` / `ERR_STORAGE` / `ERR_SDK` / `ERR_TRANSPORT` / `ERR_CONFIG` | payment / infra |

¹ Not in the Express reference — hardening additions (audit #30/#44).

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
