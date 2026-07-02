# bsv-middleware-cloudflare

BSV authentication and payment middleware for Cloudflare Workers. Rust compiled to WASM.

Port of [`auth-express-middleware`](https://github.com/bitcoin-sv/auth-express-middleware) and [`payment-express-middleware`](https://github.com/bitcoin-sv/payment-express-middleware) for the Cloudflare Workers runtime. Implements BRC-103/104 mutual identity auth and BRC-29 direct payments, with session and payment state persisted in Cloudflare KV. Error codes, HTTP statuses, and header names match the Express versions.

## What it provides

- **`process_auth`** / **`process_auth_with_storage`** — BRC-103/104 mutual identity handshake, session verification, certificate exchange, and per-request replay protection (each `x-bsv-auth-nonce` is single-use per session). Returns the authenticated identity key, a reusable session handle, and the raw request body.
- **`process_payment_with_storage`** — BRC-29 payment verification. Emits `402 Payment Required` with derivation prefix, accepts `x-bsv-payment` header, internalizes via a remote wallet storage endpoint, gates on the wallet's `accepted` flag, and enforces single-use derivation prefixes. (`process_payment` remains as a deprecated stateless variant.)
- **`sign_json_response`** — signs outbound JSON responses so BRC-103/104 clients (e.g. `AuthFetch`) can verify server identity and message integrity. Equivalent to Express's `res.json` hijacking, but explicit.
- **`WorkerStorageClient`** — WASM-compatible RPC client for a wallet storage server (e.g. `storage.babbage.systems`), used by `process_payment` and optional refund flows.
- **Optional `refund` feature** — BRC-41 refund transaction builder for partial-refund scenarios (e.g. AI agents that pre-charge and refund on failure). Not present in the Express reference.

## Why Cloudflare Workers

Workers are request-scoped and have no in-process memory, so a direct port of the Express middleware isn't possible. Adaptations:

- **Sessions in Cloudflare KV** (`KvSessionStorage`) — configurable TTL, keyed by session nonce plus an identity index for lookups.
- **Payments in Cloudflare KV** (`KvPaymentStorage`) — duplicate-txid detection, unspent tracking, derivation prefix lifecycle.
- **No `res.json` hijacking** — Workers can't intercept response construction. Call `sign_json_response(&body, status, &[], &session)` explicitly before returning.
- **Remote wallet instead of local wallet object** — Workers can't host a `WalletInterface`, so `WorkerStorageClient` speaks JSON-RPC to a storage server over HTTP, authenticated by BRC-103/104.
- **Async everywhere** — KV reads, HTTP calls, and auth verification are all `async`, matching the Workers runtime.

Error codes, HTTP statuses, and all `x-bsv-auth-*` / `x-bsv-payment-*` header names are identical to the Express versions. Clients that talk to Express middleware will talk to this middleware unchanged.

## Quick start

```rust
use bsv_middleware_cloudflare::{
    process_auth, sign_json_response,
    middleware::auth::{AuthMiddlewareOptions, AuthResult, handle_cors_preflight},
};
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    let opts = AuthMiddlewareOptions {
        server_private_key: env.secret("SERVER_PRIVATE_KEY")?.to_string(),
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
        ..Default::default()
    };

    let (auth, req, session, _body) = match process_auth(req, &env, &opts).await
        .map_err(|e| Error::from(e.to_string()))?
    {
        AuthResult::Authenticated { context, request, session, body } => (context, request, session, body),
        AuthResult::Response(resp) => return Ok(resp),
    };

    let body = serde_json::json!({ "identity": auth.identity_key });
    match session {
        Some(ref s) => sign_json_response(&body, 200, &[], s)
            .map_err(|e| Error::from(e.to_string())),
        None => Response::from_json(&body),
    }
}
```

See `examples/basic_server.rs` for auth + payment together.

## Cloudflare bindings

```toml
# wrangler.toml
[[kv_namespaces]]
binding = "AUTH_SESSIONS"
id = "<your-kv-id>"

[[kv_namespaces]]
binding = "PAYMENTS"           # only needed if you use the payment middleware
id = "<your-kv-id>"
```

Secret: `wrangler secret put SERVER_PRIVATE_KEY` (64-char hex secp256k1 private key).

## Features

| Feature | Default | Pulls in |
|---|---|---|
| `refund` | off | `sha2`, `ripemd` — enables `refund::issue_refund` for BRC-41 partial refunds |

## Parity with Express middleware

All error codes, HTTP statuses, and header names match the Express versions:

| Concern | Express | Rust |
|---|---|---|
| Auth error codes | `UNAUTHORIZED`, `ERR_INVALID_AUTH`, `ERR_SESSION_NOT_FOUND` | identical |
| Payment error codes | `ERR_PAYMENT_REQUIRED`, `ERR_MALFORMED_PAYMENT`, `ERR_INVALID_DERIVATION_PREFIX`, `ERR_PAYMENT_FAILED` | identical |
| Headers | `x-bsv-auth-*`, `x-bsv-payment-*` | identical |
| HTTP statuses | 400 / 401 / 402 / 500 | identical |

Known divergences (architectural, not bugs):
- **Response signing is explicit.** Callers invoke `sign_json_response` rather than relying on `res.json` interception.
- **Pluggable storage via `SessionStorage`.** Express lets you swap `SessionManager`; here the equivalent seam is the `SessionStorage` trait (`process_auth_with_storage` / `process_payment_with_storage`), with `KvSessionStorage` as the default backend.
- **No injectable logger.** Use `console_log!` / `console_error!` from the `worker` crate at call sites if needed.
- **Payment internalizes via HTTP to a wallet storage server**, not a local `WalletInterface`. Required for Workers (no local wallet possible).

Deliberate hardening divergences (the reference is weaker here; the-composer audit #30/#44):
- **Auth replay protection.** The TS stack (`@bsv/sdk` `Peer.processGeneralMessage`) never records consumed per-request nonces, so a byte-identical signed request replays successfully there for the whole session TTL. This crate consumes each `(session nonce, x-bsv-auth-nonce)` pair and rejects duplicates with `401 ERR_REPLAYED_REQUEST`. See `middleware::auth` docs for the exact residual window under eventually-consistent KV.
- **`accepted` gate.** `payment-express-middleware` calls `next()` even when `wallet.internalizeAction` returns `accepted: false`. Here a rejected payment returns `402` with a fresh challenge and never reaches the handler.
- **Single-use payment derivation prefixes.** The reference's `verifyNonce` is a stateless HMAC; here each verified prefix is consumed (no expiry) via the `SessionStorage` nonce store, so a captured `X-BSV-Payment` header cannot be internalized twice.

## Consumers

Known production consumers using BRC-103/104 auth + dynamic pricing + optional refund:

- `bsv-messagebox-cloudflare` — BSV peer-to-peer messaging service (upcoming public release)
- Various agents (image gen, LLM inference) that pre-charge and refund on upstream failure

## License

Dual-licensed under MIT or Apache-2.0 at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
