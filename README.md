# bsv-middleware-cloudflare

BSV authentication and payment middleware for Cloudflare Workers. Rust compiled to WASM.

Port of [`auth-express-middleware`](https://github.com/bitcoin-sv/auth-express-middleware) and [`payment-express-middleware`](https://github.com/bitcoin-sv/payment-express-middleware) for the Cloudflare Workers runtime. Implements BRC-103/104 mutual identity auth and BRC-29 direct payments, with session and payment state persisted in Cloudflare KV. Error codes, HTTP statuses, and header names match the Express versions.

## What it provides

- **`process_auth`** / **`process_auth_with_storage`** — BRC-103/104 mutual identity handshake, session verification, certificate exchange, and per-request replay protection (each `x-bsv-auth-nonce` is single-use per session). Returns the authenticated identity key, a reusable session handle, and the raw request body.
- **`process_payment_with_storage`** — BRC-29 payment verification. Emits `402 Payment Required` with derivation prefix, accepts `x-bsv-payment` header, reads output 0 of the payment and refuses it (`400 ERR_INVALID_PAYMENT`, the quote kept) unless it pays this server's BRC-29 derived key at least the price (0.3.8; 400 since 0.4.0), internalizes via a remote wallet storage endpoint, gates on the wallet's `accepted` flag, and enforces single-use derivation prefixes. `satoshis_paid` is the amount read from the output. (`process_payment` remains as a deprecated stateless variant.)
- **`sign_json_response`** — signs outbound JSON responses so BRC-103/104 clients (e.g. `AuthFetch`) can verify server identity and message integrity. Equivalent to Express's `res.json` hijacking, but explicit.
- **`WorkerStorageClient`** — WASM-compatible RPC client for a wallet storage server (e.g. `storage.babbage.systems`), used by `process_payment` and optional refund flows.
- **Optional `refund` feature** — BRC-41 refund transaction builder for partial-refund scenarios (e.g. AI agents that pre-charge and refund on failure). Not present in the Express reference.
- **`verify_brc29_payment`** / **`verify_brc29_payment_output`** (0.3.6) — checks, before anything is internalized, that a BRC-29 payment output pays *this* server's derived key at least the quoted amount inside a structurally complete BEEF, with merkle roots checked against a header service you run (required: no service, no verdict; `verify_brc29_payment_structural_only` is the named opt-out without SPV). For callers with their own payment flow; the stock middleware runs `verify_brc29_payment_output` itself (0.3.8).
- **Optional `d1-claims` feature** (0.3.6) — `claim_payment_nonce` / `release_payment_nonce`: an atomic, globally consistent single-use claim on a payment nonce in a D1 table, for callers outside the stock middleware or on the eventually-consistent KV backend.

## Shape (0.4.0): the core and the adapter

Since 0.4.0 the rules live in a runtime-free crate, [`bsv-middleware-core`](core/README.md) (this repository,
`core/`), and this crate is the Cloudflare Workers adapter over it:

| the core (`bsv-middleware-core`, no runtime) | this crate (`bsv-middleware-cloudflare`, Workers) |
|---|---|
| BRC-103 message build and verify over a `SessionBinding` (sign, verify against the SESSION's identity, the handshake replies, response signing) | reading a `worker::Request` into those messages, the session records, the replay guard, the HTTP answers, CORS |
| BRC-29 derivation, the output check, BEEF completeness and the SPV decision, answered in six words (`PaymentVerdict`: `Verified`, `Underpaid`, `WrongScript`, `NoHeaderService`, `RootMismatch`, `Unverifiable`) | `verify_brc29_payment` and friends with their 0.3 signatures, `PaymentVerifyError`, and `accept_verdict`, the one visible match from the words to it |
| the `HeaderService` trait (no URL type in the core; `None` fails closed) | `UrlHeaderService`: Workers `fetch` to a ChainTracks-compatible base URL behind the 0.3.6 configuration gate |
| the `PaymentNonceStore` and `ClaimStore` traits | KV, Durable Object and D1 implementations (`SessionNonceStore`, `D1ClaimStore`) |
| the session lane's rules, the refund key derivation and the template signer, the context types | the lane's door and store, `issue_refund` over the storage client |

**Every 0.3 public item keeps its name, path and signature** (re-exported from the core where the type moved);
adopters upgrade by bumping the version. The core is reachable as `bsv_middleware_cloudflare::core` for code that
wants the words or the traits directly.

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
| `refund` | off | `bsv-middleware-core/refund` (`ripemd`) — enables `refund::issue_refund` for BRC-41 partial refunds |
| `d1-claims` | off | `worker/d1` — enables `payment_claims::{claim_payment_nonce, release_payment_nonce}` (atomic single-use payment-nonce claims on a D1 table) |

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
- **No SPV on the middleware's own path.** `process_payment_with_storage` checks output 0's script and amount and nothing else about the transaction: no merkle proof is checked against a block header there. Whether the payment is real and confirmable is left to the wallet storage server's `internalizeAction`, which this crate does not verify. Run `verify_brc29_payment` (through a header service) before it when a proof must be checked.

Deliberate hardening divergences (the reference is weaker here; security audit findings #30/#44):
- **Auth replay protection.** The TS stack (`@bsv/sdk` `Peer.processGeneralMessage`) never records consumed per-request nonces, so a byte-identical signed request replays successfully there for the whole session TTL. This crate consumes each `(session nonce, x-bsv-auth-nonce)` pair and rejects duplicates with `401 ERR_REPLAYED_REQUEST`. See `middleware::auth` docs for the exact residual window under eventually-consistent KV.
- **`accepted` gate.** `payment-express-middleware` calls `next()` even when `wallet.internalizeAction` returns `accepted: false`. Here a rejected payment returns `402` with a fresh challenge and never reaches the handler.
- **The paying output's script.** `payment-express-middleware` 2.1.9 reads output 0's satoshis and refuses below the price with `400 ERR_INVALID_PAYMENT`, and leaves the script to its wallet's signer. Here the storage server is not a signer, so output 0 must also pay this server's BRC-29 derived key; a short or misdirected payment gets the reference's `400 ERR_INVALID_PAYMENT` with the quote kept (no fresh challenge, the prefix not consumed), before the storage is called (0.3.8 answered 402 with a fresh challenge; 400 since 0.4.0).
- **Single-use payment derivation prefixes.** The reference's `verifyNonce` is a stateless HMAC; here each verified prefix is consumed (no expiry) via the `SessionStorage` nonce store, so a captured `X-BSV-Payment` header cannot be internalized twice.

## Consumers

Known production consumers using BRC-103/104 auth + dynamic pricing + optional refund:

- `bsv-messagebox-cloudflare` — BSV peer-to-peer messaging service (upcoming public release)
- Various agents (image gen, LLM inference) that pre-charge and refund on upstream failure

## License

Dual-licensed under MIT or Apache-2.0 at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Session lane (0.3.4, opt-in)

One BRC-103/104 handshake per origin, then a LANE: `process_auth_lane(req, &env, &options, "AUTH_SESSION_STORE")`
serves calls that carry `x-low-session` (the lane id), `x-low-session-identity`, `x-low-session-n` (the client's
counter) and `x-low-session-mac` (`HMAC-SHA256(K, n ‖ "METHOD path?query" ‖ 0x00 ‖ sha256(body))`) with ZERO wallet
calls and one Durable Object round trip, and answers `LaneAuthResult::Laned { context, request, body, lane }`;
everything else is `LaneAuthResult::Reference(AuthResult)` or `LaneAuthResult::Offered { auth, offer }`, the unchanged
reference outcome. The client's FIRST BRC-104-signed general message carrying the explicit ask (`x-low-lane-ask`) on a
server with `options.session_lane = Some(..)` is answered `Offered`: the server attaches the offer to that message's
SIGNED reply as the `x-bsv-lane-offer` header (base64 JSON `{id, expiresAt, salt, ask}`, a header a reference client
ignores, exposed cross-origin); the unsigned handshake never mints. Both sides derive
`K = HMAC-SHA256(salt, label ‖ id ‖ clientMessageNonce ‖ serverSessionNonce)` from that message's own `x-bsv-auth-nonce`
and the server's session nonce. Seal a laned answer with
`seal_lane_response(&value, status, &lane)` (`x-low-session-n`, `x-low-session-mac`, `no-store`). Refusals are
401 `{status:"error", code:"ERR_SESSION_REFUSED", reason}` (`unknown-session` / `expired` / `replay` / `bad-mac` /
`malformed`; 503 `lane-unavailable` when the store cannot be asked). The KV backend keeps no lanes (never offers
one, answers a laned call 503 `lane-unsupported`). The pure rules live in `middleware::session_lane`; the MAC
vectors are `tests/fixtures/session_lane.vectors.json` (emitted by the module's own test, sha256-pinned; a client
pins the same bytes). Designed for the relay adopter: its lane, generalized to HTTP-only servers.

## Payment verification before internalize (0.3.6)

`verify_brc29_payment(server_key, sender_identity_key, derivation_prefix, derivation_suffix, &tx_bytes, output_index, required_satoshis, header_url)`
proves, offline and before any wallet call, that the payment *pays this server correctly* and is *real and confirmable*:

1. **Script + amount** (`verify_brc29_payment_output`, sync): the output's locking script equals the P2PKH script of the
   BRC-29 key derived from (server identity, sender identity, prefix, suffix) via `expected_brc29_locking_script`, and
   carries at least `required_satoshis`. One byte-compare rejects underpayment, zero-sat outputs, outputs paying any
   other key, a transaction built for another quote nonce, and a transaction built for another server.
2. **BEEF completeness + SPV**: the BEEF parses and verifies structurally (no missing inputs, no txid-only gaps, an
   intact proof chain), then each merkle root is checked against block headers from a ChainTracks-compatible service
   (`GET {header_url}/findHeaderHexForHeight?height=N`). SPV is **fail-closed** both ways: a root the service cannot
   answer for (outage, timeout, HTTP error, height not yet indexed) is refused as `Unverifiable` (the server's own
   condition: answer 503-class, keep the quote, let the client retry the same payment), and a root that differs from
   the header is refused as `RootMismatch` (a fraud signal). 0.3.x accepted the first case with a logged warning;
   0.4.0 fails closed, by the project's ruling of 2026-10-08: an unchecked root is not evidence.

> **Warning: a header service URL is required.** The crate ships no header service and never skips SPV silently.
> Pass the base URL of your own ChainTracks-compatible service as `header_url` (for example a ChainTracks deployment
> you run). `None`, `Some("")`, the `DEFAULT_CHAINTRACKS_URL` `.invalid` placeholder (in any case, with or without a
> trailing slash or dot), any other `.invalid` host, a value without an `http(s)://` scheme, or a value whose host the
> gate cannot classify as a real hostname (userinfo, percent-encoding, backslashes, whitespace, non-ASCII, a
> non-numeric port) is refused with `PaymentVerifyError::NoHeaderService` before any other check: fail-closed, never
> a silent skip. The host is normalised before the placeholder comparison, so no spelling of the placeholder reaches
> DNS and surfaces as a lookup error instead of as the misconfiguration it is. Adopters with no header service opt
> out of SPV *by name* with
> `verify_brc29_payment_structural_only(..)` (script + amount + BEEF structure, no root check).

| `header_url` | result |
|---|---|
| `None`, `Some("")`, whitespace only | `Err(NoHeaderService)` |
| the `.invalid` placeholder (trailing slash or dot or not, any case), any `.invalid` host, no `http(s)://` scheme | `Err(NoHeaderService)` |
| userinfo, `%`, `\`, whitespace, control or non-ASCII characters, a non-numeric port, a label that is not a hostname | `Err(NoHeaderService)` |
| service unreachable, HTTP error, unparseable answer, height not indexed | `Err(Unverifiable { satoshis, reason })`, warning logged (fail-closed; 503-class at the host, the quote kept) |
| the header at that height carries a different root | `Err(RootMismatch)` (fail-closed) |
| the header carries the proof's root | `Ok(satoshis)` |

Every `PaymentVerifyError` means reject without internalizing, no refund owed. Most are client-fault; `NoHeaderService`
(and a `KeyDerivation` error on the server key) is the deployment's own: answer 500-class and fix the configuration.
`Unverifiable` is the server's transient condition: answer 503-class (`ERR_HEADER_SERVICE_UNAVAILABLE` on the
middleware's own path), keep the quote, and let the client retry the same payment once the header service answers.
A host whose match on `PaymentVerifyError` has a `_` arm compiles unchanged on 0.4.0 but answers that arm's 400 for
it; add the 503 arm.

Since 0.4.0 the check itself is the core's and answers in six words; `accept_verdict` is this crate's one visible
match from them to the table above (`Verified` is the only `Ok(satoshis)`; every other word is the same-named `Err`,
`Unverifiable` included, with the reason logged). Callers that want the words themselves use
`verify_brc29_payment_verdict` with any `HeaderService` (`UrlHeaderService::resolve(header_url)` is the gated URL
one); none of the words but `Verified` may be served on. The named opt-out `verify_brc29_payment_structural_only` is
the one function that answers `Ok` with roots unchecked, because its caller asked for exactly that by name.

With the `d1-claims` feature, `claim_payment_nonce(&db, nonce, agent)` is an atomic `INSERT OR IGNORE` on a D1
`payment_claims` table (schema in `PAYMENT_CLAIMS_SCHEMA`): `Ok(true)` won, `Ok(false)` already used, `Err` storage
fault. It is the single-use guard for callers that run their own payment flow and never reach the middleware's
`try_consume_nonce`, and a second, globally consistent guard for the stock middleware on KV. Using both is safe. Claim
after `verify_brc29_payment` succeeds and before internalizing; `release_payment_nonce` frees a claim after a
pre-internalize failure.

```toml
bsv-middleware-cloudflare = { version = "0.4.0", features = ["d1-claims"] }
```

## Session storage backends

- **KV (default)** — `process_auth(req, &env, &options)`: sessions and the per-request nonce replay guard in the `AUTH_SESSIONS` KV namespace (a read, and a read + write, per authenticated request).
- **Durable Objects (0.3.3, opt-in)** — `process_auth_do(req, &env, &options, "AUTH_SESSION_STORE")`: one `AuthSessionStore` object per session nonce holds the session record and the consumed nonces, so a request costs two same-colo object round trips and no KV write; KV stays the cold path (the identity → session index written at the handshake, a KV-minted session migrated on first sight, the BRC-29 payment nonce scope). Bind the class and add a migration:

```toml
[[durable_objects.bindings]]
name = "AUTH_SESSION_STORE"
class_name = "AuthSessionStore"

[[migrations]]
tag = "vN-auth-session-store"
new_classes = ["AuthSessionStore"]
```

and export the class from the worker crate: `pub use bsv_middleware_cloudflare::AuthSessionStore;`. Any other store implements `SessionStorage` and goes through `process_auth_with_storage`.
