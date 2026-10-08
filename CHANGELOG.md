# Changelog

All notable changes to `bsv-middleware-cloudflare`. Versions below 1.0 may change public API between minor versions;
patch versions are additive unless a line below says otherwise.

## 0.4.0 — 2026-10-08

The core extract. The rules moved to a new runtime-free crate, `bsv-middleware-core` 0.1.0 (this repository,
`core/`); this crate is now the Cloudflare Workers adapter over it. **Not a breaking change for adopters:** every
0.3 public item keeps its name, path and signature (re-exported from the core where the type moved), and the
fleet's call sites compile unchanged. Carries everything in 0.3.7 and 0.3.8.

### What moved to the core (re-exported here at the 0.3 paths)

- `types::{AuthContext, PaymentContext, BsvPayment}`.
- `transport::{auth_headers, HttpRequestData, HttpResponseData}`; the request payload builder, the varint
  writer, the signable-header filters and `message_to_headers` are `bsv_middleware_core::brc104`
  (`CloudflareTransport` delegates to them).
- `middleware::session_lane` (whole; the adapter keeps the suite and `tests/fixtures/session_lane.vectors.json`).
- `refund::signer` (whole); `issue_refund` derives the client's key through `bsv_middleware_core::refund`.
- The BRC-103 sign/verify, the identity binding, the `InitialResponse` and `CertificateResponse` builders and
  response signing (`bsv_middleware_core::auth`, over a `SessionBinding`); `process_auth*`, `sign_response` and
  `sign_json_response` call them and are byte-for-byte on the wire.
- BRC-29 derivation, the output check, BEEF completeness and the SPV decision
  (`bsv_middleware_core::{brc29, spv, payment_verify}`), answered in the six words (`PaymentVerdict`).
- `PAYMENT_NONCE_SCOPE` (`bsv_middleware_core::store`).

### Added

- `UrlHeaderService`: the core's `HeaderService` over a ChainTracks-compatible base URL (Workers `fetch`), built
  only through the 0.3.6 configuration gate (`UrlHeaderService::resolve`).
- `verify_brc29_payment_verdict`: the core's `PaymentVerdict` through any `HeaderService`, for callers that
  decide the words themselves.
- `accept_verdict`: the one visible match from the core's words to `PaymentVerifyError` / `Ok(satoshis)`.
- `PaymentVerifyError: From<PaymentFault>`; `AuthCloudflareError: From<bsv_middleware_core::AuthError>`.
- `SessionNonceStore(&storage)`: any `SessionStorage` as the core's `PaymentNonceStore`; `D1ClaimStore(&db)`
  (feature `d1-claims`): the D1 table as the core's `ClaimStore`.
- `bsv_middleware_cloudflare::core` (the core crate as a module) and the top-level `HeaderService`,
  `PaymentVerdict`, `PaymentFault` re-exports.
- `core/tests/conformance_brc29.rs`: the core runs the 20 vectors of `conformance/brc29-payment-vectors.json` (0.3.7)
  through its `HeaderService` trait with a stub, from its own copy of the file (`core/conformance/`, shipped in the
  core's package); the adapter's runner re-pins the root file with the 0.4.0 producer line, writes both copies on
  `emit`, and pins the core's copy byte-identical to the root one.

### Changed

- **A short or misdirected payment on the middleware's own path is refused with `400 ERR_INVALID_PAYMENT` and the
  quote is kept** (`process_payment_with_storage`, `process_payment_with_storage_signed`, the deprecated
  `process_payment`; the core's `Underpaid` / `WrongScript` on output 0). 0.3.8 answered `402 ERR_INVALID_PAYMENT`
  with a fresh challenge. Now: no fresh challenge, the derivation prefix not consumed, the wallet not called, and the
  body says the challenge is unchanged, so an honest client corrects the payment and retries under the same prefix.
  Why: the Express reference (`payment-express-middleware`) answers 400 for every refusal after the challenge and
  reserves 402 for "pay now"; a 402 re-arms automated payers (AuthFetch-class clients) into a second payment for the
  same request while the first sits un-internalized; one live quote per request keeps the single-use rule simple;
  and existing hosts built on this crate's `verify_brc29_payment` already answer 400 and keep the quote. `NoHeaderService` stays `500 ERR_SERVER_MISCONFIGURED`,
  `RootMismatch` and a `PaymentFault` `400 ERR_INVALID_PAYMENT`, `Unverifiable` the documented `accept_verdict`
  policy. The conformance vectors do not change: the words did not change, only the HTTP rendering of two of them.

### Behaviour

- Unchanged on the wire, except the refusal under Changed. The verdict mapping is documented in `payment_verify`: `Verified` and `Unverifiable`
  are `Ok(satoshis)` (**fail-open on a header-service error stays this adapter's documented policy in 0.4**, with
  the reason logged; a later release changes the hosts), every other word is the same-named `Err`.
- `verify_brc29_payment_structural_only` now answers through the core's `Unverifiable` word when a proof carries
  roots; the adapter accepts it and logs the warning, as 0.3.6 did.
- **The middleware's own payment path decides from the core's words.** `process_payment_with_storage`,
  `process_payment_with_storage_signed` and the deprecated `process_payment` run the core's output check
  (`bsv_middleware_core::verify_payment_output`) on output 0 and match its `PaymentVerdict` once
  (`judge_paying_output`): `Verified` serves and records the amount read; `Underpaid` / `WrongScript` are
  `400 ERR_INVALID_PAYMENT` with the quote kept (the prefix not consumed, no fresh challenge, the wallet not called;
  see Changed); a `PaymentFault` or `RootMismatch` is `400 ERR_INVALID_PAYMENT`, the prefix kept; `NoHeaderService` is
  `500 ERR_SERVER_MISCONFIGURED` (the server's own fault, never a client error); `Unverifiable` takes the adapter's
  `accept_verdict` policy (accepted, logged). The output check answers three of the six words today (no SPV on
  this path); the other arms are the path's standing answer should the check grow a proof step. Every payment
  0.3.8 served is served, with the same `satoshis_paid`; the one wire answer that changed is the refusal under
  Changed.

### Removed from the dependency list

- `hmac` and `ripemd` (they moved with the lane and the signer; `sha2` stays for the Durable Object cell).

## 0.3.8 — 2026-10-08

### Fixed

- **The middleware's own payment flow reads the paying output** (P0-3b). `process_payment_with_storage`,
  `process_payment_with_storage_signed` and the deprecated `process_payment` now run `verify_brc29_payment_output` on
  output 0 before the derivation prefix is consumed and before `internalizeAction`. Until now nothing on this path
  compared the output with the price or checked that it pays this server's BRC-29 derived key; the storage server
  checks neither, so an underpaid payment, or one paying another key, was served. 0.3.7 shipped the conformance
  vectors without this wiring.

### Behaviour

- A payment whose output 0 carries less than the price, or is not locked to the server's derived key for (prefix,
  suffix, the authenticated identity), is refused with `402 ERR_INVALID_PAYMENT` and a fresh challenge; the storage
  is not called and the prefix is not consumed, so the client may retry it.
- An unreadable payment transaction, or one with no output 0, is refused with `400 ERR_INVALID_PAYMENT`; the prefix
  is not consumed.
- `PaymentContext::satoshis_paid` (and so `x-bsv-payment-satoshis-paid`) is the amount read from output 0, not the
  price: an overpayment records what was paid.
- The middleware does not run BEEF structure or SPV (`verify_brc29_payment` stays the caller's choice).
- Exact-price payers to the key derived from the same `server_private_key` see no change. A deployment whose payment
  key differs from the key its clients derive for will now be refused instead of recording outputs it cannot spend.

## 0.3.7 — 2026-10-08

### Added

- `verify_brc29_payment_with_header_lookup`: `verify_brc29_payment` with the header lookup supplied by the caller
  (`Fn(height) -> Future<Result<merkle_root, reason>>`) instead of a `header_url`; same fail-closed mismatch,
  fail-open service error. For a service binding, a cached header store, or a conformance runner.
- `conformance/brc29-payment-vectors.json` + `conformance/README.md`: 20 implementation-neutral BRC-29 payment
  verification vectors (amount, script, first-output rule, pay-yourself, header-service gate, SPV), produced and run
  by `tests/conformance_brc29.rs`. A second implementation runs the same file. No behaviour or signature changes.

## 0.3.6 — 2026-10-08

### Added

- `payment_verify`: `expected_brc29_locking_script`, `verify_brc29_payment_output` (script + amount, sync) and
  `verify_brc29_payment` (adds BEEF structural completeness and SPV against a header service you run), for callers
  that run their own payment flow and want the pays-us-correctly and real-and-confirmable checks before
  `internalizeAction`.
- `verify_brc29_payment_structural_only`: the same offline checks with **no SPV**, for adopters that have no header
  service. Opt-in by name; a warning is logged whenever merkle roots go unchecked.
- `PaymentVerifyError::NoHeaderService`.
- Feature `d1-claims`: `claim_payment_nonce` / `release_payment_nonce`, an atomic single-use payment-nonce claim on a
  D1 table (`PAYMENT_CLAIMS_SCHEMA`), for callers outside the stock middleware or on the eventually-consistent KV
  backend.
- docs.rs builds with all features.

### Behaviour

- **A header service URL is required for `verify_brc29_payment`.** `header_url = None`, `Some("")`, the
  `DEFAULT_CHAINTRACKS_URL` `.invalid` placeholder (in any case, with or without a trailing slash or dot), any other
  `.invalid` host, a value without an `http(s)://` scheme, or a value whose host the gate cannot classify as a real
  hostname (userinfo, percent-encoding, backslashes, whitespace, non-ASCII, a non-numeric port) returns
  `Err(NoHeaderService)` before any other check. The host is normalised before the placeholder comparison, so no
  spelling of the placeholder slips through to DNS and fails open. SPV is never skipped
  silently. Once a service is named, a service error (unreachable, HTTP error, unparseable answer) still fails open
  with a logged warning, and a merkle root that differs from the block header still fails closed with `RootMismatch`.
- The configuration gate and the per-root SPV decision are pure functions with table tests (match, mismatch, lookup
  error, and every refused `header_url` shape); the header lookup is injected into the loop that runs them.

## 0.3.5 — 2026-09-20

Session-lane hardening; no new API.

- The lane's replay window rides across the Durable Object store as a decimal string, and a laned counter above
  `MAX_SAFE_COUNTER` (2^53 − 1) is refused by name instead of faulting the store.
- Every 64-bit field of the session cell and its body types documents its bound.

## 0.3.4 — 2026-09-14

- **Session lane (opt-in).** One BRC-103/104 handshake per origin, then MAC'd calls with no wallet calls and one
  Durable Object round trip: `process_auth_lane`, `LaneAuthResult`, `seal_lane_response` / `seal_lane_response_text`,
  `request_presents_lane`, the `x-bsv-lane-offer` header on the first signed general message that asks, and the pure
  rules in `middleware::session_lane`. The MAC vectors are `tests/fixtures/session_lane.vectors.json`, sha256-pinned.
- `mint_attested_lane`: a lane for an identity a first-party authority has proven, with the same record and lifetime
  as the signed-read mint.
- `sha2` is a plain dependency (the lane MACs); `ripemd` stays behind `refund`.

## 0.3.3 — 2026-09-09

- **Durable Object session backend (opt-in).** `process_auth_do`, `AuthSessionStore`, `DoSessionStorage`: one object
  per session nonce holds the session record and the consumed per-request nonces (an atomic put-if-absent, no KV
  write per request); KV stays the cold path.
- `SessionStorage::get_session_and_consume`: the hot path in one round trip, as an additive trait default
  ("unsupported") that every existing backend keeps.
