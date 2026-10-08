# Changelog

## 0.3.8 — 2026-10-08

### Fixed

- **The middleware's own payment flow reads the paying output** (P0-3b, bsv-stack-lean #50): `verify_brc29_payment_output` runs on output 0 before the derivation prefix is consumed and before `internalizeAction`; `Underpaid` and `WrongScript` answer 402 with a fresh challenge; the amount read is recorded as `satoshis_paid`. 0.3.7 shipped the conformance vectors without this wiring.

## 0.3.7 — 2026-10-08

- `conformance/brc29-payment-vectors.json`: the BRC-29 payment-verification conformance set (20 cases: output checks incl. the reference's first-output rule, no-header-service forms, merkle-root outcomes) with `tests/conformance_brc29.rs` pinning and running it. A second implementation runs the same file; see `conformance/README.md`.
- One additive public decision function so the verdict is callable without a fetch. No behaviour or signature changes.

All notable changes to `bsv-middleware-cloudflare`. Versions below 1.0 may change public API between minor versions;
patch versions are additive unless a line below says otherwise.

## Unreleased

### Added

- `verify_brc29_payment_with_header_lookup`: `verify_brc29_payment` with the header lookup supplied by the caller
  (`Fn(height) -> Future<Result<merkle_root, reason>>`) instead of a `header_url`; same fail-closed mismatch,
  fail-open service error. For a service binding, a cached header store, or a conformance runner.
- `conformance/brc29-payment-vectors.json` + `conformance/README.md`: 20 implementation-neutral BRC-29 payment
  verification vectors (amount, script, first-output rule, pay-yourself, header-service gate, SPV), produced and run
  by `tests/conformance_brc29.rs`.

### Fixed

- **The middleware's own payment flow reads the paying output.** `process_payment_with_storage`,
  `process_payment_with_storage_signed` and the deprecated `process_payment` now run `verify_brc29_payment_output` on
  output 0 before the derivation prefix is consumed and before `internalizeAction`. Until now nothing on this path
  compared the output with the price or checked that it pays this server's BRC-29 derived key; the storage server
  checks neither, so an underpaid payment, or one paying another key, was served.

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
