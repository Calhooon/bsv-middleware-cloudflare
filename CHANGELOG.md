# Changelog

All notable changes to `bsv-middleware-cloudflare`. Versions below 1.0 may change public API between minor versions;
patch versions are additive unless a line below says otherwise.

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
