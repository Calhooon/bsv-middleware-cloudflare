# Changelog

All notable changes to `bsv-middleware-core`. Versions below 1.0 may change public API between minor versions;
patch versions are additive unless a line below says otherwise.

## 0.1.0 — 2026-10-08

The first release: the runtime-free rules extracted from `bsv-middleware-cloudflare` 0.3.8, which becomes a
Workers adapter over this crate in its 0.4.0.

### The six words

- `PaymentVerdict`: `Verified { satoshis }`, `Underpaid { paid, required }`, `WrongScript { expected, actual }`,
  `NoHeaderService`, `RootMismatch { height, root }`, `Unverifiable { satoshis, reason }`. One enum, no booleans.
  `Unverifiable` is the fail-open case handed to the host as a word: the core never serves on it.
- `PaymentFault`: `BadTransaction`, `MissingOutput`, `KeyDerivation`, `BadBeef`. The input could not be judged.

### The seams

- `HeaderService`: `fn merkle_root(&self, height) -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>>`.
  No URL type in the core; `verify_brc29_payment(.., service: Option<&H>)` answers `NoHeaderService` for `None`
  before any other check. `LookupFn` wraps a closure; `NoService` is the type to name for `None`.
- `PaymentNonceStore` (scoped single-use values, `PAYMENT_NONCE_SCOPE`) and `ClaimStore` (an atomic claim by key),
  both fail-closed by contract (`StoreError`, never `Ok(true)`); `MemoryStore` implements both.

### The rules

- `brc29`: `expected_locking_script`, `sender_locking_script`, `verify_payment_output`, `create_derivation_prefix`,
  `verify_derivation_prefix`, `BRC29_PROTOCOL_ID`.
- `spv`: `decide_root` / `RootDecision`, `beef_roots`, `check_roots` / `RootsOutcome`.
- `payment_verify`: `verify_brc29_payment` (the full check through a service) and
  `verify_brc29_payment_structural_only` (the named opt-out; a proof with roots is `Unverifiable`, by name).
- `brc104`: `auth_headers`, `HttpRequestData`, `HttpResponseData`, `build_request_payload`, `write_varint`,
  `signable_request_headers`, `signable_response_headers`, `message_to_headers`.
- `auth`: `SessionBinding`, `AuthError`, `sign_message`, `verify_message_signature` (the counterparty is the
  session's identity, never the header's), `message_identity_is_sessions`, `generate_random_nonce`,
  `server_identity_key`, `create_session_nonce`, `build_initial_response`, `sign_general_message`,
  `sign_http_response`, `build_certificate_response`.
- `session_lane`: the MAC'd lane, moved whole from the adapter (0.3.4 / 0.3.5), with its vectors.
- `refund` (feature `refund`): `refund_locking_script`, `signer` (moved whole from the adapter).
- `types`: `AuthContext`, `PaymentContext`, `BsvPayment`.

### Conformance

- `tests/conformance_brc29.rs` runs `conformance/brc29-payment-vectors.json` (20 cases) through
  `verify_brc29_payment` with a stub service. The file ships inside this package (a copy of the repository root's
  canonical file, which the Workers adapter produces and pins byte-identical to this one), so the published crate
  runs the vectors on its own.
- 89 unit tests with `refund` (82 without) + 2 conformance tests; the packaged crate runs all of them on its own.

### Known

- `HeaderService::merkle_root`, `PaymentNonceStore` and `ClaimStore` return `impl Future` without a `Send` bound,
  by design for wasm32. A host on a multi-threaded runtime must make its own implementations' futures `Send`; the
  verifier is generic over the service, so that works.
