# bsv-middleware-core

The runtime-free rules of BSV BRC-103/104 authentication and BRC-29 payment verification: what a server must
compute and decide, with no transport, no store, no clock and no network of its own. A host crate adapts these
rules to its runtime; `bsv-middleware-cloudflare` (0.4.0 and later) is the Cloudflare Workers host.

## What it decides

**A payment check answers in six words, never a boolean:**

```rust
pub enum PaymentVerdict {
    Verified { satoshis: u64 },
    Underpaid { paid: u64, required: u64 },
    WrongScript { expected: String, actual: String },
    NoHeaderService,
    RootMismatch { height: u32, root: String },
    Unverifiable { satoshis: u64, reason: String },
}
```

`verify_brc29_payment` runs, in order: the service gate (`None` is `NoHeaderService`, fail closed, before anything
else), script and amount (`WrongScript`, `Underpaid`), BEEF structural completeness (a `PaymentFault::BadBeef`),
then SPV through the header service: a root that differs from its header is `RootMismatch`; a root the service
could not answer makes the verdict `Unverifiable`, which the host decides on (the core never serves on it);
every root matched is `Verified`. `verify_brc29_payment_structural_only` is the named opt-out: no SPV, and a
proof with roots is answered `Unverifiable` so the skip is visible.

**The header service is a trait.** No URL lives in the core.

```rust
pub trait HeaderService {
    fn merkle_root(&self, height: u32)
        -> impl Future<Output = Result<Option<MerkleRoot>, ServiceError>>;
}
```

`Ok(Some(root))` is the header at that height, `Ok(None)` means not indexed yet, `Err` means the service could not
answer. A host implements it over whatever it has: an HTTP header service, a service binding, a cached header store,
a fixture (`LookupFn` wraps a closure).

**The stores are traits.** `PaymentNonceStore` (scoped single-use values: a BRC-104 per-request nonce under its
session, a BRC-29 derivation prefix under `PAYMENT_NONCE_SCOPE`) and `ClaimStore` (an atomic claim by key, for a
host's own payment flow or a refund idempotency key). Both fail closed by contract: a storage fault is an error,
never a fresh claim. `MemoryStore` implements both for tests and single-process hosts.

## What else is here

- `brc29`: BRC-29 derivation (`expected_locking_script`, the sender's side, the derivation-prefix HMAC nonce)
  and the pays-us-correctly check (`verify_payment_output`).
- `spv`: the per-root decision (`decide_root`, pinned by a table) and the loop over a proof's roots.
- `brc104`: BRC-104 header names, the signed request and response payloads, the header pairs a message is sent as.
- `auth`: BRC-103 message build and verify over a `SessionBinding`: sign, verify against the SESSION's identity
  (the header is a claim), the handshake's `InitialResponse`, the signed general message that carries a response.
- `session_lane`: the MAC'd session lane (one handshake, then no wallet calls per request), pure.
- `refund` (feature `refund`): the refund key derivation and the `createAction` template signer.
- `types`: `AuthContext`, `PaymentContext`, `BsvPayment`.

## What is not here, by design

No HTTP request type, no fetch, no KV, no Durable Object, no SQL, no clock read, no logging. Every function takes
what it needs as data and answers with data; the host owns every side effect and every policy decision.

The one runtime-shaped thing in the dependency tree is the SDK's own: `bsv-rs`'s `auth` feature (the BRC-103
message types and the HMAC nonce) brings `tokio`'s sync and time primitives transitively. This crate uses none of
them, declares no executor, and its tests run on `tokio`'s current-thread runtime as a dev-dependency only.

## Conformance

`tests/conformance_brc29.rs` runs the implementation-neutral BRC-29 payment vectors
(`conformance/brc29-payment-vectors.json`, 20 cases) through `verify_brc29_payment` with a stub service, reading
the file the way a second implementation does: from JSON only. The file's `AcceptedUnverified` is this crate's
`Unverifiable`. The copy under this crate's `conformance/` is shipped in the package so the published crate runs
the vectors on its own; the canonical copy is the repository root's (produced and pinned by the Workers adapter's
runner, which also pins this copy byte-identical to it).

## Build

```bash
cargo test -p bsv-middleware-core --all-features
cargo clippy -p bsv-middleware-core --all-features --all-targets -- -D warnings
```

## License

MIT OR Apache-2.0.
