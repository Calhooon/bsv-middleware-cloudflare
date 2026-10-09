# BRC-29 payment-verification conformance vectors

`brc29-payment-vectors.json` pins what a server must answer when it checks a BRC-29 payment **before**
internalizing it: does output `output_index` of the payment transaction pay this server's BRC-29 derived key at
least the quoted satoshis, and does the transaction's merkle proof tie to a real block header?

The file is implementation-neutral and OWNED by the stack review repository (bsv-stack-lean,
`conformance/brc29-payment-vectors.json`; 22 cases since 2026-10-09). Copy it verbatim; do not edit it by hand. The
copy here is the owner's bytes with one line changed, the `producer`, pinned by digest in
`tests/conformance_brc29.rs` (`VECTORS_SHA256`), so a new owned file is a reviewed diff. Twenty of its cases are
synthetic payments this crate's producer (`build_cases`, fixed inputs) regenerates, and the runner holds the file's
cases to the regenerated ones field for field (the owner's `note` and `crate_result` texts aside); the two no-root
cases of 2026-10-09 and the `rulings` list are the owner's alone. The `bsv-middleware-core` package ships its own
copy (`core/conformance/` in this repository), pinned byte-identical to this one, so the published core runs the
file without the repository. All keys are synthetic (private keys `0x01`, `0x02`, `0x03`); `headers.example`,
`real.example` and `chaintracks.invalid` are RFC 2606 reserved names.

## Schema (`brc29-payment-vectors/1`)

Top level: `schema`, `producer`, `description`, `words` (the six outcome words, defined below), `derivation` (how the
expected script is derived), `cases`, and `rulings` (the file owner's rulings on a case's word: `date`, `case`, `word`,
`by`, `why`; a ruled case's `expected.word` is the ruled word). The canonical copy of this file is the stack review
repository's; this repository's copy is byte-identical to it (sha256 `836579ad…`), the `producer` line included.

Each case:

| Field | Meaning |
|---|---|
| `name`, `description`, `note` (optional) | What the case pins and why. |
| `stage` | `config`, `output` or `spv`: the check that decides the case (below). |
| `requires_merkle_lookup` | `true` when the word depends on the header service's answer. |
| `server_private_key`, `server_identity_key` | The server (hex scalar, compressed pubkey). |
| `sender_private_key`, `sender_identity_key` | The payer. The private key is there so a sender-side implementation can re-derive the script; a verifier needs only the identity key. |
| `derivation_prefix`, `derivation_suffix` | Base64 strings, used as-is in the key ID `"<prefix> <suffix>"`. |
| `expected_locking_script` | Hex P2PKH the server expects: `76a914 <hash160(child pubkey)> 88ac`. |
| `transaction.beef_hex` | The payment as BEEF (hex). The subject transaction is the last one in the BEEF. |
| `transaction.txid`, `transaction.outputs[]` | The subject transaction's id and its outputs (`satoshis`, `locking_script` hex), for implementations that only check outputs. |
| `transaction.proof` | `{height, merkle_root}` the BEEF's merkle path computes (a one-leaf block, so the root is the txid); `null` on the no-root cases, whose BEEF carries no BUMP. |
| `output_index` | The output that must pay. Always `0`: the reference middleware internalizes output 0 only. |
| `required_satoshis` | The quoted price. |
| `header_service.url` | The configured header-service base URL, `null` for none. |
| `header_service.lookup` | The header service's answer for this case: `{"answer":"root","height":h,"merkle_root":hex}` (answers that root at `h`, nothing at other heights) or `{"answer":"error","reason":...}` (cannot answer). `null` on `config` cases and on the no-root cases, where it is never asked. |
| `expected.word`, `expected.fields` | The intended outcome. |
| `crate_result` | What `bsv-middleware-cloudflare` returned when the case was produced (`Ok(sats)` or `Err(<PaymentVerifyError variant>)`), for reference; `null` on the owner's two no-root cases. Informational only, and older cases carry older shapes: every implementation, this crate included, compares against `expected`. |

### The six words

| Word | Accept? | `fields` | crate (`PaymentVerifyError`) |
|---|---|---|---|
| `Verified` | yes | `satoshis` (the output's amount, which may exceed the price) | `Ok(satoshis)` |
| `Unverifiable` | **no**: a merkle root could not be checked (fail-closed). The server's side (the header service errored, ruled 2026-10-08): 503-class at the host, the quote kept, the same payment retried. The payer's side (the BEEF gives no root: no proof, an incomplete ancestry; ruled 2026-10-09): 400-class, another payment. | `height` (the lowest height the service could not answer for) on the server's side; none on the payer's | `Unverifiable { reason }`; `reason.is_server_side()` tells the sides |
| `Underpaid` | no | `paid`, `required` | `Underpaid { satoshis, required }` |
| `WrongScript` | no | `expected_script`, `actual_script` | `WrongScript { expected, actual }` |
| `NoHeaderService` | no (server misconfigured, 500-class) | none | `NoHeaderService` |
| `RootMismatch` | no (fraud signal) | `height`, `merkle_root` (the proof's root) | `RootMismatch { height, root }` |

`Unverifiable` is a root that could not be checked, and an unchecked root is not evidence, so the payment is
**refused** (the rulings of 2026-10-08 and 2026-10-09, recorded in `rulings`). Its reason says whose side: a header
service that could not answer is the server's condition, not the client's fault (a host answers 5xx, this crate's
middleware `503 ERR_HEADER_SERVICE_UNAVAILABLE`, keeps the quote, and the client retries the same payment once the
service answers); a BEEF that gives no root to check (no BUMP, an unproven transaction with no input, an input
naming a transaction the BEEF does not carry) is the payer's (a host answers 4xx with no fields, the server never
fetches a missing proof, and the payer sends a proven BEEF). Until 0.3.8 this crate accepted the lookup-error case
with a logged warning under the retired word `AcceptedUnverified`. `Verified` is the only word that serves.

## Order of checks

1. **config**: refuse with `NoHeaderService` if `header_service.url` is null, blank, the `.invalid` placeholder in any
   spelling, or a value whose host cannot be classified without decoding (percent-encoding, backslash, userinfo).
   This runs before anything else, so these cases carry an otherwise-valid payment.
2. **the bytes**: the BEEF must be valid (V1, V2 or Atomic) with its scripts run: every unproven transaction's
   inputs name earlier transactions in the BEEF and spend them; an invalid BEEF or a refused spend is `Unverifiable`
   with no fields (the payer's). An implementation that checks the structure alone passes the 22 cases too, but
   serves an unsigned spend beside a proven stranger (bsv-middleware-core 0.1.0 did; 0.2.0 runs the scripts).
3. **output**: take output `output_index` of the subject (the Atomic BEEF's named transaction, else the last); its
   script must equal `expected_locking_script` (`WrongScript`), then its satoshis must be `>= required_satoshis`
   (`Underpaid`). Script is checked before amount.
4. **spv**: a proof must be present: a BEEF with no BUMP, an unproven transaction with no input, or an input naming a
   transaction the BEEF does not carry is `Unverifiable` with no fields (the payer's; nothing is asked of the header
   service). Then for each distinct merkle root (lowest height first) ask the header service; a different root is
   `RootMismatch`, an error (or a height the service has not indexed) is `Unverifiable` with `fields.height` (the
   lowest such height; refused, fail-closed, the server's), a case-insensitive match continues. All roots matched is
   `Verified`.

## Running it from a second implementation

For each case:

1. Check derivation: from `server_private_key`, `sender_identity_key`, `derivation_prefix`, `derivation_suffix`,
   BRC-42 child pubkey with protocol `[2, "3241645161d8"]`, key ID `"<prefix> <suffix>"`, `for_self = true`;
   P2PKH of its hash160 must equal `expected_locking_script`.
2. If `stage == "config"`: call your verifier with `header_service.url` (null = no service configured) and expect
   `NoHeaderService`. No network call may happen.
3. Otherwise call your verifier on `hex_decode(transaction.beef_hex)`, `output_index`, `required_satoshis`, with the
   header service replaced by a stub that answers from `header_service.lookup`. Map the result to a word and compare
   `expected.word` and `expected.fields` exactly.

A pure implementation with no header-service seam (only a script + amount check) can run every `output` case
(`requires_merkle_lookup: false`) using `transaction.outputs[output_index]` or the BEEF, and must get the same word.

### Cases that need a merkle-root lookup

Only these four (`stage: "spv"`, `requires_merkle_lookup: true`):

- `spv-root-match`, `spv-root-match-uppercase` → `Verified`
- `spv-root-mismatch` → `RootMismatch`
- `spv-lookup-error` → `Unverifiable`, `fields.height` (refused; ruled 2026-10-08)

Two more `spv` cases need no lookup (`requires_merkle_lookup: false`, `lookup: null`): `spv-no-root` and
`spv-incomplete-beef` → `Unverifiable` with no fields (refused; ruled 2026-10-09). The six `no-header-service-*`
cases need a configuration gate but no lookup. The other ten need neither.

## Notes on specific cases

- **`first-output-*`**: the reference express payment middleware internalizes `outputIndex: 0` only. A transaction
  whose output 1 would pay while output 0 does not is refused; implementations must not scan for a paying output.
- **`pay-yourself-sender-is-server`**: the verifier does not refuse a sender identity equal to the server's. The
  derivation is well defined and the output pays a key the server controls, so it is `Verified`. Refusing
  self-payment, if wanted, is policy above the verifier.
- **`wrong-script-stale-prefix`** and **`wrong-script-another-server`**: replaying a paid transaction against a new
  quote, or against another server, fails the script compare because both the prefix and the server identity are part
  of the derivation.
- **`spv-no-root`** and **`spv-incomplete-beef`** (the owner's, produced by the stack review repository's
  `tools/brc29_noroot_cases.py`; `crate_result: null`): the payment pays correctly, and the BEEF gives no root to
  check. `spv-no-root` carries the subject and the parent it spends, neither proven, the parent's input naming a
  transaction the BEEF does not carry; `spv-incomplete-beef` carries the subject alone, its input naming a parent the
  BEEF does not carry. `Unverifiable`, no fields, the payer's side: nothing is asked of the header service, and the
  refusal names the absent transaction (bsv-rs 0.4.0's reader refuses both as `InputNamesNoElement` at the input
  that names it). A missing proof is never fetched by the server.

## Taking a new owned file

Copy the owner's bytes unchanged over `conformance/brc29-payment-vectors.json` and
`core/conformance/brc29-payment-vectors.json` (the `producer` line is the owner's and stays), update `VECTORS_SHA256` in `tests/conformance_brc29.rs`, and run
both runners: `cargo test --test conformance_brc29` at the root and `cargo test -p bsv-middleware-core --test
conformance_brc29`. Never retype a case.
