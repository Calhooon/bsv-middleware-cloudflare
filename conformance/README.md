# BRC-29 payment-verification conformance vectors

`brc29-payment-vectors.json` pins what a server must answer when it checks a BRC-29 payment **before**
internalizing it: does output `output_index` of the payment transaction pay this server's BRC-29 derived key at
least the quoted satoshis, and does the transaction's merkle proof tie to a real block header?

The file is implementation-neutral. Copy it verbatim; do not edit it by hand. It is produced by
`bsv-middleware-cloudflare` (`tests/conformance_brc29.rs`, `build_vectors`) from fixed synthetic inputs and pinned
byte-for-byte by that crate's tests, so any change shows up as a reviewed diff there first. All keys are synthetic
(private keys `0x01`, `0x02`, `0x03`); `headers.example`, `real.example` and `chaintracks.invalid` are RFC 2606
reserved names.

## Schema (`brc29-payment-vectors/1`)

Top level: `schema`, `producer`, `description`, `words` (the six outcome words, defined below), `derivation` (how the
expected script is derived), `cases`, `rulings` (owner rulings that set a case's word: date, case, word, by, why).

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
| `transaction.proof` | `{height, merkle_root}` the BEEF's merkle path computes (a one-leaf block, so the root is the txid). |
| `output_index` | The output that must pay. Always `0`: the reference middleware internalizes output 0 only. |
| `required_satoshis` | The quoted price. |
| `header_service.url` | The configured header-service base URL, `null` for none. |
| `header_service.lookup` | The header service's answer for this case: `{"answer":"root","height":h,"merkle_root":hex}` (answers that root at `h`, nothing at other heights) or `{"answer":"error","reason":...}` (cannot answer). `null` on `config` cases, where it is never asked. |
| `expected.word`, `expected.fields` | The intended outcome. |
| `crate_result` | What `bsv-middleware-cloudflare` returned when the file was produced (`Ok(sats)` or `Err(<PaymentVerifyError variant>)`), for reference. Other implementations compare against `expected`, not this string. |

### The six words

| Word | Accept? | `fields` | crate (`PaymentVerifyError`) |
|---|---|---|---|
| `Verified` | yes | `satoshis` (the output's amount, which may exceed the price) | `Ok(satoshis)` |
| `Underpaid` | no | `paid`, `required` | `Underpaid { satoshis, required }` |
| `WrongScript` | no | `expected_script`, `actual_script` | `WrongScript { expected, actual }` |
| `NoHeaderService` | no (server misconfigured, 500-class) | none | `NoHeaderService` |
| `RootMismatch` | no (fraud signal) | `height`, `merkle_root` (the proof's root) | `RootMismatch { height, root }` |
| `Unverifiable` | no (header service could not answer; transient, 5xx) | `height` (the first root, lowest height first, whose lookup failed) | `Unverifiable { height, reason }` |

`Unverifiable` is the fail-closed lookup error, by the owner's ruling of 2026-10-08 (the `rulings` list): a root that
could not be checked leaves the payment unanchored, so it is refused, never accepted on the script, amount and BEEF
structure alone. It replaces `AcceptedUnverified` (fail-open, 0.3.8 and earlier), which is retired.

## Order of checks

1. **config**: refuse with `NoHeaderService` if `header_service.url` is null, blank, the `.invalid` placeholder in any
   spelling, or a value whose host cannot be classified without decoding (percent-encoding, backslash, userinfo).
   This runs before anything else, so these cases carry an otherwise-valid payment.
2. **output**: parse the BEEF, take output `output_index`; its script must equal `expected_locking_script`
   (`WrongScript`), then its satoshis must be `>= required_satoshis` (`Underpaid`). Script is checked before amount.
3. **spv**: the BEEF must be structurally complete; for each merkle root (lowest height first) ask the header
   service; a different root is `RootMismatch`, an error is `Unverifiable` (fail-closed), a case-insensitive match
   continues. The first root that does not match decides. All roots matched is `Verified`.

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
- `spv-lookup-error` → `Unverifiable`

The six `no-header-service-*` cases need a configuration gate but no lookup. The other ten need neither.

## Notes on specific cases

- **`first-output-*`**: the reference express payment middleware internalizes `outputIndex: 0` only. A transaction
  whose output 1 would pay while output 0 does not is refused; implementations must not scan for a paying output.
- **`pay-yourself-sender-is-server`**: the verifier does not refuse a sender identity equal to the server's. The
  derivation is well defined and the output pays a key the server controls, so it is `Verified`. Refusing
  self-payment, if wanted, is policy above the verifier.
- **`wrong-script-stale-prefix`** and **`wrong-script-another-server`**: replaying a paid transaction against a new
  quote, or against another server, fails the script compare because both the prefix and the server identity are part
  of the derivation.
