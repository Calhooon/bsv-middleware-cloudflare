# bsv-middleware-cloudflare/src/client

> WASM-compatible storage client with BRC-103/104 authentication for Cloudflare Workers.

## Overview

This module provides `WorkerStorageClient`, a Cloudflare Workers-compatible client for communicating with `storage.babbage.systems` via authenticated JSON-RPC. Unlike the `StorageClient` in `bsv-wallet-toolbox` (which depends on reqwest, tokio, and `Peer<W, SimplifiedFetchTransport>`), this implementation uses `worker::Fetch` with inline BRC-103/104 handshake and signing, making it fully WASM-compatible.

The client handles the complete BRC-103/104 authentication lifecycle: initial handshake at `/.well-known/auth`, session nonce exchange, signature creation/verification, and authenticated General message sending with BRC-104 headers.

## Architecture

```
client/
├── mod.rs          # Module root, re-exports public types
├── json_rpc.rs     # JSON-RPC 2.0 request/response/error types
└── storage.rs      # WorkerStorageClient: handshake, signing, RPC calls
```

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-exports `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError`, and `WorkerStorageClient` |
| `json_rpc.rs` | Minimal JSON-RPC 2.0 types for storage server communication: `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError` |
| `storage.rs` | `WorkerStorageClient` struct with BRC-103/104 handshake, authenticated RPC transport, and high-level storage operations (`make_available`, `find_or_insert_user`, `internalize_action`, `list_outputs`, `create_action`, `process_action`) |

## Key Exports

### `WorkerStorageClient` (from `storage.rs`)

The primary type. A stateful HTTP client that manages a BRC-103/104 session with the storage server.

| Member | Description |
|--------|-------------|
| `MAINNET_URL` | `"https://storage.babbage.systems"` |
| `TESTNET_URL` | `"https://staging-storage.babbage.systems"` |
| `new(wallet, endpoint_url)` | Create client for a custom endpoint (trailing slash stripped) |
| `mainnet(wallet)` | Create client targeting mainnet storage |
| `testnet(wallet)` | Create client targeting testnet/staging storage |
| `rpc_call<T>(method, params)` | Generic authenticated JSON-RPC call; returns deserialized `T` |
| `make_available()` | Calls `makeAvailable` RPC; returns storage settings (chain, identity key, etc.) |
| `find_or_insert_user(identity_key)` | Calls `findOrInsertUser` RPC; returns user object with `userId` |
| `internalize_action(auth, args)` | Calls `internalizeAction` RPC; records transaction and credits outputs |
| `list_outputs(auth, args)` | Calls `listOutputs` RPC; returns array of wallet output objects |
| `create_action(auth, args)` | Calls `createAction` RPC; returns unsigned transaction template for local signing |
| `process_action(auth, args)` | Calls `processAction` RPC; submits signed transaction for broadcast, returns final BEEF |

### JSON-RPC Types (from `json_rpc.rs`)

| Type | Description |
|------|-------------|
| `JsonRpcRequest` | Serializable request: `jsonrpc`, `method`, `params: Vec<Value>`, `id: u64`. Constructor: `new(id, method, params)` |
| `JsonRpcResponse` | Deserializable response: `jsonrpc: String`, `result: Option<Value>`, `error: Option<JsonRpcError>`, `id: u64` |
| `JsonRpcError` | Error object with all-optional fields for dual-format compatibility: `code: Option<i32>`, `message: Option<String>`, `data: Option<Value>`, `name: Option<String>`. Implements `Display` |
| `JSON_RPC_VERSION` | Constant `"2.0"` |

**Note on `JsonRpcError`:** Some servers (e.g., `storage.babbage.systems`) return non-standard error objects with `{isError, name, message}` instead of the standard `{code, message, data}`. All fields use `#[serde(default)]` to handle both formats. The `Display` impl prioritizes `code` over `name` for formatting.

## Internal Details

### BRC-103/104 Handshake (`perform_handshake`)

The handshake is triggered lazily on the first RPC call via `ensure_session()`:

1. Generate a session nonce using `create_nonce()` with counterparty=None (Self) and originator `"bsv-wallet-toolbox"`
2. Build an `AuthMessage` with `MessageType::InitialRequest` and POST to `{endpoint}/.well-known/auth`
3. Parse the `InitialResponse`, verify `your_nonce` matches our session nonce
4. Extract the server's session nonce from `initial_nonce` or `nonce` field
5. Verify the response signature with TS SDK-compatible signing data (see below)
6. Store session state (`PeerSessionState`: `our_nonce`, `peer_nonce`, `server_identity_key`)

**TS SDK Signing Data Compatibility:** The TS SDK's `Peer.base64ToBytes(nonce1 + nonce2)` uses `Buffer.from(concatenated, 'base64')`, which stops decoding at the first `=` padding character. This means only the first nonce's raw bytes (32 bytes) are used as signing data. The Rust SDK's `signing_data()` decodes each nonce separately and concatenates (64 bytes), which doesn't match. To maintain compatibility, the handshake verification uses `from_base64(session_nonce)` directly (32 bytes) instead of calling `signing_data()`.

### Authenticated RPC (`rpc_call`)

Each RPC call after session establishment:

1. Build a `JsonRpcRequest` with auto-incrementing ID
2. Generate a 32-byte random request ID
3. Wrap the JSON-RPC body in an `HttpRequest` payload (BRC-104 format) for signing
4. Build a `General` `AuthMessage` with a random nonce and the peer's session nonce
5. Sign with `ProtoWallet::create_signature` using `AUTH_PROTOCOL_ID` at `SecurityLevel::Counterparty`
6. Send via `worker::Fetch` with BRC-104 headers (`x-bsv-auth-*`)
7. Parse JSON-RPC response, check for errors and ID match, deserialize result

**Important: `peer_nonce` is NOT updated from response headers.** Unlike what one might expect, the server's response nonce is a random value (not HMAC-derived). Updating `peer_nonce` would break subsequent calls because: (1) server session lookup fails (indexed by handshake nonce), (2) `verifyNonce` fails (random nonce isn't wallet-derived), and (3) signature keyID won't match. This matches TS SDK behavior where `peerSession.peerNonce` is set once during handshake.

### BRC-104 Headers

The `headers` submodule defines the header names used for authentication:

| Constant | Header |
|----------|--------|
| `VERSION` | `x-bsv-auth-version` |
| `IDENTITY_KEY` | `x-bsv-auth-identity-key` |
| `NONCE` | `x-bsv-auth-nonce` |
| `YOUR_NONCE` | `x-bsv-auth-your-nonce` |
| `SIGNATURE` | `x-bsv-auth-signature` |
| `MESSAGE_TYPE` | `x-bsv-auth-message-type` |
| `REQUEST_ID` | `x-bsv-auth-request-id` |

### Session State

`PeerSessionState` (private) holds:
- `our_nonce` — our session nonce (base64), retained for potential session re-establishment
- `peer_nonce` — server's session nonce (base64), set once during handshake and never updated
- `server_identity_key` — server's `PublicKey` for signature verification

## Usage

### Creating a Client

```rust
use bsv_middleware_cloudflare::client::WorkerStorageClient;
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::primitives::PrivateKey;

let wallet = ProtoWallet::new(Some(PrivateKey::from_hex("abcd...")?));
let mut client = WorkerStorageClient::mainnet(wallet);
```

### Making Storage Calls

```rust
// Initialize connection and get storage settings
let settings = client.make_available().await?;

// Look up or create a user by identity key
let user = client.find_or_insert_user("02abc...").await?;

// Internalize a payment transaction
let result = client.internalize_action(auth_json, args_json).await?;

// List wallet outputs
let outputs = client.list_outputs(auth_json, args_json).await?;

// Create an outgoing transaction (returns unsigned template)
let action = client.create_action(auth_json, args_json).await?;

// Process a signed transaction (broadcast and get BEEF)
let result = client.process_action(auth_json, signed_args_json).await?;
```

### Generic RPC Calls

```rust
use serde_json::json;

// Call any RPC method with typed deserialization
let result: MyResponseType = client.rpc_call(
    "someMethod",
    vec![json!("param1"), json!(42)],
).await?;
```

## Error Handling

All methods return `crate::error::Result<T>` (`Result<T, AuthCloudflareError>`). Errors map to these variants:

| Scenario | Error Variant |
|----------|---------------|
| HTTP fetch failures, non-2xx status | `TransportError` |
| JSON serialization/deserialization | `SerializationError` |
| BSV SDK operations (signing, nonce creation) | `SdkError` |
| Handshake nonce mismatch, invalid signature | `InvalidAuthentication` |
| JSON-RPC error from storage server | `TransportError` (wraps `JsonRpcError::Display`) |
| Response ID mismatch | `TransportError` |

## Tests

`storage.rs` contains structural unit tests (not integration tests, since full tests require `wasm32` target + network access):

- `test_create_client` — verifies constructor and URL storage
- `test_mainnet_url` — validates `MAINNET_URL` constant
- `test_testnet_url` — validates `TESTNET_URL` constant
- `test_url_trailing_slash_stripped` — ensures trailing slashes are normalized

## Dependencies

- `bsv_sdk` — `auth::transports::HttpRequest`, `auth::types::{AuthMessage, MessageType, AUTH_PROTOCOL_ID}`, `auth::utils::create_nonce`, `primitives::{to_base64, from_base64, PublicKey}`, `wallet::{ProtoWallet, Counterparty, CreateSignatureArgs, Protocol, SecurityLevel, VerifySignatureArgs}`
- `worker` — `Fetch`, `Request`, `RequestInit`, `Response`, `Headers`, `Method` (Cloudflare Workers runtime)
- `serde` / `serde_json` — JSON serialization for RPC and auth messages
- `rand` — `RngCore` for random request IDs and message nonces
- `hex` — Signature hex encoding
- `wasm_bindgen` — `JsValue` for request body construction

## Related

- [`../CLAUDE.md`](../CLAUDE.md) — Parent crate overview, architecture, and all exports
- [`../transport/CLAUDE.md`](../transport/CLAUDE.md) — Server-side BRC-104 header handling (this module implements the client side)
- [`../middleware/CLAUDE.md`](../middleware/CLAUDE.md) — Server-side BRC-103/104 auth middleware (this module is the client counterpart)
- [`../error.rs`](../error.rs) — `AuthCloudflareError` enum used by all client methods
