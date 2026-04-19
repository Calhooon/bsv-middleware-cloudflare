# Transport Module
> HTTP transport layer for BRC-104 authenticated requests in Cloudflare Workers

## Overview

This module provides utilities for extracting and constructing BRC-104 authenticated HTTP requests and responses within Cloudflare Workers. It handles the serialization/deserialization of `AuthMessage` structures to/from HTTP headers and binary payloads, enabling cryptographic authentication for API requests using BSV keys.

The transport layer bridges the gap between raw HTTP requests (from the `worker` crate) and the authentication message format defined by the BSV SDK.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module exports - re-exports `CloudflareTransport`, `auth_headers`, `HttpRequestData`, `HttpResponseData` |
| `cloudflare.rs` | Core implementation of BRC-104 header extraction, payload serialization, and transport utilities (~858 lines, includes tests) |

## Key Exports

### `auth_headers` Module

Constants for BRC-104 authentication header names:

| Constant | Header Name | Purpose |
|----------|-------------|---------|
| `VERSION` | `x-bsv-auth-version` | Auth protocol version |
| `IDENTITY_KEY` | `x-bsv-auth-identity-key` | Sender's compressed public key (66 hex chars) |
| `NONCE` | `x-bsv-auth-nonce` | Sender's nonce (base64) |
| `INITIAL_NONCE` | `x-bsv-auth-initial-nonce` | Initial nonce for handshake (base64) |
| `YOUR_NONCE` | `x-bsv-auth-your-nonce` | Recipient's nonce from previous message (base64) |
| `SIGNATURE` | `x-bsv-auth-signature` | Message signature (hex or base64) |
| `MESSAGE_TYPE` | `x-bsv-auth-message-type` | Message type (e.g., "general", "initialRequest") |
| `REQUEST_ID` | `x-bsv-auth-request-id` | Request correlation ID (base64, 32 bytes) |
| `REQUESTED_CERTIFICATES` | `x-bsv-auth-requested-certificates` | Certificate specification (JSON) |

### `HttpRequestData`

Deserialized HTTP request extracted from a General message payload:

```rust
pub struct HttpRequestData {
    pub request_id: [u8; 32],           // Correlation ID
    pub method: String,                  // HTTP method
    pub path: String,                    // URL path
    pub search: String,                  // Query string
    pub headers: Vec<(String, String)>,  // Signed headers
    pub body: Vec<u8>,                   // Request body
}
```

**Methods:**
- `url(&self) -> String` - Returns combined path + search string

### `HttpResponseData`

HTTP response to be serialized as a General message payload:

```rust
pub struct HttpResponseData {
    pub request_id: [u8; 32],           // From the request
    pub status: u16,                     // HTTP status code
    pub headers: Vec<(String, String)>,  // Only x-bsv-* and authorization (excluding x-bsv-auth-*)
    pub body: Vec<u8>,                   // Response body
}
```

**Methods:**
- `to_payload(&self) -> Vec<u8>` - Serializes to binary payload format

### `CloudflareTransport`

Static utility struct for working with BRC-104 authenticated requests:

| Method | Signature | Purpose |
|--------|-----------|---------|
| `has_auth_headers` | `fn(req: &Request) -> bool` | Checks if request has `REQUEST_ID` or `MESSAGE_TYPE` auth header |
| `is_handshake_request` | `fn(req: &Request) -> bool` | Checks if request path ends with `/.well-known/auth` (any HTTP method) |
| `get_identity_key` | `fn(req: &Request) -> Result<String>` | Extracts identity key hex from headers |
| `get_request_id` | `fn(req: &Request) -> Result<[u8; 32]>` | Extracts and decodes request ID |
| `extract_auth_message` | `async fn(req: &mut Request) -> Result<(AuthMessage, Vec<u8>)>` | Builds `AuthMessage` from request; returns `(message, raw_body_bytes)` |
| `message_to_headers` | `fn(message: &AuthMessage) -> Vec<(String, String)>` | Converts `AuthMessage` to response headers |
| `create_headers` | `fn(pairs: &[(String, String)]) -> Headers` | Creates `worker::Headers` from pairs |

## Internal Functions

### Payload Serialization

The module uses a Bitcoin-style varint encoding for binary payloads:

- `write_varint(value: i64) -> Vec<u8>` - Encodes integers with variable-length format
  - Values < 253: single byte
  - Values < 0x10000: `0xFD` + 2 bytes (little-endian)
  - Values < 0x100000000: `0xFE` + 4 bytes (little-endian)
  - Larger values: `0xFF` + 8 bytes (little-endian)
  - Negative values (-1): 9 bytes of `0xFF` (indicates empty/missing)

- `extract_signable_headers(req: &Request) -> Vec<(String, String)>` - Extracts headers eligible for signing from a request, matching SimplifiedFetchTransport rules:
  - Includes `authorization` header
  - Includes headers starting with `x-bsv-` (but NOT `x-bsv-auth-*`)
  - Includes `content-type` header (value stripped to media type only, params like `; charset=utf-8` removed)
  - Results sorted alphabetically by lowercase key

- `build_request_payload(request_id, method, path, search, headers, body)` - Constructs binary payload from HTTP request components

### Payload Format

**Request Payload:**
```
[request_id: 32 bytes]
[method: varint length + bytes]
[path: varint length + bytes, or -1 if empty]
[search: varint length + bytes, or -1 if empty]
[headers: varint count + pairs (varint key + varint value)]
[body: varint length + bytes, or -1 if empty]
```

**Response Payload:**
```
[request_id: 32 bytes]
[status: varint]
[headers: varint count + pairs (varint key + varint value)]
[body: varint length + bytes, or -1 if empty]
```

## Usage

### Checking for Authenticated Requests

```rust
use bsv_middleware_cloudflare::transport::CloudflareTransport;

pub async fn handle_request(req: Request) -> Result<Response> {
    if CloudflareTransport::has_auth_headers(&req) {
        // Process authenticated request
    } else {
        // Handle unauthenticated request
    }
}
```

### Extracting Authentication Data

```rust
use bsv_middleware_cloudflare::transport::CloudflareTransport;

pub async fn handle_auth(mut req: Request) -> Result<Response> {
    // Check if this is a handshake
    if CloudflareTransport::is_handshake_request(&req) {
        // Handle handshake flow
    }

    // Extract the full auth message and raw body bytes
    let (auth_message, raw_body) = CloudflareTransport::extract_auth_message(&mut req).await?;
    // raw_body contains the original request body for General messages (empty for handshakes)

    // Get identity for logging/validation
    let identity = CloudflareTransport::get_identity_key(&req)?;
}
```

### Building Response Headers

```rust
use bsv_middleware_cloudflare::transport::{CloudflareTransport, HttpResponseData};

fn build_response(auth_message: &AuthMessage, body: Vec<u8>, request_id: [u8; 32]) -> Response {
    // Build response data
    let response_data = HttpResponseData {
        request_id,
        status: 200,
        headers: vec![],
        body,
    };

    // Convert auth message to headers
    let auth_headers = CloudflareTransport::message_to_headers(auth_message);
    let headers = CloudflareTransport::create_headers(&auth_headers);

    Response::from_bytes(response_data.body)
        .unwrap()
        .with_headers(headers)
}
```

## Message Flow

### Handshake Request (initialRequest/initialResponse)
1. Client sends request to `/.well-known/auth` with auth headers (any HTTP method; `is_handshake_request` checks path only)
2. `is_handshake_request()` returns `true`
3. `extract_auth_message()` parses headers + JSON body, merging fields from JSON into the message (nonce, initial_nonce, your_nonce, signature, certificates, requested_certificates)
4. Server processes handshake, returns response with `message_to_headers()`

### General Request (authenticated API call)
1. Client sends request with auth headers including `REQUEST_ID`
2. `has_auth_headers()` returns `true`
3. `extract_auth_message()` parses headers + builds binary payload from HTTP metadata
4. Server verifies signature, processes request
5. Response includes auth headers via `message_to_headers()`

## Key Implementation Details

### `extract_auth_message` Behavior

Returns `(AuthMessage, Vec<u8>)` — the second element is the raw request body bytes consumed during extraction:
- **General messages**: `raw_body_bytes` contains the original request body (useful for passing through to handlers)
- **Handshake messages**: `raw_body_bytes` is empty (handshake body is protocol JSON, not passed through)

Other behavior:
- **Version**: Defaults to `AUTH_VERSION` constant if `x-bsv-auth-version` header is missing
- **Message type**: Defaults to `"general"` if `x-bsv-auth-message-type` header is missing
- **Request ID**: Falls back to `[0u8; 32]` if missing/invalid (does not error for general messages)
- **Signature parsing**: Tries hex decoding first, falls back to base64 (`hex::decode` then `from_base64`)
- **General messages**: Reads body as bytes, extracts signable headers via `extract_signable_headers()`, then constructs binary payload with full HTTP metadata (method, path, search, headers, body)
- **Handshake messages**: Reads body as JSON text, deserializes as `AuthMessage`, and merges non-None fields (nonce, initial_nonce, your_nonce, signature, certificates, requested_certificates) into the header-based message

### `message_to_headers` Behavior

- Always includes: `version`, `identity_key`, `message_type`
- Conditionally includes (only when `Some`): `nonce`, `initial_nonce`, `your_nonce`, `signature`, `requested_certificates`
- Signature is hex-encoded in output headers
- Requested certificates are JSON-serialized

## Error Handling

All methods return `Result<T, AuthCloudflareError>` where failures include:

- `AuthCloudflareError::InvalidAuthentication` - Missing/invalid headers, malformed keys
- `AuthCloudflareError::TransportError` - Body read failures, URL parsing errors

## Dependencies

### External Crates
- `worker` - Cloudflare Workers types (`Request`, `Headers`, `Url`)
- `hex` - Hex encoding/decoding for signatures
- `serde_json` - JSON parsing for certificates and handshake bodies

### Internal Dependencies
- `crate::error` - `AuthCloudflareError`, `Result` type alias
- `bsv_sdk::auth::types` - `AuthMessage`, `MessageType`, `AUTH_VERSION`
- `bsv_sdk::primitives` - `from_base64`, `PublicKey`

## Tests

The module includes comprehensive unit tests in `cloudflare.rs` (lines 481-858):

| Test Group | Coverage |
|------------|----------|
| **Varint encoding** | Zero, single-byte (1-252), boundary at 252/253, two-byte (253-0xFFFF), four-byte (0x10000-0xFFFFFFFF), eight-byte (>0x100000000), negative (-1 empty marker) |
| **Response payload** | Empty body (verifies -1 marker), body with content, headers serialization, various status codes (200, 201, 204, 400, 401, 402, 404, 500) |
| **Request payload** | GET without body, POST with JSON body, query parameters, custom headers |
| **message_to_headers** | InitialResponse with all fields, General with minimal fields, verifies None fields are excluded |
| **Header constants** | Validates all 9 auth header constant values match BRC-104 spec |
| **HttpRequestData** | `url()` method with and without query string |

Note: `extract_auth_message` and `has_auth_headers`/`is_handshake_request` are not unit-tested here because they depend on `worker::Request` which requires the Cloudflare Workers runtime. These are tested via integration tests.

## Related

- `../middleware/auth.rs` - Uses transport to process authentication flow
- `../middleware/payment.rs` - Uses transport for payment-authenticated requests
- `../error.rs` - Error types used throughout transport layer
- `../storage/` - Session storage consumed by middleware after transport extracts auth data
