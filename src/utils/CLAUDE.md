# Utilities - CORS Handling for Cloudflare Workers

> CORS configuration and header management utilities for BSV authentication in Cloudflare Workers.

## Overview

This module provides CORS (Cross-Origin Resource Sharing) utilities specifically designed for BSV authentication workflows running on Cloudflare Workers. The utilities handle preflight requests, header configuration, and response augmentation with proper CORS headers that expose the BSV authentication and payment-related headers required by clients.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module exports - re-exports `cors_headers`, `handle_cors_preflight`, `CorsConfig` |
| `cors.rs` | CORS header generation, preflight handling, and configuration |

## Public Exports

Re-exported from `mod.rs` (accessible via `crate::utils::{...}`):

```rust
pub use cors::{cors_headers, handle_cors_preflight, CorsConfig};
```

Additional public functions in `cors.rs` (accessible via `crate::utils::cors::{...}`):
- `cors_headers_with_config`
- `handle_cors_preflight_with_config`
- `add_cors_to_response`
- `add_cors_to_response_with_config`

## Key Types

### CorsConfig

Configuration struct for customizing CORS behavior.

```rust
pub struct CorsConfig {
    pub allow_origin: String,        // Default: "*"
    pub allow_methods: Vec<String>,  // Default: GET, POST, PUT, DELETE, OPTIONS
    pub allow_headers: Vec<String>,  // Default: includes BSV auth headers
    pub expose_headers: Vec<String>, // Default: includes BSV auth/payment headers
    pub max_age: u32,                // Default: 86400 (24 hours)
}
```

**Default Allowed Headers:**
- `Content-Type`
- `Authorization`
- `x-bsv-auth-version`
- `x-bsv-auth-identity-key`
- `x-bsv-auth-nonce`
- `x-bsv-auth-your-nonce`
- `x-bsv-auth-signature`
- `x-bsv-auth-message-type`
- `x-bsv-auth-request-id`
- `x-bsv-auth-requested-certificates`
- `x-bsv-payment`

**Default Exposed Headers:**
- `x-bsv-auth-version`
- `x-bsv-auth-identity-key`
- `x-bsv-auth-nonce`
- `x-bsv-auth-your-nonce`
- `x-bsv-auth-signature`
- `x-bsv-payment-version`
- `x-bsv-payment-satoshis-required`
- `x-bsv-payment-derivation-prefix`
- `x-bsv-payment-satoshis-paid`

## Key Functions

### cors_headers

```rust
pub fn cors_headers() -> Headers
```

- **Purpose:** Creates CORS headers with default configuration
- **Returns:** `worker::Headers` populated with all CORS headers
- **Example:**
```rust
let headers = cors_headers();
// Use with response builder
```

### cors_headers_with_config

```rust
pub fn cors_headers_with_config(config: &CorsConfig) -> Headers
```

- **Purpose:** Creates CORS headers with custom configuration
- **Parameters:** `config` - Custom CORS configuration
- **Returns:** `worker::Headers` with configured CORS settings
- **Example:**
```rust
let config = CorsConfig {
    allow_origin: "https://example.com".to_string(),
    ..CorsConfig::default()
};
let headers = cors_headers_with_config(&config);
```

### handle_cors_preflight

```rust
pub fn handle_cors_preflight() -> worker::Result<Response>
```

- **Purpose:** Handle OPTIONS preflight requests with default CORS configuration
- **Returns:** Empty 204 response with CORS headers
- **Example:**
```rust
if req.method() == Method::Options {
    return handle_cors_preflight();
}
```

### handle_cors_preflight_with_config

```rust
pub fn handle_cors_preflight_with_config(config: &CorsConfig) -> worker::Result<Response>
```

- **Purpose:** Handle OPTIONS preflight requests with custom CORS configuration
- **Parameters:** `config` - Custom CORS configuration
- **Returns:** Empty 204 response with custom CORS headers
- **Example:**
```rust
let config = CorsConfig {
    max_age: 3600,  // 1 hour cache
    ..CorsConfig::default()
};
if req.method() == Method::Options {
    return handle_cors_preflight_with_config(&config);
}
```

### add_cors_to_response

```rust
pub fn add_cors_to_response(response: Response) -> Response
```

- **Purpose:** Add CORS headers to an existing response
- **Parameters:** `response` - The response to augment
- **Returns:** Response with CORS headers added
- **Example:**
```rust
let response = Response::ok("Success")?;
let cors_response = add_cors_to_response(response);
```

### add_cors_to_response_with_config

```rust
pub fn add_cors_to_response_with_config(response: Response, config: &CorsConfig) -> Response
```

- **Purpose:** Add custom CORS headers to an existing response
- **Parameters:**
  - `response` - The response to augment
  - `config` - Custom CORS configuration
- **Returns:** Response with custom CORS headers added
- **Example:**
```rust
let config = CorsConfig {
    allow_origin: "https://myapp.com".to_string(),
    ..CorsConfig::default()
};
let response = Response::ok("Success")?;
let cors_response = add_cors_to_response_with_config(response, &config);
```

## Usage Patterns

### Basic Preflight Handling

```rust
use crate::utils::{handle_cors_preflight, add_cors_to_response};
use worker::{Request, Response, Method};

pub async fn handle_request(req: Request) -> worker::Result<Response> {
    // Handle CORS preflight
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    // Process request...
    let response = Response::ok("Hello")?;

    // Add CORS headers to response
    Ok(add_cors_to_response(response))
}
```

### Restricted Origin Configuration

```rust
use crate::utils::{CorsConfig, handle_cors_preflight_with_config, add_cors_to_response_with_config};

let config = CorsConfig {
    allow_origin: "https://trusted-domain.com".to_string(),
    allow_methods: vec!["GET".to_string(), "POST".to_string()],
    max_age: 3600,
    ..CorsConfig::default()
};

// Use throughout your worker
if is_options {
    return handle_cors_preflight_with_config(&config);
}
let response = add_cors_to_response_with_config(my_response, &config);
```

### Why BSV Headers are Exposed

The default configuration exposes BSV authentication and payment headers because:

1. **Authentication Flow:** Clients need to read server-sent nonces and signatures to complete the mutual authentication handshake
2. **Payment Integration:** Payment-required responses include satoshi amounts and derivation info that clients must access
3. **Version Negotiation:** Both auth and payment protocol versions are exposed for compatibility checking

## Dependencies

This module depends on:
- `worker` crate - Cloudflare Workers runtime types (`Headers`, `Response`)
- `crate::transport::auth_headers` - BSV authentication header constants
- `crate::middleware::payment::payment_headers` - BSV payment header constants

## Related

- `../transport/` - Contains auth header constant definitions used by CORS configuration
- `../middleware/payment.rs` - Contains payment header constants and payment middleware
