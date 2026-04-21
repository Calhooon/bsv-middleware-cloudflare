//! CORS handling utilities for Cloudflare Workers.

use crate::middleware::payment::payment_headers;
use crate::transport::auth_headers;
use worker::{Headers, Response};

/// CORS configuration.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins (default: "*").
    pub allow_origin: String,
    /// Allowed methods.
    pub allow_methods: Vec<String>,
    /// Allowed headers.
    pub allow_headers: Vec<String>,
    /// Exposed headers.
    pub expose_headers: Vec<String>,
    /// Max age for preflight cache in seconds.
    pub max_age: u32,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allow_origin: "*".to_string(),
            allow_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allow_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                auth_headers::VERSION.to_string(),
                auth_headers::IDENTITY_KEY.to_string(),
                auth_headers::NONCE.to_string(),
                auth_headers::YOUR_NONCE.to_string(),
                auth_headers::SIGNATURE.to_string(),
                auth_headers::MESSAGE_TYPE.to_string(),
                auth_headers::REQUEST_ID.to_string(),
                auth_headers::REQUESTED_CERTIFICATES.to_string(),
                payment_headers::PAYMENT.to_string(),
            ],
            expose_headers: vec![
                auth_headers::VERSION.to_string(),
                auth_headers::IDENTITY_KEY.to_string(),
                auth_headers::NONCE.to_string(),
                auth_headers::YOUR_NONCE.to_string(),
                auth_headers::SIGNATURE.to_string(),
                payment_headers::VERSION.to_string(),
                payment_headers::SATOSHIS_REQUIRED.to_string(),
                payment_headers::DERIVATION_PREFIX.to_string(),
                payment_headers::SATOSHIS_PAID.to_string(),
            ],
            max_age: 86400, // 24 hours
        }
    }
}

/// Creates CORS headers with default configuration.
pub fn cors_headers() -> Headers {
    cors_headers_with_config(&CorsConfig::default())
}

/// Creates CORS headers with custom configuration.
pub fn cors_headers_with_config(config: &CorsConfig) -> Headers {
    let headers = Headers::new();
    let _ = headers.set("Access-Control-Allow-Origin", &config.allow_origin);
    let _ = headers.set(
        "Access-Control-Allow-Methods",
        &config.allow_methods.join(", "),
    );
    let _ = headers.set(
        "Access-Control-Allow-Headers",
        &config.allow_headers.join(", "),
    );
    let _ = headers.set(
        "Access-Control-Expose-Headers",
        &config.expose_headers.join(", "),
    );
    let _ = headers.set("Access-Control-Max-Age", &config.max_age.to_string());
    headers
}

/// Handle CORS preflight request.
pub fn handle_cors_preflight() -> worker::Result<Response> {
    Ok(Response::empty()?
        .with_status(204)
        .with_headers(cors_headers()))
}

/// Handle CORS preflight request with custom configuration.
pub fn handle_cors_preflight_with_config(config: &CorsConfig) -> worker::Result<Response> {
    Ok(Response::empty()?
        .with_status(204)
        .with_headers(cors_headers_with_config(config)))
}

/// Add CORS headers to an existing response.
pub fn add_cors_to_response(response: Response) -> Response {
    response.with_headers(cors_headers())
}

/// Add CORS headers to an existing response with custom configuration.
pub fn add_cors_to_response_with_config(response: Response, config: &CorsConfig) -> Response {
    response.with_headers(cors_headers_with_config(config))
}
