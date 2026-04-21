//! Error types for BSV Auth Cloudflare middleware.

use thiserror::Error;

/// Error type for BSV Auth Cloudflare middleware.
#[derive(Error, Debug)]
pub enum AuthCloudflareError {
    // ==================
    // Auth errors (match auth-express-middleware)
    // ==================
    /// Authentication is required but not provided.
    /// Express equivalent: `{ code: 'UNAUTHORIZED', message: 'Mutual-authentication failed!' }`
    #[error("Mutual-authentication failed!")]
    Unauthorized,

    /// Authentication headers or signature is invalid.
    #[error("Invalid authentication: {0}")]
    InvalidAuthentication(String),

    /// Session not found in storage.
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    // ==================
    // Payment errors (match payment-express-middleware exactly)
    // ==================
    /// Payment middleware was run before auth middleware.
    /// Express: `ERR_SERVER_MISCONFIGURED` / 500
    #[error("The payment middleware must be executed after the Auth middleware.")]
    ServerMisconfigured,

    /// Error calculating request price.
    /// Express: `ERR_PAYMENT_INTERNAL` / 500
    #[error("An internal error occurred while determining the payment required for this request.")]
    PaymentInternal(String),

    /// Payment is required to access this resource.
    /// Express: `ERR_PAYMENT_REQUIRED` / 402
    #[error(
        "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
    )]
    PaymentRequired {
        /// Amount required in satoshis.
        satoshis: u64,
        /// Derivation prefix for payment address generation.
        derivation_prefix: String,
    },

    /// Payment data is malformed or cannot be parsed.
    /// Express: `ERR_MALFORMED_PAYMENT` / 400
    #[error("The X-BSV-Payment header is not valid JSON.")]
    MalformedPayment(String),

    /// Derivation prefix is invalid or not recognized.
    /// Express: `ERR_INVALID_DERIVATION_PREFIX` / 400
    #[error("The X-BSV-Payment-Derivation-Prefix header is not valid.")]
    InvalidDerivationPrefix,

    /// Payment verification failed (wallet rejected).
    /// Express: `ERR_PAYMENT_FAILED` or error's own code / 400
    #[error("{0}")]
    PaymentFailed(String),

    /// Payment provided is invalid (duplicate, etc).
    #[error("Invalid payment: {0}")]
    InvalidPayment(String),

    // ==================
    // Infrastructure errors
    // ==================
    /// Error interacting with Cloudflare KV storage.
    #[error("KV storage error: {0}")]
    KvError(String),

    /// Error from the BSV SDK.
    #[error("SDK error: {0}")]
    SdkError(String),

    /// Error in the transport layer.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<bsv_sdk::Error> for AuthCloudflareError {
    fn from(e: bsv_sdk::Error) -> Self {
        AuthCloudflareError::SdkError(e.to_string())
    }
}

impl From<worker::Error> for AuthCloudflareError {
    fn from(e: worker::Error) -> Self {
        AuthCloudflareError::KvError(e.to_string())
    }
}

impl From<serde_json::Error> for AuthCloudflareError {
    fn from(e: serde_json::Error) -> Self {
        AuthCloudflareError::SerializationError(e.to_string())
    }
}

/// Result type alias for BSV Auth Cloudflare middleware.
pub type Result<T> = std::result::Result<T, AuthCloudflareError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Status code tests - verify HTTP status codes match Express exactly
    // ===========================================

    #[test]
    fn test_unauthorized_status_code() {
        assert_eq!(AuthCloudflareError::Unauthorized.status_code(), 401);
    }

    #[test]
    fn test_invalid_auth_status_code() {
        assert_eq!(
            AuthCloudflareError::InvalidAuthentication("test".into()).status_code(),
            401
        );
    }

    #[test]
    fn test_session_not_found_status_code() {
        assert_eq!(
            AuthCloudflareError::SessionNotFound("test".into()).status_code(),
            401
        );
    }

    #[test]
    fn test_server_misconfigured_status_code() {
        assert_eq!(AuthCloudflareError::ServerMisconfigured.status_code(), 500);
    }

    #[test]
    fn test_payment_internal_status_code() {
        assert_eq!(
            AuthCloudflareError::PaymentInternal("test".into()).status_code(),
            500
        );
    }

    #[test]
    fn test_payment_required_status_code() {
        assert_eq!(
            AuthCloudflareError::PaymentRequired {
                satoshis: 100,
                derivation_prefix: "test".into()
            }
            .status_code(),
            402
        );
    }

    #[test]
    fn test_malformed_payment_status_code() {
        assert_eq!(
            AuthCloudflareError::MalformedPayment("test".into()).status_code(),
            400
        );
    }

    #[test]
    fn test_invalid_derivation_prefix_status_code() {
        assert_eq!(
            AuthCloudflareError::InvalidDerivationPrefix.status_code(),
            400
        );
    }

    #[test]
    fn test_payment_failed_status_code() {
        assert_eq!(
            AuthCloudflareError::PaymentFailed("test".into()).status_code(),
            400
        );
    }

    #[test]
    fn test_invalid_payment_status_code() {
        assert_eq!(
            AuthCloudflareError::InvalidPayment("test".into()).status_code(),
            400
        );
    }

    #[test]
    fn test_kv_error_status_code() {
        assert_eq!(
            AuthCloudflareError::KvError("test".into()).status_code(),
            500
        );
    }

    #[test]
    fn test_config_error_status_code() {
        assert_eq!(
            AuthCloudflareError::ConfigError("test".into()).status_code(),
            500
        );
    }

    // ===========================================
    // Error code tests - verify machine-readable codes match Express exactly
    // ===========================================

    #[test]
    fn test_unauthorized_error_code() {
        assert_eq!(
            AuthCloudflareError::Unauthorized.error_code(),
            "UNAUTHORIZED"
        );
    }

    #[test]
    fn test_invalid_auth_error_code() {
        assert_eq!(
            AuthCloudflareError::InvalidAuthentication("test".into()).error_code(),
            "ERR_INVALID_AUTH"
        );
    }

    #[test]
    fn test_session_not_found_error_code() {
        assert_eq!(
            AuthCloudflareError::SessionNotFound("test".into()).error_code(),
            "ERR_SESSION_NOT_FOUND"
        );
    }

    #[test]
    fn test_server_misconfigured_error_code() {
        assert_eq!(
            AuthCloudflareError::ServerMisconfigured.error_code(),
            "ERR_SERVER_MISCONFIGURED"
        );
    }

    #[test]
    fn test_payment_internal_error_code() {
        assert_eq!(
            AuthCloudflareError::PaymentInternal("test".into()).error_code(),
            "ERR_PAYMENT_INTERNAL"
        );
    }

    #[test]
    fn test_payment_required_error_code() {
        assert_eq!(
            AuthCloudflareError::PaymentRequired {
                satoshis: 100,
                derivation_prefix: "test".into()
            }
            .error_code(),
            "ERR_PAYMENT_REQUIRED"
        );
    }

    #[test]
    fn test_malformed_payment_error_code() {
        assert_eq!(
            AuthCloudflareError::MalformedPayment("test".into()).error_code(),
            "ERR_MALFORMED_PAYMENT"
        );
    }

    #[test]
    fn test_invalid_derivation_prefix_error_code() {
        assert_eq!(
            AuthCloudflareError::InvalidDerivationPrefix.error_code(),
            "ERR_INVALID_DERIVATION_PREFIX"
        );
    }

    #[test]
    fn test_payment_failed_error_code() {
        assert_eq!(
            AuthCloudflareError::PaymentFailed("test".into()).error_code(),
            "ERR_PAYMENT_FAILED"
        );
    }

    #[test]
    fn test_invalid_payment_error_code() {
        assert_eq!(
            AuthCloudflareError::InvalidPayment("test".into()).error_code(),
            "ERR_INVALID_PAYMENT"
        );
    }

    // ===========================================
    // JSON output tests
    // ===========================================

    #[test]
    fn test_error_json_format() {
        let json = AuthCloudflareError::Unauthorized.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "UNAUTHORIZED");
        // Middleware-layer errors use `message` (matches TS wire format).
        assert_eq!(parsed["message"], "Mutual-authentication failed!");
        // And explicitly NOT `description` — that's for handler-layer errors.
        assert!(parsed.get("description").is_none());
    }

    #[test]
    fn test_handler_layer_error_uses_description() {
        let err = AuthCloudflareError::MalformedPayment("bad".into());
        let json = err.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Handler-layer errors keep `description` (matches TS handler format).
        assert!(parsed.get("description").is_some());
        assert!(parsed.get("message").is_none());
    }

    #[test]
    fn test_payment_required_json_format() {
        let err = AuthCloudflareError::PaymentRequired {
            satoshis: 500,
            derivation_prefix: "test-prefix".into(),
        };
        let json = err.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "ERR_PAYMENT_REQUIRED");
    }

    #[test]
    fn test_server_misconfigured_json_format() {
        let json = AuthCloudflareError::ServerMisconfigured.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "ERR_SERVER_MISCONFIGURED");
        assert_eq!(
            parsed["description"],
            "The payment middleware must be executed after the Auth middleware."
        );
    }

    #[test]
    fn test_malformed_payment_json_format() {
        let json = AuthCloudflareError::MalformedPayment("bad json".into()).to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["code"], "ERR_MALFORMED_PAYMENT");
        assert_eq!(
            parsed["description"],
            "The X-BSV-Payment header is not valid JSON."
        );
    }

    // ===========================================
    // Error display tests - verify messages match Express
    // ===========================================

    #[test]
    fn test_unauthorized_display() {
        assert_eq!(
            AuthCloudflareError::Unauthorized.to_string(),
            "Mutual-authentication failed!"
        );
    }

    #[test]
    fn test_server_misconfigured_display() {
        assert_eq!(
            AuthCloudflareError::ServerMisconfigured.to_string(),
            "The payment middleware must be executed after the Auth middleware."
        );
    }

    #[test]
    fn test_payment_required_display() {
        let err = AuthCloudflareError::PaymentRequired {
            satoshis: 100,
            derivation_prefix: "test".into(),
        };
        assert_eq!(
            err.to_string(),
            "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
        );
    }

    // ===========================================
    // From conversions
    // ===========================================

    #[test]
    fn test_from_serde_error() {
        let err: serde_json::Error = serde_json::from_str::<String>("invalid").unwrap_err();
        let auth_err: AuthCloudflareError = err.into();
        assert_eq!(auth_err.error_code(), "ERR_SERIALIZATION");
        assert_eq!(auth_err.status_code(), 400);
    }

    // ===========================================
    // Payment error codes match Express payment-express-middleware exactly
    // ===========================================

    #[test]
    fn test_all_payment_error_codes_match_express() {
        // These MUST match payment-express-middleware/src/index.ts exactly
        let test_cases = vec![
            (
                AuthCloudflareError::ServerMisconfigured,
                "ERR_SERVER_MISCONFIGURED",
            ),
            (
                AuthCloudflareError::PaymentInternal("x".into()),
                "ERR_PAYMENT_INTERNAL",
            ),
            (
                AuthCloudflareError::PaymentRequired {
                    satoshis: 100,
                    derivation_prefix: "x".into(),
                },
                "ERR_PAYMENT_REQUIRED",
            ),
            (
                AuthCloudflareError::MalformedPayment("x".into()),
                "ERR_MALFORMED_PAYMENT",
            ),
            (
                AuthCloudflareError::InvalidDerivationPrefix,
                "ERR_INVALID_DERIVATION_PREFIX",
            ),
            (
                AuthCloudflareError::PaymentFailed("x".into()),
                "ERR_PAYMENT_FAILED",
            ),
        ];
        for (err, expected_code) in test_cases {
            assert_eq!(
                err.error_code(),
                expected_code,
                "Error code mismatch for {:?}",
                err
            );
        }
    }

    // ===========================================
    // Auth error codes match Express auth-express-middleware exactly
    // ===========================================

    #[test]
    fn test_all_auth_error_codes_match_express() {
        // These MUST match auth-express-middleware
        let test_cases = vec![
            (AuthCloudflareError::Unauthorized, "UNAUTHORIZED"),
            (
                AuthCloudflareError::InvalidAuthentication("x".into()),
                "ERR_INVALID_AUTH",
            ),
            (
                AuthCloudflareError::SessionNotFound("x".into()),
                "ERR_SESSION_NOT_FOUND",
            ),
        ];
        for (err, expected_code) in test_cases {
            assert_eq!(
                err.error_code(),
                expected_code,
                "Error code mismatch for {:?}",
                err
            );
        }
    }
}

impl AuthCloudflareError {
    /// Returns the HTTP status code appropriate for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            // Auth errors
            Self::Unauthorized => 401,
            Self::InvalidAuthentication(_) => 401,
            Self::SessionNotFound(_) => 401,
            // Payment errors (matching Express exactly)
            Self::ServerMisconfigured => 500,
            Self::PaymentInternal(_) => 500,
            Self::PaymentRequired { .. } => 402,
            Self::MalformedPayment(_) => 400,
            Self::InvalidDerivationPrefix => 400,
            Self::PaymentFailed(_) => 400,
            Self::InvalidPayment(_) => 400,
            // Infrastructure errors
            Self::KvError(_) => 500,
            Self::SdkError(_) => 500,
            Self::TransportError(_) => 500,
            Self::ConfigError(_) => 500,
            Self::SerializationError(_) => 400,
        }
    }

    /// Returns a machine-readable error code for this error.
    /// These match the Express middleware error codes exactly.
    pub fn error_code(&self) -> &'static str {
        match self {
            // Auth errors (match auth-express-middleware)
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidAuthentication(_) => "ERR_INVALID_AUTH",
            Self::SessionNotFound(_) => "ERR_SESSION_NOT_FOUND",
            // Payment errors (match payment-express-middleware exactly)
            Self::ServerMisconfigured => "ERR_SERVER_MISCONFIGURED",
            Self::PaymentInternal(_) => "ERR_PAYMENT_INTERNAL",
            Self::PaymentRequired { .. } => "ERR_PAYMENT_REQUIRED",
            Self::MalformedPayment(_) => "ERR_MALFORMED_PAYMENT",
            Self::InvalidDerivationPrefix => "ERR_INVALID_DERIVATION_PREFIX",
            Self::PaymentFailed(_) => "ERR_PAYMENT_FAILED",
            Self::InvalidPayment(_) => "ERR_INVALID_PAYMENT",
            // Infrastructure errors
            Self::KvError(_) => "ERR_STORAGE",
            Self::SdkError(_) => "ERR_SDK",
            Self::TransportError(_) => "ERR_TRANSPORT",
            Self::ConfigError(_) => "ERR_CONFIG",
            Self::SerializationError(_) => "ERR_SERIALIZATION",
        }
    }

    /// Converts this error to a JSON response body.
    ///
    /// Field-name choice mirrors the TS reference servers: the BRC-31
    /// middleware layer (Unauthorized) uses `message`; handler-layer
    /// errors use `description`. Verified against the live TS server
    /// at messagebox.babbage.systems which returns
    /// `{"status":"error","code":"UNAUTHORIZED","message":"Mutual-authentication failed!"}`
    /// on any unauthed request.
    pub fn to_json(&self) -> String {
        let mut obj = serde_json::Map::new();
        obj.insert("status".into(), "error".into());
        obj.insert("code".into(), self.error_code().into());
        let field = if matches!(self, Self::Unauthorized) {
            "message"
        } else {
            "description"
        };
        obj.insert(field.into(), self.to_string().into());
        serde_json::Value::Object(obj).to_string()
    }
}
