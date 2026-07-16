//! Middleware implementations for authentication and payment.

pub mod auth;
pub mod multipart;
pub mod payment;

pub use auth::{
    process_auth, sign_json_response, sign_response, AuthMiddlewareOptions, AuthResult, AuthSession,
};
pub use multipart::prepare_multipart_payment;
#[allow(deprecated)] // re-exported for backward compatibility
pub use payment::process_payment;
pub use payment::{
    payment_headers, process_payment_with_storage, process_payment_with_storage_signed,
    PaymentMiddlewareOptions, PaymentResult,
    PAYMENT_NONCE_SCOPE,
};
