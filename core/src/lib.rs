//! # bsv-middleware-core
//!
//! The runtime-free rules of BSV BRC-103/104 authentication and BRC-29
//! payment verification. This is the skeleton: the six-word verdict, the
//! header-service seam, the single-use store traits and the context types.

pub mod header_service;
pub mod store;
pub mod types;
pub mod verdict;

pub use header_service::{HeaderService, LookupFn, MerkleRoot, NoService, ServiceError};
pub use store::{ClaimStore, MemoryStore, PaymentNonceStore, StoreError, PAYMENT_NONCE_SCOPE};
pub use types::{AuthContext, BsvPayment, PaymentContext};
pub use verdict::{PaymentFault, PaymentVerdict};
