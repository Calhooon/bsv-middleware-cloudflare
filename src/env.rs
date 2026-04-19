//! Environment wrapper for Cloudflare Workers secrets and bindings.

use crate::error::{AuthCloudflareError, Result};
use worker::Env;

/// Helper for accessing Cloudflare Workers environment bindings.
pub struct WorkerEnv<'a> {
    env: &'a Env,
}

impl<'a> WorkerEnv<'a> {
    /// Creates a new WorkerEnv wrapper.
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Gets the server private key from secrets.
    ///
    /// The secret should be named `SERVER_PRIVATE_KEY` and contain a 64-character
    /// hexadecimal string representing a secp256k1 private key.
    pub fn get_server_private_key(&self) -> Result<String> {
        self.env
            .secret("SERVER_PRIVATE_KEY")
            .map(|s| s.to_string())
            .map_err(|_| {
                AuthCloudflareError::ConfigError(
                    "SERVER_PRIVATE_KEY secret not configured".to_string(),
                )
            })
    }

    /// Gets the AUTH_SESSIONS KV namespace.
    pub fn get_auth_sessions_kv(&self) -> Result<worker::kv::KvStore> {
        self.env
            .kv("AUTH_SESSIONS")
            .map_err(|e| AuthCloudflareError::ConfigError(format!("AUTH_SESSIONS KV not bound: {}", e)))
    }

    /// Gets the PAYMENTS KV namespace.
    pub fn get_payments_kv(&self) -> Result<worker::kv::KvStore> {
        self.env
            .kv("PAYMENTS")
            .map_err(|e| AuthCloudflareError::ConfigError(format!("PAYMENTS KV not bound: {}", e)))
    }

    /// Gets an environment variable.
    pub fn get_var(&self, name: &str) -> Option<String> {
        self.env.var(name).ok().map(|v| v.to_string())
    }

    /// Gets the environment (development, production, etc.).
    pub fn get_environment(&self) -> String {
        self.get_var("ENVIRONMENT").unwrap_or_else(|| "production".to_string())
    }
}
