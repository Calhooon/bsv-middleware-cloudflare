//! KV-backed session storage for BRC-103/104 authentication.

use crate::error::{AuthCloudflareError, Result};
use crate::types::StoredSession;
use worker::kv::KvStore;

/// Session manager backed by Cloudflare KV.
///
/// This stores session state for BRC-103/104 authenticated peers in Cloudflare KV,
/// with automatic TTL expiration.
pub struct KvSessionStorage {
    kv: KvStore,
    prefix: String,
    session_ttl_seconds: u64,
}

impl KvSessionStorage {
    /// Creates a new KV session storage.
    ///
    /// # Arguments
    ///
    /// * `kv` - The Cloudflare KV namespace
    /// * `prefix` - Prefix for all keys (to allow multiple instances)
    /// * `session_ttl_seconds` - TTL for sessions in seconds
    pub fn new(kv: KvStore, prefix: &str, session_ttl_seconds: u64) -> Self {
        Self {
            kv,
            prefix: prefix.to_string(),
            session_ttl_seconds,
        }
    }

    /// Constructs the KV key for a session by its nonce.
    fn session_key(&self, session_nonce: &str) -> String {
        format!("{}:session:{}", self.prefix, session_nonce)
    }

    /// Constructs the KV key for the identity -> session index.
    fn identity_key(&self, identity_key: &str, session_nonce: &str) -> String {
        format!("{}:identity:{}:{}", self.prefix, identity_key, session_nonce)
    }

    /// Gets a session by its nonce.
    pub async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        let key = self.session_key(session_nonce);
        match self.kv.get(&key).json::<StoredSession>().await {
            Ok(session) => Ok(session),
            Err(e) => Err(AuthCloudflareError::KvError(e.to_string())),
        }
    }

    /// Saves a session to KV.
    ///
    /// Also creates an index entry by identity key for lookups.
    pub async fn save_session(&self, session: &StoredSession) -> Result<()> {
        let session_key = self.session_key(&session.session_nonce);
        let json = serde_json::to_string(session)?;

        // Store by session nonce
        self.kv
            .put(&session_key, &json)
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?
            .expiration_ttl(self.session_ttl_seconds)
            .execute()
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        // Also index by identity key for lookups
        let identity_key = self.identity_key(&session.peer_identity_key, &session.session_nonce);
        self.kv
            .put(&identity_key, &session.session_nonce)
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?
            .expiration_ttl(self.session_ttl_seconds)
            .execute()
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        Ok(())
    }

    /// Removes a session from KV.
    pub async fn remove_session(&self, session_nonce: &str) -> Result<()> {
        // Get session first to find identity key
        if let Some(session) = self.get_session(session_nonce).await? {
            let identity_key = self.identity_key(&session.peer_identity_key, session_nonce);
            let _ = self.kv.delete(&identity_key).await;
        }

        let session_key = self.session_key(session_nonce);
        self.kv
            .delete(&session_key)
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        Ok(())
    }

    /// Gets all sessions for a given identity key.
    ///
    /// Note: This uses KV list which may be slow for large numbers of sessions.
    pub async fn get_sessions_for_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Vec<StoredSession>> {
        // List all session nonces for this identity
        let prefix = format!("{}:identity:{}:", self.prefix, identity_key_hex);
        let list = self
            .kv
            .list()
            .prefix(prefix)
            .execute()
            .await
            .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;

        let mut sessions = Vec::new();
        for key in list.keys {
            if let Ok(Some(nonce)) = self.kv.get(&key.name).text().await {
                if let Ok(Some(session)) = self.get_session(&nonce).await {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Updates an existing session.
    pub async fn update_session(&self, session: &StoredSession) -> Result<()> {
        self.save_session(session).await
    }

    /// Checks if a session exists.
    pub async fn has_session(&self, session_nonce: &str) -> Result<bool> {
        Ok(self.get_session(session_nonce).await?.is_some())
    }

    /// Gets a session by identity key (returns the most recent one if multiple exist).
    pub async fn get_session_by_identity(&self, identity_key_hex: &str) -> Result<Option<StoredSession>> {
        let sessions = self.get_sessions_for_identity(identity_key_hex).await?;
        // Return the most recently updated session
        Ok(sessions.into_iter().max_by_key(|s| s.last_update))
    }
}
