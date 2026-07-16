//! Worker-compatible storage client for storage.babbage.systems.
//!
//! Implements BRC-103/104 authentication using `worker::Fetch` instead of
//! `reqwest`, making it compatible with Cloudflare Workers' WASM environment.
//!
//! This is a minimal client exposing only the RPC methods needed for payment
//! processing: `make_available`, `find_or_insert_user`, and `internalize_action`.

use super::json_rpc::{JsonRpcRequest, JsonRpcResponse};
use crate::error::{AuthCloudflareError, Result};
use bsv_sdk::auth::transports::HttpRequest;
use bsv_sdk::auth::types::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
use bsv_sdk::auth::utils::create_nonce;
use bsv_sdk::primitives::{to_base64, PublicKey};
use bsv_sdk::wallet::{
    Counterparty, CreateSignatureArgs, Protocol, SecurityLevel, VerifySignatureArgs,
};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::kv::KvStore;

/// BRC-104 header names.
mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
}

/// Originator string for auth operations.
const ORIGINATOR: &str = "bsv-wallet-toolbox";

/// Session state after BRC-103/104 handshake.
struct PeerSessionState {
    /// Our session nonce (base64). Retained for session re-establishment.
    our_nonce: String,
    /// Server's session nonce (base64) — stored as peer_nonce.
    peer_nonce: String,
    /// Server's identity key.
    server_identity_key: PublicKey,
}

/// Version of the [`ClientSessionSnapshot`] wire format. Bump on any
/// incompatible change; [`WorkerStorageClient::resume_session`] rejects
/// mismatched versions (callers then fall back to a fresh handshake).
pub const CLIENT_SESSION_SNAPSHOT_VERSION: u32 = 1;

/// A persistable snapshot of an established BRC-103/104 CLIENT session,
/// mirroring the TS SDK's `PeerSession` (`sessionNonce` / `peerNonce` /
/// `peerIdentityKey`).
///
/// # What this contains — and deliberately does NOT contain
///
/// Every field is **public** wire material: both session nonces were already
/// transmitted in cleartext during the handshake (they are session
/// *identifiers*, not secrets), and the server identity key is the server's
/// public key. Message authenticity rests exclusively on the wallet's private
/// key, from which a per-message signing key is BRC-42-derived at request
/// time — the private key is never part of the session and never serialized.
///
/// Per-request state is likewise never persisted: each General message signs
/// a **fresh 256-bit random nonce** and a fresh 256-bit random request ID
/// (see `send_rpc_once`), so two isolates resuming the same snapshot
/// concurrently cannot reuse a nonce — matching the TS SDK, where one
/// long-lived `PeerSession` serves any number of concurrent requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSessionSnapshot {
    /// Snapshot format version (see [`CLIENT_SESSION_SNAPSHOT_VERSION`]).
    #[serde(default)]
    pub v: u32,
    /// Our session nonce (base64) from the handshake InitialRequest.
    pub our_nonce: String,
    /// The server's session nonce (base64) from the InitialResponse. This is
    /// the key the server uses to look its session up (`x-bsv-auth-your-nonce`).
    pub peer_nonce: String,
    /// The server's identity public key (compressed hex).
    pub server_identity_key: String,
}

/// Where to persist/resume the client session (Cloudflare KV).
struct KvSessionCache {
    kv: KvStore,
    key: String,
    ttl_seconds: u64,
}

/// Worker-compatible storage client for `storage.babbage.systems`.
///
/// Uses `worker::Fetch` for HTTP and inline BRC-103/104 handshake/signing
/// (no `Peer` type or tokio dependencies).
///
/// # Example
///
/// ```rust,ignore
/// use bsv_middleware_cloudflare::client::WorkerStorageClient;
/// use bsv_sdk::wallet::ProtoWallet;
/// use bsv_sdk::primitives::PrivateKey;
///
/// let wallet = ProtoWallet::new(Some(PrivateKey::from_hex("...")?));
/// let mut client = WorkerStorageClient::mainnet(wallet);
///
/// let settings = client.make_available().await?;
/// let user = client.find_or_insert_user(&identity_key).await?;
/// ```
pub struct WorkerStorageClient {
    endpoint_url: String,
    wallet: bsv_sdk::wallet::ProtoWallet,
    next_id: u64,
    session: Option<PeerSessionState>,
    /// Optional KV persistence of the session across (stateless) isolates.
    session_cache: Option<KvSessionCache>,
    /// True while the current `session` was resumed from a snapshot rather
    /// than established by a handshake in this instance.
    session_resumed: bool,
}

impl WorkerStorageClient {
    /// Mainnet storage URL.
    pub const MAINNET_URL: &'static str = "https://storage.babbage.systems";

    /// Testnet storage URL.
    pub const TESTNET_URL: &'static str = "https://staging-storage.babbage.systems";

    /// Creates a new client for the given endpoint.
    pub fn new(wallet: bsv_sdk::wallet::ProtoWallet, endpoint_url: &str) -> Self {
        Self {
            endpoint_url: endpoint_url.trim_end_matches('/').to_string(),
            wallet,
            next_id: 1,
            session: None,
            session_cache: None,
            session_resumed: false,
        }
    }

    /// Creates a new client for mainnet.
    pub fn mainnet(wallet: bsv_sdk::wallet::ProtoWallet) -> Self {
        Self::new(wallet, Self::MAINNET_URL)
    }

    /// Creates a new client for testnet.
    pub fn testnet(wallet: bsv_sdk::wallet::ProtoWallet) -> Self {
        Self::new(wallet, Self::TESTNET_URL)
    }

    /// Returns our identity key.
    fn identity_key(&self) -> PublicKey {
        self.wallet.identity_key()
    }

    // ========================================================================
    // Session persistence (skip the 0.8–2.9 s handshake across isolates)
    // ========================================================================

    /// Persist/resume the BRC-103/104 session in Cloudflare KV under `key`.
    ///
    /// With this set, `ensure_session()` first tries to resume the snapshot
    /// stored at `key`; only on miss/parse-failure does it perform the full
    /// handshake (and then writes the fresh snapshot back, best-effort). If
    /// the server's auth layer rejects a resumed session (expired server-side,
    /// server KV wiped, server key rotated), `rpc_call` re-handshakes,
    /// overwrites the snapshot, and retries the RPC exactly once — see
    /// `is_auth_layer_rejection` for why that retry cannot double-execute.
    ///
    /// `ttl_seconds` must be comfortably below the server's session TTL
    /// (`AuthMiddlewareOptions::session_ttl_seconds`, default 3600) so a
    /// resumed session is always inside the server's window; KV clamps to a
    /// 60 s minimum. Only public handshake material is stored — never a
    /// private key (see [`ClientSessionSnapshot`]).
    pub fn use_kv_session_cache(&mut self, kv: KvStore, key: String, ttl_seconds: u64) {
        self.session_cache = Some(KvSessionCache {
            kv,
            key,
            ttl_seconds,
        });
    }

    /// True while the current session was resumed from a snapshot (KV cache
    /// or `resume_session`) rather than handshaken by this instance. Useful
    /// for logging warm vs cold auth paths.
    pub fn session_was_resumed(&self) -> bool {
        self.session_resumed
    }

    /// Exports the current session as a persistable snapshot (None if no
    /// session has been established/resumed yet).
    pub fn export_session(&self) -> Option<ClientSessionSnapshot> {
        self.session.as_ref().map(|s| ClientSessionSnapshot {
            v: CLIENT_SESSION_SNAPSHOT_VERSION,
            our_nonce: s.our_nonce.clone(),
            peer_nonce: s.peer_nonce.clone(),
            server_identity_key: s.server_identity_key.to_hex(),
        })
    }

    /// Resumes a previously exported session, skipping the handshake.
    ///
    /// Validation only checks the snapshot is well-formed (version, non-empty
    /// nonces, parseable server key) — whether the server still honors the
    /// session is discovered on the first RPC, where a rejection triggers the
    /// fresh-handshake retry in `rpc_call`.
    pub fn resume_session(&mut self, snapshot: ClientSessionSnapshot) -> Result<()> {
        if snapshot.v != CLIENT_SESSION_SNAPSHOT_VERSION {
            return Err(AuthCloudflareError::SerializationError(format!(
                "session snapshot version {} != {}",
                snapshot.v, CLIENT_SESSION_SNAPSHOT_VERSION
            )));
        }
        if snapshot.our_nonce.is_empty() || snapshot.peer_nonce.is_empty() {
            return Err(AuthCloudflareError::SerializationError(
                "session snapshot has empty nonce".into(),
            ));
        }
        let server_identity_key =
            PublicKey::from_hex(&snapshot.server_identity_key).map_err(|e| {
                AuthCloudflareError::SerializationError(format!(
                    "session snapshot server key: {}",
                    e
                ))
            })?;
        self.session = Some(PeerSessionState {
            our_nonce: snapshot.our_nonce,
            peer_nonce: snapshot.peer_nonce,
            server_identity_key,
        });
        self.session_resumed = true;
        Ok(())
    }

    /// Best-effort resume from the configured KV cache. Any failure (no
    /// cache configured, KV miss, KV error, parse/validation failure) simply
    /// returns false and the caller falls back to a fresh handshake.
    async fn try_resume_from_kv(&mut self) -> bool {
        let (key, kv) = match &self.session_cache {
            Some(c) => (c.key.clone(), &c.kv),
            None => return false,
        };
        let text = match kv.get(&key).text().await {
            Ok(Some(t)) => t,
            _ => return false,
        };
        match serde_json::from_str::<ClientSessionSnapshot>(&text) {
            Ok(snapshot) => self.resume_session(snapshot).is_ok(),
            Err(_) => false,
        }
    }

    /// Best-effort persist of the current session to the configured KV cache.
    /// Failures are logged and ignored — the session works either way; the
    /// only cost of a failed write is a handshake on some future isolate.
    async fn persist_session_to_kv(&self) {
        let cache = match &self.session_cache {
            Some(c) => c,
            None => return,
        };
        let snapshot = match self.export_session() {
            Some(s) => s,
            None => return,
        };
        let json = match serde_json::to_string(&snapshot) {
            Ok(j) => j,
            Err(_) => return,
        };
        match cache.kv.put(&cache.key, json) {
            Ok(put) => {
                // Cloudflare KV enforces a 60 s minimum TTL — clamp up.
                if let Err(e) = put.expiration_ttl(cache.ttl_seconds.max(60)).execute().await {
                    worker::console_warn!("client session KV persist skipped (non-fatal): {e:?}");
                }
            }
            Err(e) => {
                worker::console_warn!("client session KV persist skipped (non-fatal): {e:?}");
            }
        }
    }

    /// True when an HTTP response was produced by the SERVER'S AUTH LAYER
    /// rejecting the request BEFORE the JSON-RPC handler ran — i.e. the RPC
    /// definitively did NOT execute, so re-handshaking and resending is safe
    /// even for non-idempotent methods.
    ///
    /// Grounding (bsv-middleware-cloudflare `process_auth`, which wallet-infra
    /// wires in front of its JSON-RPC dispatch):
    ///   * expired/unknown session → 401 `ERR_SESSION_NOT_FOUND`
    ///   * replayed request nonce  → 401 `ERR_REPLAYED_REQUEST`
    ///   * missing auth material   → 401 `UNAUTHORIZED` / `ERR_INVALID_AUTH`
    ///   * signature mismatch (e.g. resumed session vs a rotated server key)
    ///     → `Err(InvalidAuthentication)` which the worker surfaces as a 500
    ///     whose body carries the Display string "Invalid authentication".
    ///
    /// All of these occur strictly before dispatch. Handler-side failures
    /// return signed JSON-RPC error bodies with status 200, or 5xx bodies
    /// that do not carry the auth-layer strings — those are NOT retried.
    fn is_auth_layer_rejection(status: u16, body: &str) -> bool {
        if status == 401 || status == 403 {
            return true;
        }
        status == 500
            && (body.contains("Invalid authentication")
                || body.contains("Session not found")
                || body.contains("Mutual-authentication failed"))
    }

    /// Makes a POST request using worker::Fetch.
    ///
    /// Returns the worker::Response.
    async fn fetch_post(
        url: &str,
        headers: &[(String, String)],
        body: &str,
    ) -> Result<worker::Response> {
        let worker_headers = worker::Headers::new();
        for (key, value) in headers {
            worker_headers
                .set(key, value)
                .map_err(|e| AuthCloudflareError::TransportError(format!("Header error: {}", e)))?;
        }

        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_headers(worker_headers)
            .with_body(Some(wasm_bindgen::JsValue::from_str(body)));

        let request = worker::Request::new_with_init(url, &init)
            .map_err(|e| AuthCloudflareError::TransportError(format!("Request error: {}", e)))?;

        worker::Fetch::Request(request)
            .send()
            .await
            .map_err(|e| AuthCloudflareError::TransportError(format!("Fetch error: {}", e)))
    }

    /// Performs the BRC-103/104 handshake with the storage server.
    ///
    /// 1. Creates a session nonce via `create_nonce()`
    /// 2. POSTs InitialRequest to `/.well-known/auth`
    /// 3. Parses InitialResponse and verifies signature
    /// 4. Stores session state for subsequent General messages
    async fn perform_handshake(&mut self) -> Result<()> {
        let my_identity = self.identity_key();

        // Create session nonce (counterparty=None=Self, matching Go/TS).
        // create_nonce uses WalletInterface trait (async), which ProtoWallet implements.
        let session_nonce = create_nonce(&self.wallet, None, ORIGINATOR)
            .await
            .map_err(|e| AuthCloudflareError::SdkError(e.to_string()))?;

        // Build InitialRequest
        let mut msg = AuthMessage::new(MessageType::InitialRequest, my_identity);
        msg.initial_nonce = Some(session_nonce.clone());

        // Serialize and POST to /.well-known/auth
        let auth_url = format!("{}/.well-known/auth", self.endpoint_url);
        let body = serde_json::to_string(&msg)
            .map_err(|e| AuthCloudflareError::SerializationError(e.to_string()))?;

        let mut response = Self::fetch_post(
            &auth_url,
            &[("Content-Type".to_string(), "application/json".to_string())],
            &body,
        )
        .await?;

        let status = response.status_code();
        if !(200..300).contains(&status) {
            let body_text = response.text().await.unwrap_or_default();
            return Err(AuthCloudflareError::TransportError(format!(
                "Auth endpoint returned {}: {}",
                status, body_text
            )));
        }

        // Parse InitialResponse
        let response_text = response
            .text()
            .await
            .map_err(|e| AuthCloudflareError::TransportError(format!("Read error: {}", e)))?;

        let response_msg: AuthMessage = serde_json::from_str(&response_text).map_err(|e| {
            AuthCloudflareError::TransportError(format!(
                "Failed to parse auth response: {} - body: {}",
                e, response_text
            ))
        })?;

        // Verify response type
        if response_msg.message_type != MessageType::InitialResponse {
            return Err(AuthCloudflareError::InvalidAuthentication(format!(
                "Expected InitialResponse, got {:?}",
                response_msg.message_type
            )));
        }

        // Verify your_nonce matches our session nonce
        let echoed_nonce = response_msg.your_nonce.as_deref().unwrap_or("");
        if echoed_nonce != session_nonce {
            return Err(AuthCloudflareError::InvalidAuthentication(
                "InitialResponse your_nonce doesn't match our session nonce".into(),
            ));
        }

        // Get server's session nonce (initial_nonce in the response, or nonce)
        let server_nonce = response_msg
            .initial_nonce
            .as_ref()
            .or(response_msg.nonce.as_ref())
            .ok_or_else(|| {
                AuthCloudflareError::InvalidAuthentication(
                    "InitialResponse missing server nonce".into(),
                )
            })?
            .clone();

        // Verify InitialResponse signature.
        //
        // Use the SDK's signing_data() which concatenates decoded your_nonce || initial_nonce
        // (64 bytes). This matches the current TS/Go SDK behavior and storage server signing.
        let data = response_msg.signing_data();
        let key_id = response_msg.get_key_id(None); // InitialResponse ignores this param

        let signature = response_msg.signature.as_ref().ok_or_else(|| {
            AuthCloudflareError::InvalidAuthentication("InitialResponse not signed".into())
        })?;

        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);

        // Use ProtoWallet's sync verify_signature method
        let verify_result = self
            .wallet
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature: signature.clone(),
                protocol_id: protocol,
                key_id,
                counterparty: Some(Counterparty::Other(response_msg.identity_key.clone())),
                for_self: None,
            })
            .map_err(|e| AuthCloudflareError::SdkError(e.to_string()))?;

        if !verify_result.valid {
            return Err(AuthCloudflareError::InvalidAuthentication(
                "InitialResponse signature invalid".into(),
            ));
        }

        // Store session (freshly handshaken, not resumed from a snapshot)
        self.session = Some(PeerSessionState {
            our_nonce: session_nonce,
            peer_nonce: server_nonce,
            server_identity_key: response_msg.identity_key,
        });
        self.session_resumed = false;

        Ok(())
    }

    /// Ensures we have an authenticated session: in-memory first, then a
    /// KV-cached snapshot (if configured), then the full handshake. A fresh
    /// handshake persists its snapshot back to KV (best-effort) so subsequent
    /// isolates skip the handshake entirely.
    async fn ensure_session(&mut self) -> Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        if self.try_resume_from_kv().await {
            return Ok(());
        }
        self.perform_handshake().await?;
        self.session_resumed = false;
        self.persist_session_to_kv().await;
        Ok(())
    }

    /// Makes an authenticated JSON-RPC call to the storage server.
    ///
    /// 1. Ensures we have a BRC-103/104 session (resumed from KV when cached)
    /// 2. Sends one freshly signed attempt (`send_rpc_once`)
    /// 3. If the server's AUTH LAYER rejected it (stale/expired session —
    ///    the RPC handler never ran, see `is_auth_layer_rejection`),
    ///    re-handshakes, overwrites the KV snapshot, and retries exactly once
    /// 4. Parses response and extracts result
    pub async fn rpc_call<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T> {
        self.ensure_session().await?;

        let (mut status, mut id, mut response_text) = self.send_rpc_once(method, &params).await?;

        if Self::is_auth_layer_rejection(status, &response_text) {
            // Correctness over speed: a stale resumed session (or a session
            // that expired server-side mid-isolate) must never surface as a
            // failed RPC. The rejection came from the auth middleware BEFORE
            // dispatch, so the RPC did not execute — re-handshake, refresh
            // the cache, and resend once (fresh id/nonce/request-id/signature).
            self.session = None;
            self.session_resumed = false;
            self.perform_handshake().await?;
            self.persist_session_to_kv().await;
            let (s, i, t) = self.send_rpc_once(method, &params).await?;
            status = s;
            id = i;
            response_text = t;
        }

        if !(200..300).contains(&status) {
            return Err(AuthCloudflareError::TransportError(format!(
                "Storage server returned {}: {}",
                status, response_text
            )));
        }

        // Parse JSON-RPC response
        let rpc_resp: JsonRpcResponse = serde_json::from_str(&response_text).map_err(|e| {
            AuthCloudflareError::SerializationError(format!(
                "Failed to parse RPC response: {} - body: {}",
                e, response_text
            ))
        })?;

        // Check for JSON-RPC error
        if let Some(error) = rpc_resp.error {
            return Err(AuthCloudflareError::TransportError(format!(
                "RPC error: {}",
                error
            )));
        }

        // Check ID match
        if rpc_resp.id != id {
            return Err(AuthCloudflareError::TransportError(format!(
                "RPC response ID mismatch: expected {}, got {}",
                id, rpc_resp.id
            )));
        }

        // Deserialize result
        let result_value = rpc_resp.result.unwrap_or(Value::Null);
        serde_json::from_value(result_value)
            .map_err(|e| AuthCloudflareError::SerializationError(e.to_string()))
    }

    /// Sends ONE signed JSON-RPC attempt over the current session and returns
    /// `(http_status, jsonrpc_id, body_text)`. Every attempt is independently
    /// safe: a fresh JSON-RPC id, a fresh 256-bit random request ID, a fresh
    /// 256-bit random message nonce, and a fresh BRC-42-derived signature —
    /// nothing per-request is ever reused, whether the session was resumed
    /// or freshly handshaken.
    ///
    /// 1. Builds JSON-RPC request
    /// 2. Wraps in HttpRequest payload for signing
    /// 3. Signs with BRC-42 key derivation
    /// 4. Sends via `worker::Fetch` with BRC-104 auth headers
    async fn send_rpc_once(&mut self, method: &str, params: &[Value]) -> Result<(u16, u64, String)> {
        // Build JSON-RPC request
        let id = self.next_id;
        self.next_id += 1;
        let rpc_req = JsonRpcRequest::new(id, method, params.to_vec());
        let rpc_body = serde_json::to_vec(&rpc_req)
            .map_err(|e| AuthCloudflareError::SerializationError(e.to_string()))?;
        let rpc_body_str = String::from_utf8(rpc_body.clone())
            .map_err(|e| AuthCloudflareError::SerializationError(e.to_string()))?;

        // Generate 32-byte random request ID
        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);

        // Build HttpRequest payload (BRC-104) for signing
        let http_request = HttpRequest {
            request_id,
            method: "POST".to_string(),
            path: "/".to_string(),
            search: String::new(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: rpc_body,
        };
        let payload = http_request.to_payload();

        // Build General AuthMessage
        let my_identity = self.identity_key();
        let mut msg = AuthMessage::new(MessageType::General, my_identity);

        // Random message nonce (matches TS: Utils.toBase64(Random(32)))
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        msg.nonce = Some(to_base64(&random_bytes));

        // Reference the session fields we need before signing
        let session = self.session.as_ref().ok_or_else(|| {
            AuthCloudflareError::InvalidAuthentication("no session established".into())
        })?;
        msg.your_nonce = Some(session.peer_nonce.clone());
        msg.payload = Some(payload);

        // Sign the message using ProtoWallet's sync create_signature
        let data = msg.signing_data();
        let key_id = msg.get_key_id(Some(&session.peer_nonce));
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);
        let counterparty = Counterparty::Other(session.server_identity_key.clone());

        let sig_result = self
            .wallet
            .create_signature(CreateSignatureArgs {
                data: Some(data),
                hash_to_directly_sign: None,
                protocol_id: protocol,
                key_id,
                counterparty: Some(counterparty),
            })
            .map_err(|e| AuthCloudflareError::SdkError(e.to_string()))?;

        msg.signature = Some(sig_result.signature);

        // Build headers for the HTTP request
        let mut http_headers = vec![
            (headers::VERSION.to_string(), msg.version.clone()),
            (headers::IDENTITY_KEY.to_string(), msg.identity_key.to_hex()),
            (headers::MESSAGE_TYPE.to_string(), "general".to_string()),
            (headers::REQUEST_ID.to_string(), to_base64(&request_id)),
            ("content-type".to_string(), "application/json".to_string()),
        ];

        if let Some(ref nonce) = msg.nonce {
            http_headers.push((headers::NONCE.to_string(), nonce.clone()));
        }
        if let Some(ref your_nonce) = msg.your_nonce {
            http_headers.push((headers::YOUR_NONCE.to_string(), your_nonce.clone()));
        }
        if let Some(ref sig) = msg.signature {
            http_headers.push((headers::SIGNATURE.to_string(), hex::encode(sig)));
        }

        // Send the request
        let url = format!("{}/", self.endpoint_url);
        let mut response = Self::fetch_post(&url, &http_headers, &rpc_body_str).await?;

        // NOTE: Do NOT update peer_nonce from the response's x-bsv-auth-nonce header.
        // In the TS SDK, peerSession.peerNonce is set once during handshake and never
        // updated for General messages. The server's response nonce is a random value
        // (not HMAC-derived), and if we store it as peer_nonce:
        //   1. Session lookup fails (server indexes by handshake nonce, not random nonce)
        //   2. verifyNonce fails (random nonce is not wallet-derived)
        //   3. Signature keyID doesn't match (uses peer_nonce, server expects session nonce)

        let status = response.status_code();
        let response_text = response.text().await.map_err(|e| {
            AuthCloudflareError::TransportError(format!("Failed to read RPC response: {}", e))
        })?;

        Ok((status, id, response_text))
    }

    // ========================================================================
    // High-level storage operations
    // ========================================================================

    /// Calls `makeAvailable` on the storage server.
    ///
    /// Returns the storage settings (chain, storage identity key, etc.).
    pub async fn make_available(&mut self) -> Result<Value> {
        self.rpc_call("makeAvailable", vec![]).await
    }

    /// Calls `findOrInsertUser` to get or create a user by identity key.
    ///
    /// Returns the user object with `userId`, `identityKey`, etc.
    pub async fn find_or_insert_user(&mut self, identity_key: &str) -> Result<Value> {
        self.rpc_call("findOrInsertUser", vec![serde_json::json!(identity_key)])
            .await
    }

    /// Calls `internalizeAction` to accept an incoming transaction.
    ///
    /// This is the key method for payment processing — it tells the storage
    /// server to record the transaction and credit the outputs to the wallet.
    pub async fn internalize_action(&mut self, auth: Value, args: Value) -> Result<Value> {
        self.rpc_call("internalizeAction", vec![auth, args]).await
    }

    /// Calls `listOutputs` to get wallet outputs.
    ///
    /// Returns an array of output objects with `satoshis`, `outputIndex`, etc.
    pub async fn list_outputs(&mut self, auth: Value, args: Value) -> Result<Value> {
        self.rpc_call("listOutputs", vec![auth, args]).await
    }

    /// Calls `createAction` to create an outgoing transaction.
    ///
    /// Returns a `StorageCreateActionResult` with the unsigned transaction
    /// template, input details (for signing), output details, and a reference.
    /// The caller must sign the inputs locally and then call `process_action`.
    pub async fn create_action(&mut self, auth: Value, args: Value) -> Result<Value> {
        self.rpc_call("createAction", vec![auth, args]).await
    }

    /// Calls `processAction` to process a signed transaction.
    ///
    /// After signing the template from `create_action`, call this with the
    /// signed transaction bytes and reference to broadcast and get final BEEF.
    pub async fn process_action(&mut self, auth: Value, args: Value) -> Result<Value> {
        self.rpc_call("processAction", vec![auth, args]).await
    }

    /// Calls `relinquishOutput` to remove an output from basket tracking.
    ///
    /// After sending funds to an external party (e.g. refunds), call this
    /// so the wallet stops treating the sent output as its own spendable UTXO.
    ///
    /// `args` should contain `{"basket": "<name>", "output": "<txid>.<vout>"}`.
    pub async fn relinquish_output(&mut self, auth: Value, args: Value) -> Result<Value> {
        self.rpc_call("relinquishOutput", vec![auth, args]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require wasm32 target + network access.
    // These are structural tests only.

    #[test]
    fn test_create_client() {
        let wallet =
            bsv_sdk::wallet::ProtoWallet::new(Some(bsv_sdk::primitives::PrivateKey::random()));
        let client = WorkerStorageClient::new(wallet, "https://example.com");
        assert_eq!(client.endpoint_url, "https://example.com");
    }

    #[test]
    fn test_mainnet_url() {
        assert_eq!(
            WorkerStorageClient::MAINNET_URL,
            "https://storage.babbage.systems"
        );
    }

    #[test]
    fn test_testnet_url() {
        assert_eq!(
            WorkerStorageClient::TESTNET_URL,
            "https://staging-storage.babbage.systems"
        );
    }

    #[test]
    fn test_url_trailing_slash_stripped() {
        let wallet =
            bsv_sdk::wallet::ProtoWallet::new(Some(bsv_sdk::primitives::PrivateKey::random()));
        let client = WorkerStorageClient::new(wallet, "https://example.com/");
        assert_eq!(client.endpoint_url, "https://example.com");
    }

    // ===========================================
    // Session snapshot (persist/resume) tests
    // ===========================================

    fn test_client() -> WorkerStorageClient {
        let wallet =
            bsv_sdk::wallet::ProtoWallet::new(Some(bsv_sdk::primitives::PrivateKey::random()));
        WorkerStorageClient::new(wallet, "https://example.com")
    }

    fn test_snapshot() -> ClientSessionSnapshot {
        ClientSessionSnapshot {
            v: CLIENT_SESSION_SNAPSHOT_VERSION,
            our_nonce: "b64-our-nonce".to_string(),
            peer_nonce: "b64-peer-nonce".to_string(),
            server_identity_key: bsv_sdk::primitives::PrivateKey::random()
                .public_key()
                .to_hex(),
        }
    }

    #[test]
    fn test_session_snapshot_save_load_roundtrip() {
        let mut client = test_client();
        assert!(client.export_session().is_none());
        assert!(!client.session_was_resumed());

        let snap = test_snapshot();
        let server_key = snap.server_identity_key.clone();

        // JSON round-trip — exactly what the KV cache stores and reloads.
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: ClientSessionSnapshot = serde_json::from_str(&json).unwrap();
        client.resume_session(parsed).unwrap();
        assert!(client.session_was_resumed());

        let exported = client.export_session().unwrap();
        assert_eq!(exported.v, CLIENT_SESSION_SNAPSHOT_VERSION);
        assert_eq!(exported.our_nonce, "b64-our-nonce");
        assert_eq!(exported.peer_nonce, "b64-peer-nonce");
        assert_eq!(exported.server_identity_key, server_key);
    }

    #[test]
    fn test_session_snapshot_contains_no_private_material() {
        // Guard: the persisted JSON must carry ONLY the four public fields.
        // A private key must never be serializable from a snapshot.
        let json = serde_json::to_value(test_snapshot()).unwrap();
        let obj = json.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["our_nonce", "peer_nonce", "server_identity_key", "v"]
        );
    }

    #[test]
    fn test_resume_rejects_wrong_version() {
        let mut client = test_client();
        let mut snap = test_snapshot();
        snap.v = CLIENT_SESSION_SNAPSHOT_VERSION + 1;
        assert!(client.resume_session(snap).is_err());
        assert!(client.export_session().is_none());
        assert!(!client.session_was_resumed());
    }

    #[test]
    fn test_resume_rejects_bad_server_key() {
        let mut client = test_client();
        let mut snap = test_snapshot();
        snap.server_identity_key = "not-a-pubkey".to_string();
        assert!(client.resume_session(snap).is_err());
        assert!(client.export_session().is_none());
    }

    #[test]
    fn test_resume_rejects_empty_nonces() {
        let mut client = test_client();
        let mut snap = test_snapshot();
        snap.peer_nonce = String::new();
        assert!(client.resume_session(snap).is_err());

        let mut snap = test_snapshot();
        snap.our_nonce = String::new();
        assert!(client.resume_session(snap).is_err());
    }

    #[test]
    fn test_auth_layer_rejection_classifier() {
        // 401/403 = auth middleware rejection, always pre-dispatch.
        assert!(WorkerStorageClient::is_auth_layer_rejection(401, ""));
        assert!(WorkerStorageClient::is_auth_layer_rejection(
            401,
            r#"{"status":"error","code":"ERR_SESSION_NOT_FOUND","description":"No authenticated session found"}"#
        ));
        assert!(WorkerStorageClient::is_auth_layer_rejection(403, ""));

        // 500 carrying process_auth Display strings = pre-dispatch too.
        assert!(WorkerStorageClient::is_auth_layer_rejection(
            500,
            "Invalid authentication: Invalid message signature"
        ));
        assert!(WorkerStorageClient::is_auth_layer_rejection(
            500,
            "Session not found: 02abc"
        ));

        // Handler-side / other failures must NOT be retried.
        assert!(!WorkerStorageClient::is_auth_layer_rejection(
            500,
            "D1_ERROR: database is locked"
        ));
        assert!(!WorkerStorageClient::is_auth_layer_rejection(400, "bad request"));
        assert!(!WorkerStorageClient::is_auth_layer_rejection(200, "ok"));
        assert!(!WorkerStorageClient::is_auth_layer_rejection(404, "not found"));
    }
}
