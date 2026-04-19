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
use serde_json::Value;

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
#[allow(dead_code)]
struct PeerSessionState {
    /// Our session nonce (base64). Retained for session re-establishment.
    our_nonce: String,
    /// Server's session nonce (base64) — stored as peer_nonce.
    peer_nonce: String,
    /// Server's identity key.
    server_identity_key: PublicKey,
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
            AuthCloudflareError::InvalidAuthentication(
                "InitialResponse not signed".into(),
            )
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

        // Store session
        self.session = Some(PeerSessionState {
            our_nonce: session_nonce,
            peer_nonce: server_nonce,
            server_identity_key: response_msg.identity_key,
        });

        Ok(())
    }

    /// Ensures we have an authenticated session, performing handshake if needed.
    async fn ensure_session(&mut self) -> Result<()> {
        if self.session.is_none() {
            self.perform_handshake().await?;
        }
        Ok(())
    }

    /// Makes an authenticated JSON-RPC call to the storage server.
    ///
    /// 1. Ensures we have a BRC-103/104 session
    /// 2. Builds JSON-RPC request
    /// 3. Wraps in HttpRequest payload for signing
    /// 4. Signs with BRC-42 key derivation
    /// 5. Sends via `worker::Fetch` with BRC-104 auth headers
    /// 6. Parses response and extracts result
    pub async fn rpc_call<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T> {
        self.ensure_session().await?;

        // Build JSON-RPC request
        let id = self.next_id;
        self.next_id += 1;
        let rpc_req = JsonRpcRequest::new(id, method, params);
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
            headers: vec![(
                "content-type".to_string(),
                "application/json".to_string(),
            )],
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
        let session = self.session.as_ref().unwrap();
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
            (
                headers::IDENTITY_KEY.to_string(),
                msg.identity_key.to_hex(),
            ),
            (headers::MESSAGE_TYPE.to_string(), "general".to_string()),
            (
                headers::REQUEST_ID.to_string(),
                to_base64(&request_id),
            ),
            (
                "content-type".to_string(),
                "application/json".to_string(),
            ),
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
        self.rpc_call(
            "findOrInsertUser",
            vec![serde_json::json!(identity_key)],
        )
        .await
    }

    /// Calls `internalizeAction` to accept an incoming transaction.
    ///
    /// This is the key method for payment processing — it tells the storage
    /// server to record the transaction and credit the outputs to the wallet.
    pub async fn internalize_action(
        &mut self,
        auth: Value,
        args: Value,
    ) -> Result<Value> {
        self.rpc_call("internalizeAction", vec![auth, args]).await
    }

    /// Calls `listOutputs` to get wallet outputs.
    ///
    /// Returns an array of output objects with `satoshis`, `outputIndex`, etc.
    pub async fn list_outputs(
        &mut self,
        auth: Value,
        args: Value,
    ) -> Result<Value> {
        self.rpc_call("listOutputs", vec![auth, args]).await
    }

    /// Calls `createAction` to create an outgoing transaction.
    ///
    /// Returns a `StorageCreateActionResult` with the unsigned transaction
    /// template, input details (for signing), output details, and a reference.
    /// The caller must sign the inputs locally and then call `process_action`.
    pub async fn create_action(
        &mut self,
        auth: Value,
        args: Value,
    ) -> Result<Value> {
        self.rpc_call("createAction", vec![auth, args]).await
    }

    /// Calls `processAction` to process a signed transaction.
    ///
    /// After signing the template from `create_action`, call this with the
    /// signed transaction bytes and reference to broadcast and get final BEEF.
    pub async fn process_action(
        &mut self,
        auth: Value,
        args: Value,
    ) -> Result<Value> {
        self.rpc_call("processAction", vec![auth, args]).await
    }

    /// Calls `relinquishOutput` to remove an output from basket tracking.
    ///
    /// After sending funds to an external party (e.g. refunds), call this
    /// so the wallet stops treating the sent output as its own spendable UTXO.
    ///
    /// `args` should contain `{"basket": "<name>", "output": "<txid>.<vout>"}`.
    pub async fn relinquish_output(
        &mut self,
        auth: Value,
        args: Value,
    ) -> Result<Value> {
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
}
