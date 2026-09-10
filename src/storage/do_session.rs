//! The Durable Object session backend (bsv-low W-D, 2026-09-10).
//!
//! # Why
//!
//! The KV backend does a KV read (`get_session`) and a KV read + WRITE
//! (`try_consume_nonce`) on EVERY authenticated request: `auth_ms` p50 404 ms /
//! p90 528 ms measured on the LOW relay in production. KV is eventually
//! consistent and slow to write; the replay guard is a put-if-absent that KV
//! cannot even make atomic.
//!
//! # What
//!
//! One Durable Object per SESSION NONCE (`AuthSessionStore`, keyed by
//! `id_from_name(session_nonce)`): the session record and the consumed
//! per-request nonces live in ONE strongly consistent, in-memory object with
//! transactional storage behind it. The two hot-path questions the middleware
//! asks per request — "is this session live?" and "has this request nonce been
//! seen?" — are answered by the SAME object, so the replay guard is an atomic
//! put-if-absent and a request costs two same-colo DO round trips (~ms) and no
//! KV write. Cloudflare KV stays the COLD path: the identity → session index
//! (the handshake writes it; the no-session-nonce lookup reads it), the cold
//! copy a DO miss falls back to (a session minted under the KV backend before
//! a rollout is migrated into its object on first sight), and the PAYMENT
//! nonce scope (`PAYMENT_NONCE_SCOPE` is global, not per session — it stays
//! where a global put-if-absent lives).
//!
//! The reference (`auth-express-middleware`) keeps sessions in process memory;
//! a Durable Object is that memory's durable, single-writer equivalent. The
//! wire (BRC-103/104) is untouched; only the server's storage moved.
//!
//! # Adopting it
//!
//! ```toml
//! [[durable_objects.bindings]]
//! name = "AUTH_SESSION_STORE"
//! class_name = "AuthSessionStore"
//! [[migrations]]
//! tag = "vN-auth-session-store"
//! new_classes = ["AuthSessionStore"]
//! ```
//!
//! ```rust,ignore
//! pub use bsv_middleware_cloudflare::AuthSessionStore; // exports the DO class from your worker
//! let result = process_auth_do(req, &env, &options, "AUTH_SESSION_STORE").await?;
//! ```
//!
//! The pure state machine (`SessionCell`) and the scope routing are unit-pinned;
//! the object and the client are thin shells over them.

use crate::error::{AuthCloudflareError, Result};
use crate::storage::kv_session::KvSessionStorage;
use crate::storage::session_storage::SessionStorage;
use crate::types::{current_time_ms, StoredSession};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use worker::*;

/// A consumed nonce outlives its request by at least this long when the
/// caller passes no TTL (the KV backend's floor is the same 60 s).
pub const NONCE_MIN_TTL_SECONDS: u64 = 60;

/// The pure state one `AuthSessionStore` holds for ONE session nonce.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SessionCell {
    /// The session record, once a handshake saved it.
    pub session: Option<StoredSession>,
    /// The session's expiry (ms since the epoch); nothing is answered past it.
    pub expires_at_ms: u64,
    /// Consumed per-request nonces → their expiry (ms since the epoch).
    pub consumed: HashMap<String, u64>,
}

impl SessionCell {
    /// Whether the cell holds nothing live at `now_ms` (absent or expired).
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.session.is_none() || now_ms >= self.expires_at_ms
    }

    /// The live session, or `None` when absent or expired.
    pub fn get(&self, now_ms: u64) -> Option<&StoredSession> {
        if self.is_expired(now_ms) {
            None
        } else {
            self.session.as_ref()
        }
    }

    /// Save (or update) the session and extend its life by `ttl_seconds` from
    /// `now_ms`. The consumed set is KEPT: an update is the same session.
    pub fn save(&mut self, session: StoredSession, ttl_seconds: u64, now_ms: u64) {
        self.session = Some(session);
        self.expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
        self.prune(now_ms);
    }

    /// Atomic put-if-absent of a per-request nonce: `true` the first time,
    /// `false` on a replay. A consumed nonce is remembered for `ttl_seconds`
    /// (floored at `NONCE_MIN_TTL_SECONDS`); expired ones are pruned first, so
    /// a nonce whose memory lapsed is fresh again — exactly the KV backend's
    /// TTL semantics, without the write.
    pub fn consume(&mut self, nonce: &str, ttl_seconds: Option<u64>, now_ms: u64) -> bool {
        self.prune(now_ms);
        if self.consumed.contains_key(nonce) {
            return false;
        }
        let ttl = ttl_seconds
            .unwrap_or(NONCE_MIN_TTL_SECONDS)
            .max(NONCE_MIN_TTL_SECONDS);
        self.consumed.insert(
            nonce.to_string(),
            now_ms.saturating_add(ttl.saturating_mul(1000)),
        );
        true
    }

    /// Forget a consumed nonce (the payment path's release on a failed
    /// verification; symmetric with the KV backend).
    pub fn release(&mut self, nonce: &str) {
        self.consumed.remove(nonce);
    }

    /// Drop every consumed nonce whose memory lapsed.
    pub fn prune(&mut self, now_ms: u64) {
        self.consumed.retain(|_, exp| *exp > now_ms);
    }

    /// The hot path in one step: the live session (if any) AND the
    /// put-if-absent of the request nonce. An absent or expired cell consumes
    /// NOTHING (`(None, false)`): a nonce is only ever burnt against a live
    /// session. Returns whether the nonce was fresh.
    pub fn get_and_consume(
        &mut self,
        nonce: &str,
        ttl_seconds: Option<u64>,
        now_ms: u64,
    ) -> (Option<StoredSession>, bool) {
        if self.is_expired(now_ms) {
            return (None, false);
        }
        let fresh = self.consume(nonce, ttl_seconds, now_ms);
        (self.session.clone(), fresh)
    }
}

/// Where a nonce scope's put-if-absent lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRoute {
    /// A session nonce: its own Durable Object.
    Do,
    /// A global scope (the BRC-29 payment prefix): Cloudflare KV.
    Kv,
}

/// The auth middleware consumes request nonces under the SESSION nonce as the
/// scope; the payment middleware under the global `PAYMENT_NONCE_SCOPE`. Only
/// the former has an object to live in.
pub fn route_scope(scope: &str) -> ScopeRoute {
    if scope == crate::middleware::payment::PAYMENT_NONCE_SCOPE {
        ScopeRoute::Kv
    } else {
        ScopeRoute::Do
    }
}

/// `PUT /session` body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SaveBody {
    pub session: StoredSession,
    pub ttl_seconds: u64,
}

/// `POST /consume` and `POST /release` body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NonceBody {
    pub nonce: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// `POST /consume` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsumeAnswer {
    pub fresh: bool,
}

/// `POST /session-consume` answer: the hot path's two questions in one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionConsumeAnswer {
    pub session: Option<StoredSession>,
    pub fresh: bool,
}

const CELL_KEY: &str = "cell";
const DO_ORIGIN: &str = "https://auth-session-store";

/// The Durable Object: one per session nonce. Re-export it from the worker
/// crate that binds it (`pub use bsv_middleware_cloudflare::AuthSessionStore;`).
#[durable_object]
pub struct AuthSessionStore {
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl AuthSessionStore {
    async fn load(&self) -> SessionCell {
        self.state
            .storage()
            .get::<SessionCell>(CELL_KEY)
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    async fn store(&self, cell: &SessionCell) -> Result<()> {
        self.state
            .storage()
            .put(CELL_KEY, cell)
            .await
            .map_err(|e| AuthCloudflareError::KvError(format!("auth-session-store put: {e}")))
    }

    /// Garbage collection: an alarm at the session's expiry deletes the object's
    /// storage, so an abandoned session costs nothing after its TTL.
    async fn arm_gc(&self, expires_at_ms: u64) {
        let _ = self
            .state
            .storage()
            .set_alarm(std::time::Duration::from_millis(
                expires_at_ms
                    .saturating_sub(Date::now().as_millis())
                    .max(1_000),
            ))
            .await;
    }
}

fn json_status<T: Serialize>(value: &T, status: u16) -> worker::Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

impl DurableObject for AuthSessionStore {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let now = Date::now().as_millis();
        let path = req.path();
        let mut cell = self.load().await;
        match (req.method(), path.as_str()) {
            (Method::Get, "/session") => json_status(&cell.get(now).cloned(), 200),
            (Method::Put, "/session") => {
                let body: SaveBody = req.json().await?;
                cell.save(body.session, body.ttl_seconds, now);
                self.store(&cell)
                    .await
                    .map_err(|e| worker::Error::from(e.to_string()))?;
                self.arm_gc(cell.expires_at_ms).await;
                Ok(Response::empty()?.with_status(204))
            }
            (Method::Post, "/session-consume") => {
                let body: NonceBody = req.json().await?;
                let (session, fresh) = cell.get_and_consume(&body.nonce, body.ttl_seconds, now);
                if fresh {
                    self.store(&cell)
                        .await
                        .map_err(|e| worker::Error::from(e.to_string()))?;
                }
                json_status(&SessionConsumeAnswer { session, fresh }, 200)
            }
            (Method::Post, "/consume") => {
                let body: NonceBody = req.json().await?;
                let fresh = cell.consume(&body.nonce, body.ttl_seconds, now);
                if fresh {
                    self.store(&cell)
                        .await
                        .map_err(|e| worker::Error::from(e.to_string()))?;
                }
                json_status(&ConsumeAnswer { fresh }, 200)
            }
            (Method::Post, "/release") => {
                let body: NonceBody = req.json().await?;
                cell.release(&body.nonce);
                self.store(&cell)
                    .await
                    .map_err(|e| worker::Error::from(e.to_string()))?;
                Ok(Response::empty()?.with_status(204))
            }
            (Method::Delete, "/session") => {
                let _ = self.state.storage().delete_all().await;
                Ok(Response::empty()?.with_status(204))
            }
            _ => Ok(Response::error("not found", 404)?),
        }
    }

    async fn alarm(&self) -> worker::Result<Response> {
        let cell = self.load().await;
        if cell.is_expired(Date::now().as_millis()) {
            let _ = self.state.storage().delete_all().await;
        } else {
            self.arm_gc(cell.expires_at_ms).await;
        }
        Ok(Response::empty()?.with_status(204))
    }
}

/// The client side: a [`SessionStorage`] over the Durable Objects, with the KV
/// backend as the cold path (the identity index, the migration of a KV-minted
/// session, the payment scope).
pub struct DoSessionStorage {
    namespace: ObjectNamespace,
    kv: KvSessionStorage,
    session_ttl_seconds: u64,
}

impl DoSessionStorage {
    pub fn new(namespace: ObjectNamespace, kv: KvSessionStorage, session_ttl_seconds: u64) -> Self {
        Self {
            namespace,
            kv,
            session_ttl_seconds,
        }
    }

    /// Both bindings from the worker's environment: the Durable Object
    /// namespace `do_binding` and the KV namespace `AUTH_SESSIONS`.
    pub fn from_env(env: &Env, do_binding: &str, session_ttl_seconds: u64) -> Result<Self> {
        let namespace = env.durable_object(do_binding).map_err(|e| {
            AuthCloudflareError::ConfigError(format!("{do_binding} Durable Object not bound: {e}"))
        })?;
        let kv = env.kv("AUTH_SESSIONS").map_err(|e| {
            AuthCloudflareError::ConfigError(format!("AUTH_SESSIONS KV not bound: {e}"))
        })?;
        Ok(Self::new(
            namespace,
            KvSessionStorage::new(kv, "auth", session_ttl_seconds),
            session_ttl_seconds,
        ))
    }

    async fn call(
        &self,
        session_nonce: &str,
        method: Method,
        path: &str,
        body: Option<String>,
    ) -> Result<Response> {
        let stub = self
            .namespace
            .id_from_name(session_nonce)
            .and_then(|id| id.get_stub())
            .map_err(|e| AuthCloudflareError::KvError(format!("auth-session-store stub: {e}")))?;
        let mut init = RequestInit::new();
        init.with_method(method);
        if let Some(b) = body {
            let headers = Headers::new();
            headers
                .set("content-type", "application/json")
                .map_err(|e| AuthCloudflareError::KvError(e.to_string()))?;
            init.with_headers(headers);
            init.with_body(Some(wasm_bindgen::JsValue::from_str(&b)));
        }
        let req = Request::new_with_init(&format!("{DO_ORIGIN}{path}"), &init).map_err(|e| {
            AuthCloudflareError::KvError(format!("auth-session-store request: {e}"))
        })?;
        stub.fetch_with_request(req)
            .await
            .map_err(|e| AuthCloudflareError::KvError(format!("auth-session-store fetch: {e}")))
    }

    async fn do_get(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        let mut resp = self
            .call(session_nonce, Method::Get, "/session", None)
            .await?;
        if resp.status_code() != 200 {
            return Err(AuthCloudflareError::KvError(format!(
                "auth-session-store GET answered {}",
                resp.status_code()
            )));
        }
        resp.json::<Option<StoredSession>>()
            .await
            .map_err(|e| AuthCloudflareError::KvError(format!("auth-session-store GET body: {e}")))
    }

    async fn do_put(&self, session: &StoredSession) -> Result<()> {
        let body = serde_json::to_string(&SaveBody {
            session: session.clone(),
            ttl_seconds: self.session_ttl_seconds,
        })?;
        let resp = self
            .call(&session.session_nonce, Method::Put, "/session", Some(body))
            .await?;
        if resp.status_code() != 204 {
            return Err(AuthCloudflareError::KvError(format!(
                "auth-session-store PUT answered {}",
                resp.status_code()
            )));
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStorage for DoSessionStorage {
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>> {
        if let Some(s) = self.do_get(session_nonce).await? {
            return Ok(Some(s));
        }
        // The cold path: a session minted under the KV backend (before a
        // rollout, or by a sibling deployment still on KV). Migrate it into its
        // object so the next request is hot; a failed migration is not a
        // failed read.
        match self.kv.get_session(session_nonce).await? {
            Some(s) => {
                if let Err(e) = self.do_put(&s).await {
                    console_warn!(
                        "auth-session-store: migrating a KV session failed (non-fatal): {e:?}"
                    );
                }
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>> {
        // The identity → session index lives in KV (written by save_session);
        // the object holds the fresher record.
        match self.kv.get_session_by_identity(identity_key_hex).await? {
            Some(cold) => Ok(self.do_get(&cold.session_nonce).await?.or(Some(cold))),
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &StoredSession) -> Result<()> {
        self.do_put(session).await?;
        // The handshake's ONE cold write: the identity index + the cold copy.
        self.kv.save_session(session).await
    }

    async fn update_session(&self, session: &StoredSession) -> Result<()> {
        // The per-request liveness touch never reaches KV.
        self.do_put(session).await
    }

    async fn try_consume_nonce(
        &self,
        scope: &str,
        nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<bool> {
        match route_scope(scope) {
            ScopeRoute::Kv => self.kv.try_consume_nonce(scope, nonce, ttl_seconds).await,
            ScopeRoute::Do => {
                let body = serde_json::to_string(&NonceBody {
                    nonce: nonce.to_string(),
                    ttl_seconds,
                })?;
                let mut resp = self
                    .call(scope, Method::Post, "/consume", Some(body))
                    .await?;
                if resp.status_code() != 200 {
                    return Err(AuthCloudflareError::KvError(format!(
                        "auth-session-store consume answered {}",
                        resp.status_code()
                    )));
                }
                let answer: ConsumeAnswer = resp.json().await.map_err(|e| {
                    AuthCloudflareError::KvError(format!("auth-session-store consume body: {e}"))
                })?;
                Ok(answer.fresh)
            }
        }
    }

    async fn get_session_and_consume(
        &self,
        session_nonce: &str,
        request_nonce: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<Option<(Option<StoredSession>, bool)>> {
        let body = serde_json::to_string(&NonceBody {
            nonce: request_nonce.to_string(),
            ttl_seconds,
        })?;
        let mut resp = self
            .call(session_nonce, Method::Post, "/session-consume", Some(body))
            .await?;
        if resp.status_code() != 200 {
            return Err(AuthCloudflareError::KvError(format!(
                "auth-session-store session-consume answered {}",
                resp.status_code()
            )));
        }
        let answer: SessionConsumeAnswer = resp.json().await.map_err(|e| {
            AuthCloudflareError::KvError(format!("auth-session-store session-consume body: {e}"))
        })?;
        if answer.session.is_some() {
            return Ok(Some((answer.session, answer.fresh)));
        }
        // The cold path (a KV-minted session): migrate it, then consume
        // against its object — two more round trips, once per such session.
        match self.kv.get_session(session_nonce).await? {
            Some(s) => {
                if let Err(e) = self.do_put(&s).await {
                    console_warn!(
                        "auth-session-store: migrating a KV session failed (non-fatal): {e:?}"
                    );
                    return Ok(None); // unsupported for this call: the two-step path decides
                }
                let fresh = self
                    .try_consume_nonce(session_nonce, request_nonce, ttl_seconds)
                    .await?;
                Ok(Some((Some(s), fresh)))
            }
            None => Ok(Some((None, false))),
        }
    }

    async fn release_nonce(&self, scope: &str, nonce: &str) -> Result<()> {
        match route_scope(scope) {
            ScopeRoute::Kv => self.kv.release_nonce(scope, nonce).await,
            ScopeRoute::Do => {
                let body = serde_json::to_string(&NonceBody {
                    nonce: nonce.to_string(),
                    ttl_seconds: None,
                })?;
                let resp = self
                    .call(scope, Method::Post, "/release", Some(body))
                    .await?;
                if resp.status_code() != 204 {
                    return Err(AuthCloudflareError::KvError(format!(
                        "auth-session-store release answered {}",
                        resp.status_code()
                    )));
                }
                Ok(())
            }
        }
    }
}

/// `now` for callers outside a Worker request (tests); the object itself reads
/// the runtime clock.
#[allow(dead_code)]
fn now_ms() -> u64 {
    current_time_ms()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session built by hand: `StoredSession::new` reads the JS clock, which
    /// does not exist under native `cargo test`.
    fn session(nonce: &str) -> StoredSession {
        StoredSession {
            session_nonce: nonce.to_string(),
            peer_identity_key: "02".repeat(33),
            peer_nonce: None,
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 1,
            last_update: 1,
        }
    }

    #[test]
    fn a_cell_answers_nothing_when_absent_or_expired_and_the_session_inside_its_life() {
        let mut c = SessionCell::default();
        assert!(c.get(1_000).is_none());
        c.save(session("n1"), 3_600, 1_000);
        assert_eq!(c.expires_at_ms, 1_000 + 3_600_000);
        assert_eq!(c.get(1_000).map(|s| s.session_nonce.as_str()), Some("n1"));
        assert_eq!(
            c.get(1_000 + 3_600_000 - 1)
                .map(|s| s.session_nonce.as_str()),
            Some("n1")
        );
        assert!(
            c.get(1_000 + 3_600_000).is_none(),
            "expired at exactly the deadline"
        );
        assert!(c.is_expired(1_000 + 3_600_000));
    }

    #[test]
    fn consume_is_a_put_if_absent_with_the_kv_backend_s_ttl_semantics() {
        let mut c = SessionCell::default();
        c.save(session("n1"), 3_600, 0);
        assert!(c.consume("r1", Some(3_600), 10));
        assert!(!c.consume("r1", Some(3_600), 11), "a replay is refused");
        assert!(c.consume("r2", None, 12));
        // The floor: a consumed nonce is remembered for at least 60 s.
        assert!(!c.consume("r2", None, 12 + 59_999));
        assert!(
            c.consume("r2", None, 12 + 60_000),
            "its memory lapsed: fresh again"
        );
        // The caller's TTL, when longer, is honoured.
        assert!(!c.consume("r1", Some(3_600), 10 + 3_599_999));
        assert!(c.consume("r1", Some(3_600), 10 + 3_600_000));
    }

    #[test]
    fn release_forgets_a_nonce_and_an_update_keeps_the_consumed_set() {
        let mut c = SessionCell::default();
        c.save(session("n1"), 3_600, 0);
        assert!(c.consume("r1", Some(3_600), 1));
        c.release("r1");
        assert!(c.consume("r1", Some(3_600), 2), "released: fresh again");
        let mut touched = session("n1");
        touched.last_update = 5_000;
        c.save(touched, 3_600, 5_000);
        assert_eq!(c.session.as_ref().map(|s| s.last_update), Some(5_000));
        assert!(
            !c.consume("r1", Some(3_600), 6),
            "the update kept the consumed set"
        );
        assert_eq!(
            c.expires_at_ms,
            5_000 + 3_600_000,
            "the update extended the life"
        );
    }

    /// The one-round-trip hot path: a live session answers (Some, fresh) then
    /// (Some, replayed); an absent or expired cell answers (None, false) and
    /// burns NOTHING.
    #[test]
    fn get_and_consume_answers_both_questions_and_burns_nothing_on_a_dead_cell() {
        let mut c = SessionCell::default();
        assert_eq!(c.get_and_consume("r1", Some(60), 5), (None, false));
        assert!(c.consumed.is_empty(), "nothing burnt on an absent cell");
        c.save(session("n1"), 3_600, 0);
        let (s, fresh) = c.get_and_consume("r1", Some(60), 5);
        assert_eq!(s.as_ref().map(|s| s.session_nonce.as_str()), Some("n1"));
        assert!(fresh);
        let (s, fresh) = c.get_and_consume("r1", Some(60), 6);
        assert!(s.is_some());
        assert!(
            !fresh,
            "the replay is refused with the session still served"
        );
        let (s, fresh) = c.get_and_consume("r2", Some(60), 3_600_000);
        assert_eq!(
            (s, fresh),
            (None, false),
            "expired: nothing served, nothing burnt"
        );
        assert!(!c.consumed.contains_key("r2"));
        let answer = SessionConsumeAnswer {
            session: Some(session("n1")),
            fresh: true,
        };
        let back: SessionConsumeAnswer =
            serde_json::from_str(&serde_json::to_string(&answer).unwrap()).unwrap();
        assert_eq!(back, answer);
    }

    #[test]
    fn only_the_payment_scope_stays_in_kv() {
        assert_eq!(
            route_scope(crate::middleware::payment::PAYMENT_NONCE_SCOPE),
            ScopeRoute::Kv
        );
        assert_eq!(route_scope(&"ab".repeat(24)), ScopeRoute::Do);
        assert_eq!(route_scope("anything-else"), ScopeRoute::Do);
    }

    #[test]
    fn the_wire_bodies_round_trip_and_the_cell_persists_whole() {
        let save = SaveBody {
            session: session("n1"),
            ttl_seconds: 3_600,
        };
        let back: SaveBody = serde_json::from_str(&serde_json::to_string(&save).unwrap()).unwrap();
        assert_eq!(back, save);
        let nb: NonceBody = serde_json::from_str(r#"{"nonce":"r1"}"#).unwrap();
        assert_eq!(nb.ttl_seconds, None);
        let mut c = SessionCell::default();
        c.save(session("n1"), 3_600, 7);
        assert!(c.consume("r1", Some(10), 8));
        let back: SessionCell = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }
}
