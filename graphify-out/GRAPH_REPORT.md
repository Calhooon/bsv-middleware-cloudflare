# Graph Report - bsv-middleware-cloudflare-public  (2026-05-13)

## Corpus Check
- 29 files · ~30,819 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 504 nodes · 671 edges · 27 communities (23 shown, 4 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 26 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `bdb484fd`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]

## God Nodes (most connected - your core abstractions)
1. `WorkerStorageClient` - 16 edges
2. `Middleware - BSV Authentication and Payment Processing` - 15 edges
3. `bsv-middleware-cloudflare/src` - 14 edges
4. `KvPaymentStorage` - 12 edges
5. `Transport Module` - 12 edges
6. `parse_multipart()` - 11 edges
7. `add_cors_headers()` - 11 edges
8. `KvSessionStorage` - 11 edges
9. `bsv-middleware-cloudflare/src/client` - 11 edges
10. `process_auth()` - 10 edges

## Surprising Connections (you probably didn't know these)
- `fetch()` --calls--> `init_panic_hook()`  [INFERRED]
  examples/basic_server.rs → src/lib.rs
- `fetch()` --calls--> `add_cors_headers()`  [INFERRED]
  examples/basic_server.rs → src/middleware/auth.rs
- `fetch()` --calls--> `sign_json_response()`  [INFERRED]
  examples/basic_server.rs → src/middleware/auth.rs
- `handle_protected()` --calls--> `sign_json_response()`  [INFERRED]
  examples/basic_server.rs → src/middleware/auth.rs
- `handle_paid()` --calls--> `sign_json_response()`  [INFERRED]
  examples/basic_server.rs → src/middleware/auth.rs

## Communities (27 total, 4 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.1
Nodes (35): fetch(), handle_paid(), handle_protected(), add_cors_headers(), AuthMiddlewareOptions, AuthResult, AuthSession, filter_signable_headers() (+27 more)

### Community 1 - "Community 1"
Cohesion: 0.04
Nodes (45): Adding Payment Verification, Architecture, Authentication with Response Signing, BRC-103/104, BRC-104 (HTTP Headers), BRC-29 (Direct Payment), BRC Standards Implementation, bsv-middleware-cloudflare/src (+37 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (6): AuthCloudflareError, test_error_json_format(), test_handler_layer_error_uses_description(), test_malformed_payment_json_format(), test_payment_required_json_format(), test_server_misconfigured_json_format()

### Community 3 - "Community 3"
Cohesion: 0.08
Nodes (20): process_auth(), build_request_payload(), CloudflareTransport, extract_signable_headers(), HttpRequestData, HttpResponseData, test_message_to_headers_excludes_none_fields(), test_message_to_headers_general() (+12 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (35): AuthContext, code:rust (pub use auth::{process_auth, sign_json_response, sign_respon), code:json ({), code:rust (pub struct AuthContext {), code:rust (pub struct PaymentContext {), code:rust (pub struct AuthMiddlewareOptions {), code:rust (pub enum AuthResult {), code:rust (#[derive(Debug, Clone)]) (+27 more)

### Community 5 - "Community 5"
Cohesion: 0.06
Nodes (35): add_cors_to_response, add_cors_to_response_with_config, Basic Preflight Handling, code:rust (pub use cors::{cors_headers, handle_cors_preflight, CorsConf), code:rust (let config = CorsConfig {), code:rust (pub fn add_cors_to_response(response: Response) -> Response), code:rust (let response = Response::ok("Success")?;), code:rust (pub fn add_cors_to_response_with_config(response: Response, ) (+27 more)

### Community 6 - "Community 6"
Cohesion: 0.06
Nodes (34): `auth_headers` Module, Building Response Headers, Checking for Authenticated Requests, `CloudflareTransport`, code:rust (pub struct HttpRequestData {), code:rust (pub struct HttpResponseData {), code:block3 ([request_id: 32 bytes]), code:block4 ([request_id: 32 bytes]) (+26 more)

### Community 7 - "Community 7"
Cohesion: 0.11
Nodes (14): add_payment_headers(), payment_failed_response(), PaymentMiddlewareOptions, PaymentMiddlewareOptions<F>, PaymentResult, process_payment(), test_create_and_verify_nonce(), test_error_response_matches_express_format() (+6 more)

### Community 8 - "Community 8"
Cohesion: 0.08
Nodes (24): Architecture, Authenticated RPC (`rpc_call`), BRC-103/104 Handshake (`perform_handshake`), BRC-104 Headers, bsv-middleware-cloudflare/src/client, code:block1 (client/), code:rust (use bsv_middleware_cloudflare::client::WorkerStorageClient;), code:rust (// Initialize connection and get storage settings) (+16 more)

### Community 9 - "Community 9"
Cohesion: 0.19
Nodes (19): issue_refund(), RefundError, RefundInfo, brc29_e2e_client_pays_server_then_server_spends(), brc29_e2e_server_change_create_and_spend(), brc29_other_round_trip_client_server(), brc29_self_change_create_spend_roundtrip(), build_p2pkh_unlocking_script() (+11 more)

### Community 10 - "Community 10"
Cohesion: 0.18
Nodes (4): PeerSessionState, test_create_client(), test_url_trailing_slash_stripped(), WorkerStorageClient

### Community 11 - "Community 11"
Cohesion: 0.09
Nodes (21): code:rust (pub struct KvSessionStorage {), code:rust (pub struct KvPaymentStorage {), code:rust (pub struct StoredSession {), code:rust (pub struct StoredPayment {), code:rust (use worker::kv::KvStore;), code:rust (use worker::kv::KvStore;), Data Types, Error Handling (+13 more)

### Community 12 - "Community 12"
Cohesion: 0.15
Nodes (13): extract_boundary(), extract_part_content_type(), extract_part_name(), find_bytes(), MultipartPart, parse_multipart(), prepare_multipart_payment(), test_parse_multipart_binary_body() (+5 more)

### Community 13 - "Community 13"
Cohesion: 0.15
Nodes (9): test_auth_context_authenticated(), test_auth_context_unauthenticated(), AuthContext, BsvPayment, current_time_ms(), ErrorResponse, PaymentContext, StoredPayment (+1 more)

### Community 16 - "Community 16"
Cohesion: 0.17
Nodes (11): bsv-middleware-cloudflare, Cloudflare bindings, code:rust (use bsv_middleware_cloudflare::{), code:toml (# wrangler.toml), Consumers, Features, License, Parity with Express middleware (+3 more)

### Community 17 - "Community 17"
Cohesion: 0.2
Nodes (9): bsv-middleware-cloudflare, Build, code:bash (cargo check --target wasm32-unknown-unknown), code:block2 (src/), Error codes (Express parity), Headers (BRC-104 + BRC-29), Key patterns, Layout (+1 more)

### Community 18 - "Community 18"
Cohesion: 0.39
Nodes (7): add_cors_to_response(), add_cors_to_response_with_config(), cors_headers(), cors_headers_with_config(), CorsConfig, handle_cors_preflight(), handle_cors_preflight_with_config()

### Community 20 - "Community 20"
Cohesion: 0.33
Nodes (3): JsonRpcError, JsonRpcRequest, JsonRpcResponse

## Knowledge Gaps
- **150 isolated node(s):** `PaymentContext`, `BsvPayment`, `StoredPayment`, `WorkerEnv`, `MultipartPart` (+145 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `add_cors_headers()` connect `Community 0` to `Community 3`, `Community 7`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Why does `AuthCloudflareError` connect `Community 2` to `Community 0`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **What connects `PaymentContext`, `BsvPayment`, `StoredPayment` to the rest of the system?**
  _150 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.04 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._