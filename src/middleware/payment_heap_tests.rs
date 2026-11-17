//! The paid path's heap, from the payment header's arrival to the wallet
//! call's send, and the wallet request's bytes.
//!
//! A counting allocator (this test binary's global allocator) keeps a live
//! byte count and its peak per thread, so tests running beside a
//! measurement do not move it. Each measurement drives `decide_payment`
//! with the header (allocated before the measurement starts) and, as its
//! wallet step, what `internalize_payment` runs up to `worker::Fetch`:
//! `WorkerStorageClient::prepare_internalize`, `sign_attempt` and the body
//! handed to the fetch. The bound is a fixed floor plus a multiple of the
//! header's size: 1.25 MiB plus 4 bytes per header byte, on headers of
//! 1 KiB to 128 KiB and on the 22 vectors. A control wallet step that holds
//! the request as a `serde_json::Value` must exceed the bound at 8 KiB and
//! above, so the measurement is known to register the request's size.

use super::*;
use crate::client::wire::RpcPayload;
use crate::client::{
    ClientSessionSnapshot, JsonRpcRequest, WorkerStorageClient, CLIENT_SESSION_SNAPSHOT_VERSION,
};
use bsv_middleware_core::store::conformance::block_on;
use bsv_middleware_core::MemoryStore;
use bsv_sdk::auth::transports::HttpRequest;
use bsv_sdk::auth::types::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
use bsv_sdk::primitives::{from_hex, to_base64, PublicKey};
use bsv_sdk::script::LockingScript;
use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_sdk::wallet::{Counterparty, CreateSignatureArgs, Protocol, SecurityLevel};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// ── the counting allocator ──────────────────────────────────────────────

struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn grow(n: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + n as isize;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now)
            }
        });
    });
}

fn shrink(n: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - n as isize));
}

// SAFETY: every call is forwarded to `System` unchanged; the counters are
// const-initialized thread locals without destructors, so counting
// allocates nothing.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        shrink(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                shrink(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The peak this thread's heap reaches over its level when `f` starts.
fn peak_of<R>(f: impl FnOnce() -> R) -> usize {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    drop(f());
    (PEAK.with(Cell::get) - base).max(0) as usize
}

// ── the bound ───────────────────────────────────────────────────────────

/// The fixed floor: the keys, the wallet, the session, the nonce check.
const FLOOR: usize = 5 << 18;
/// Heap bytes per header byte over the floor.
const PER_HEADER_BYTE: usize = 4;

fn bound(header_len: usize) -> usize {
    FLOOR + PER_HEADER_BYTE * header_len
}

// ── payments ────────────────────────────────────────────────────────────

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
/// 2·G, the paying client's identity.
const CLIENT_IDENTITY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SUFFIX: &str = "c3VmZml4LXN1ZmZpeA==";
const PRICE: u64 = 1000;

fn issued_prefix() -> String {
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()));
    block_on(create_nonce(&wallet, None, ORIGINATOR)).unwrap()
}

/// Bytes with every value from 0 to 255 at a realistic spread.
fn filler(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 56) as u8
        })
        .collect()
}

/// An Atomic BEEF whose output 0 pays the price to the server's derived
/// key, with a data output of `data` bytes after it.
fn payment(prefix: &str, data: usize) -> Vec<u8> {
    let script = from_hex(
        &bsv_middleware_core::expected_locking_script(SERVER_KEY, CLIENT_IDENTITY, prefix, SUFFIX)
            .unwrap(),
    )
    .unwrap();
    let mut parent = Transaction::new();
    parent
        .add_output(TransactionOutput::new(
            100_000,
            LockingScript::from_binary(&script).unwrap(),
        ))
        .unwrap();
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::with_source_transaction(parent, 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(
        PRICE,
        LockingScript::from_binary(&script).unwrap(),
    ))
    .unwrap();
    let mut data_script = vec![0x00, 0x6a, 0x4e];
    data_script.extend_from_slice(&(data as u32).to_le_bytes());
    data_script.extend_from_slice(&filler(data, data as u64));
    tx.add_output(TransactionOutput::new(
        0,
        LockingScript::from_binary(&data_script).unwrap(),
    ))
    .unwrap();
    tx.to_atomic_beef(true).unwrap()
}

fn header(prefix: &str, tx: &[u8]) -> String {
    serde_json::json!({
        "derivationPrefix": prefix,
        "derivationSuffix": SUFFIX,
        "transaction": to_base64(tx),
    })
    .to_string()
}

/// Headers of 1 KiB to 128 KiB (each within 4 bytes under its size).
fn sized_headers(prefix: &str) -> Vec<String> {
    let mut sizes: Vec<usize> = (10..=17).map(|p| 1usize << p).collect();
    sizes.extend([1536, 3000, 12_345, 50_000, 100_000, 120_000]);
    sizes
        .into_iter()
        .map(|target| {
            // The largest header of at most `target` bytes (within 4).
            let mut data = (target * 3 / 4).saturating_sub(320);
            loop {
                let next = header(prefix, &payment(prefix, data + 1));
                if next.len() > target {
                    return header(prefix, &payment(prefix, data));
                }
                data += 1;
            }
        })
        .collect()
}

// ── the wallet step, and the same request through a Value ───────────────

fn signing_client() -> WorkerStorageClient {
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()));
    let mut client = WorkerStorageClient::new(wallet, "https://storage.example");
    client
        .resume_session(ClientSessionSnapshot {
            v: CLIENT_SESSION_SNAPSHOT_VERSION,
            our_nonce: "b3Vy".into(),
            peer_nonce: "cGVlcg==".into(),
            server_identity_key: PrivateKey::from_hex(&format!("{}2", "0".repeat(63)))
                .unwrap()
                .public_key()
                .to_hex(),
        })
        .unwrap();
    client
}

fn storage_auth() -> serde_json::Value {
    let identity = PrivateKey::from_hex(SERVER_KEY)
        .unwrap()
        .public_key()
        .to_hex();
    serde_json::json!({ "identityKey": identity, "userId": 42 })
}

/// What `internalize_payment` runs up to the fetch: the request written,
/// signed, and its body taken for the fetch.
fn wallet_step(
    labels: Option<Vec<String>>,
) -> impl FnOnce(String, String, Vec<u8>) -> std::future::Ready<Result<serde_json::Value>> {
    move |prefix, suffix, tx| {
        let mut client = signing_client();
        let args = remittance_args(&prefix, &suffix, CLIENT_IDENTITY, labels.as_ref());
        let mut payload = client
            .prepare_internalize(storage_auth(), args, tx)
            .unwrap();
        let headers = client.sign_attempt(&mut payload).unwrap();
        let body = payload.body().unwrap();
        assert!(!headers.is_empty() && body.starts_with("{\"jsonrpc\":\"2.0\""));
        std::future::ready(Ok(serde_json::json!({ "accepted": true })))
    }
}

/// The control: the same request held as a `serde_json::Value`
/// (`internalize_args` in `JsonRpcRequest`), serialized and signed, all
/// live at the fetch.
fn wallet_step_through_a_value(
    prefix: String,
    suffix: String,
    tx_bytes: Vec<u8>,
) -> std::future::Ready<Result<serde_json::Value>> {
    let args = internalize_args(&tx_bytes, &prefix, &suffix, CLIENT_IDENTITY, None);
    let params = vec![storage_auth(), args];
    let rpc_req = JsonRpcRequest::new(3, "internalizeAction", params.to_vec());
    let rpc_body = serde_json::to_vec(&rpc_req).unwrap();
    let rpc_body_str = String::from_utf8(rpc_body.clone()).unwrap();
    let http_request = HttpRequest {
        request_id: [0u8; 32],
        method: "POST".to_string(),
        path: "/".to_string(),
        search: String::new(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: rpc_body,
    };
    let mut msg = AuthMessage::new(
        MessageType::General,
        PrivateKey::from_hex(SERVER_KEY).unwrap().public_key(),
    );
    msg.payload = Some(http_request.to_payload());
    let data = msg.signing_data();
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()));
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: "k".into(),
            counterparty: Some(Counterparty::Other(
                PublicKey::from_hex(CLIENT_IDENTITY).unwrap(),
            )),
        })
        .unwrap();
    assert!(!signature.signature.is_empty() && !rpc_body_str.is_empty());
    drop((tx_bytes, params, rpc_req, http_request, msg));
    std::future::ready(Ok(serde_json::json!({ "accepted": true })))
}

fn paid_peak<W, Fut>(header: String, wallet: W) -> usize
where
    W: FnOnce(String, String, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<serde_json::Value>>,
{
    let auth = AuthContext::authenticated(CLIENT_IDENTITY.to_string());
    let store = MemoryStore::new();
    peak_of(move || {
        let decision = block_on(decide_payment(
            &auth,
            || PRICE,
            Some(header),
            SERVER_KEY,
            &store,
            wallet,
        ))
        .unwrap();
        assert!(
            matches!(decision, PaymentDecision::Verified { satoshis_paid, .. } if satoshis_paid == PRICE),
            "{decision:?}"
        );
    })
}

#[test]
fn the_paid_path_to_the_wallet_call_is_a_floor_plus_a_multiple_of_the_header() {
    let prefix = issued_prefix();
    // The slope between each header and the smallest: heap per header byte.
    let mut first: Option<(usize, usize)> = None;
    let mut worst = 0f64;
    for header in sized_headers(&prefix) {
        let len = header.len();
        assert!((1020..=131_072).contains(&len), "{len}");
        let replica = paid_peak(header.clone(), wallet_step_through_a_value);
        let peak = paid_peak(header, wallet_step(None));
        let (len0, peak0) = *first.get_or_insert((len, peak));
        if len > len0 {
            worst = worst.max((peak as f64 - peak0 as f64) / (len - len0) as f64);
        }
        eprintln!("header {len:>6} B: peak {peak:>8} B");
        assert!(
            peak <= bound(len),
            "header {len} B: peak {peak} B over {FLOOR} + {PER_HEADER_BYTE} x {len}"
        );
        if len >= 8 << 10 {
            assert!(
                replica > bound(len),
                "header {len} B: the control must exceed the bound"
            );
        }
    }
    eprintln!("per header byte above the smallest header: at most {worst:.2} B");
}

// ── the request, byte for byte ──────────────────────────────────────────

/// The signed payload of the middleware's internalize built through a
/// `serde_json::Value` (`internalize_args`, `JsonRpcRequest`): the body is
/// its tail.
fn reference_payload(tx: &[u8], prefix: &str, labels: Option<&Vec<String>>) -> Vec<u8> {
    let args = internalize_args(tx, prefix, SUFFIX, CLIENT_IDENTITY, labels);
    let body = serde_json::to_vec(&JsonRpcRequest::new(
        3,
        "internalizeAction",
        vec![storage_auth(), args],
    ))
    .unwrap();
    HttpRequest {
        request_id: [5u8; 32],
        method: "POST".to_string(),
        path: "/".to_string(),
        search: String::new(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
    }
    .to_payload()
}

fn written_payload(tx: &[u8], prefix: &str, labels: Option<&Vec<String>>) -> RpcPayload {
    let mut client = signing_client();
    for _ in 0..2 {
        // The paid path's request is the client's third: makeAvailable and
        // findOrInsertUser take ids 1 and 2.
        let _ = client.prepare_internalize(storage_auth(), serde_json::json!({}), Vec::new());
    }
    let args = remittance_args(prefix, SUFFIX, CLIENT_IDENTITY, labels);
    let mut payload = client
        .prepare_internalize(storage_auth(), args, tx.to_vec())
        .unwrap();
    payload.set_request_id(&[5u8; 32]);
    payload
}

fn vector_transactions() -> Vec<(String, Vec<u8>)> {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("../../conformance/brc29-payment-vectors.json")).unwrap();
    file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            (
                case["name"].as_str().unwrap().to_string(),
                from_hex(case["transaction"]["beef_hex"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn the_wallet_request_is_the_value_built_request_byte_for_byte_on_every_fixture() {
    let prefix = issued_prefix();
    let labels = Some(vec!["paid".to_string(), "route \"/x\"".to_string()]);
    let mut txs = vector_transactions();
    assert_eq!(txs.len(), 22);
    for header in sized_headers(&prefix) {
        let payment: BsvPayment = serde_json::from_str(&header).unwrap();
        txs.push(("sized".into(), from_base64(&payment.transaction).unwrap()));
    }
    txs.push(("every byte value".into(), (0..=255u8).collect()));
    for (name, tx) in &txs {
        for labels in [None, labels.as_ref()] {
            let written = written_payload(tx, &prefix, labels);
            let want = reference_payload(tx, &prefix, labels);
            assert_eq!(written.signed(), want.as_slice(), "{name}");
            assert!(want.ends_with(written.body().unwrap().as_bytes()), "{name}");
        }
    }
}

#[test]
fn the_wallet_step_on_every_fixture_is_held_to_the_bound() {
    let prefix = issued_prefix();
    for (name, tx) in vector_transactions() {
        let header = header(&prefix, &tx);
        let len = header.len();
        // The vectors pay another server's key: the step after the read is
        // the wallet's, measured from the header.
        let peak = peak_of(move || {
            let payment: BsvPayment = serde_json::from_str(&header).unwrap();
            drop(header);
            let tx = from_base64(&payment.transaction).unwrap();
            block_on(wallet_step(None)(
                payment.derivation_prefix,
                payment.derivation_suffix,
                tx,
            ))
            .unwrap()
        });
        assert!(peak <= bound(len), "{name}: {peak} B for a {len} B header");
    }
}
