//! A JSON-RPC request to the wallet storage server, written once: the
//! BRC-104 `general` payload it is signed over, whose tail is the HTTP body.
//!
//! The payload is what `HttpRequest::to_payload` writes for `POST /` with
//! the one `content-type: application/json` header and the JSON-RPC body
//! (`JsonRpcRequest` as serde_json writes it). The body is serialized
//! straight into the payload's buffer after a counting pass sizes it, so
//! the buffer is allocated once; the body sent is a view of its tail.

use std::io::Write;

use bsv_sdk::auth::transports::HttpRequest;
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use serde_json::{Map, Value};

use super::json_rpc::JSON_RPC_VERSION;
use crate::error::{AuthCloudflareError, Result};

/// The BRC-104 length of an absent body: `to_payload`'s -1.
const ABSENT: [u8; 9] = [0xFF; 9];

/// The signed payload of one JSON-RPC request, its body at the tail.
pub(crate) struct RpcPayload {
    buf: Vec<u8>,
    /// Where the body's length (a varint) starts.
    varint_at: usize,
    /// Where the body starts.
    body_start: usize,
    /// Where the digits of the body's `id` start.
    id_at: usize,
    /// The JSON-RPC id written.
    pub(crate) id: u64,
}

fn serialization(e: impl std::fmt::Display) -> AuthCloudflareError {
    AuthCloudflareError::SerializationError(e.to_string())
}

/// A byte count for a pass that keeps nothing.
struct Count(usize);

impl Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// BRC-104's varint for a length (bsv-rs `write_varint` for a value >= 0).
fn varint(n: usize) -> ([u8; 9], usize) {
    let n = n as u64;
    let mut out = [0u8; 9];
    let len = if n < 253 {
        out[0] = n as u8;
        1
    } else if n < 0x1_0000 {
        out[0] = 0xFD;
        out[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        3
    } else if n < 0x1_0000_0000 {
        out[0] = 0xFE;
        out[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        5
    } else {
        out[0] = 0xFF;
        out[1..9].copy_from_slice(&n.to_le_bytes());
        9
    };
    (out, len)
}

/// `{"jsonrpc":"2.0","method":<method>,"params":<params>,"id":` — the body
/// up to its id, the field order of `JsonRpcRequest`.
fn write_body_head<W: Write, P: Serialize + ?Sized>(
    w: &mut W,
    method: &str,
    params: &P,
) -> Result<()> {
    w.write_all(b"{\"jsonrpc\":").map_err(serialization)?;
    serde_json::to_writer(&mut *w, JSON_RPC_VERSION).map_err(serialization)?;
    w.write_all(b",\"method\":").map_err(serialization)?;
    serde_json::to_writer(&mut *w, method).map_err(serialization)?;
    w.write_all(b",\"params\":").map_err(serialization)?;
    serde_json::to_writer(&mut *w, params).map_err(serialization)?;
    w.write_all(b",\"id\":").map_err(serialization)?;
    Ok(())
}

fn write_id(buf: &mut Vec<u8>, id: u64) {
    buf.extend_from_slice(id.to_string().as_bytes());
    buf.push(b'}');
}

impl RpcPayload {
    /// The request `method(params)` with JSON-RPC id `id`, written once.
    pub(crate) fn write<P: Serialize + ?Sized>(id: u64, method: &str, params: &P) -> Result<Self> {
        let mut head = HttpRequest {
            request_id: [0u8; 32],
            method: "POST".to_string(),
            path: "/".to_string(),
            search: String::new(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Vec::new(),
        }
        .to_payload();
        if !head.ends_with(&ABSENT) {
            return Err(serialization("BRC-104 payload layout"));
        }
        head.truncate(head.len() - ABSENT.len());

        let mut count = Count(0);
        write_body_head(&mut count, method, params)?;
        let id_digits = id.to_string().len();
        let body_len = count.0 + id_digits + 1;
        let (len, len_size) = varint(body_len);

        let mut buf = Vec::with_capacity(head.len() + len_size + body_len);
        buf.extend_from_slice(&head);
        drop(head);
        let varint_at = buf.len();
        buf.extend_from_slice(&len[..len_size]);
        let body_start = buf.len();
        write_body_head(&mut buf, method, params)?;
        let id_at = buf.len();
        write_id(&mut buf, id);
        if buf.len() - body_start != body_len {
            return Err(serialization("the body's two passes differ"));
        }
        Ok(RpcPayload {
            buf,
            varint_at,
            body_start,
            id_at,
            id,
        })
    }

    /// Rewrites the body's JSON-RPC id (and the body's length before it).
    pub(crate) fn set_id(&mut self, id: u64) {
        self.buf.truncate(self.id_at);
        write_id(&mut self.buf, id);
        self.id = id;
        let (len, len_size) = varint(self.buf.len() - self.body_start);
        let old = self.varint_at..self.body_start;
        if old.len() == len_size {
            self.buf[old].copy_from_slice(&len[..len_size]);
        } else {
            let shift = len_size as isize - old.len() as isize;
            self.buf.splice(old, len[..len_size].iter().copied());
            self.body_start = (self.body_start as isize + shift) as usize;
            self.id_at = (self.id_at as isize + shift) as usize;
        }
    }

    /// Writes the attempt's request ID (the payload's first 32 bytes).
    pub(crate) fn set_request_id(&mut self, request_id: &[u8; 32]) {
        self.buf[..32].copy_from_slice(request_id);
    }

    /// The bytes the attempt is signed over.
    pub(crate) fn signed(&self) -> &[u8] {
        &self.buf
    }

    /// The HTTP body: the JSON-RPC request.
    pub(crate) fn body(&self) -> Result<&str> {
        std::str::from_utf8(&self.buf[self.body_start..]).map_err(serialization)
    }
}

/// Whether serde_json's maps keep insertion order in this build (its
/// `preserve_order` feature, which any crate in the build may turn on).
fn maps_keep_insertion_order() -> bool {
    let mut map = Map::new();
    map.insert("b".into(), Value::Null);
    map.insert("a".into(), Value::Null);
    map.keys().next().is_some_and(|k| k == "b")
}

/// `args` with `"tx": tx` (its byte values) where a `serde_json::Value`
/// holding it would write the key.
struct ArgsWithTx<'a> {
    args: &'a Map<String, Value>,
    tx: &'a [u8],
    tx_first: bool,
}

impl Serialize for ArgsWithTx<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.args.len() + 1))?;
        let mut tx_written = false;
        if self.tx_first {
            map.serialize_entry("tx", self.tx)?;
            tx_written = true;
        }
        for (key, value) in self.args {
            if !tx_written && key.as_str() > "tx" {
                map.serialize_entry("tx", self.tx)?;
                tx_written = true;
            }
            map.serialize_entry(key, value)?;
        }
        if !tx_written {
            map.serialize_entry("tx", self.tx)?;
        }
        map.end()
    }
}

/// `internalizeAction(auth, args + tx)`, written once.
pub(crate) fn internalize_payload(
    id: u64,
    auth: &Value,
    args: &Value,
    tx: &[u8],
) -> Result<RpcPayload> {
    let args = args
        .as_object()
        .ok_or_else(|| serialization("internalizeAction args must be an object"))?;
    if args.contains_key("tx") {
        return Err(serialization(
            "internalizeAction args carry tx; pass it beside them",
        ));
    }
    let with_tx = ArgsWithTx {
        args,
        tx,
        tx_first: maps_keep_insertion_order(),
    };
    RpcPayload::write(id, "internalizeAction", &(auth, with_tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::JsonRpcRequest;

    /// The payload of `JsonRpcRequest` serialized as one value, and its body.
    fn reference(id: u64, method: &str, params: Vec<Value>, request_id: [u8; 32]) -> Vec<u8> {
        let body = serde_json::to_vec(&JsonRpcRequest::new(id, method, params)).unwrap();
        HttpRequest {
            request_id,
            method: "POST".to_string(),
            path: "/".to_string(),
            search: String::new(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
        }
        .to_payload()
    }

    fn body_of(payload: &[u8], body: &str) -> bool {
        payload.ends_with(body.as_bytes())
    }

    #[test]
    fn a_request_is_the_reference_payload_byte_for_byte() {
        let rid = [9u8; 32];
        for params in [
            vec![],
            vec![serde_json::json!("02abc")],
            vec![
                serde_json::json!({"identityKey": "02ab", "userId": 7}),
                serde_json::json!({"z": [1, 2, 3], "a": "é\"\\\n", "m": null}),
            ],
        ] {
            let mut p = RpcPayload::write(3, "findOrInsertUser", &params).unwrap();
            p.set_request_id(&rid);
            let want = reference(3, "findOrInsertUser", params.clone(), rid);
            assert_eq!(p.signed(), want.as_slice());
            assert!(body_of(&want, p.body().unwrap()));
        }
    }

    #[test]
    fn a_new_id_rewrites_the_body_and_its_length() {
        let rid = [1u8; 32];
        // Bodies whose length crosses the varint's one- and three-byte forms
        // when the id gains a digit.
        for pad in 0..400usize {
            let params = vec![Value::String("x".repeat(pad))];
            let mut p = RpcPayload::write(9, "m", &params).unwrap();
            for id in [10u64, 99_999, 4, u64::MAX] {
                p.set_id(id);
                p.set_request_id(&rid);
                assert_eq!(
                    p.signed(),
                    reference(id, "m", params.clone(), rid).as_slice()
                );
                assert_eq!(p.id, id);
            }
        }
    }

    #[test]
    fn varint_matches_bsv_rs_at_every_boundary() {
        for n in [
            0usize,
            252,
            253,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
        ] {
            let (v, len) = varint(n);
            let want: Vec<u8> = match n as u64 {
                x if x < 253 => vec![x as u8],
                x if x < 0x1_0000 => [&[0xFD][..], &(x as u16).to_le_bytes()].concat(),
                x if x < 0x1_0000_0000 => [&[0xFE][..], &(x as u32).to_le_bytes()].concat(),
                x => [&[0xFF][..], &x.to_le_bytes()].concat(),
            };
            assert_eq!(&v[..len], want.as_slice());
        }
        // And against to_payload's own length prefix.
        for len in [1usize, 252, 253, 300, 70_000] {
            let rq = HttpRequest {
                request_id: [0; 32],
                method: "POST".into(),
                path: "/".into(),
                search: String::new(),
                headers: vec![],
                body: vec![b'a'; len],
            };
            let full = rq.to_payload();
            let (v, n) = varint(len);
            let at = full.len() - len - n;
            assert_eq!(&full[at..at + n], &v[..n]);
        }
    }

    #[test]
    fn args_with_tx_put_it_where_a_value_would() {
        let auth = serde_json::json!({"identityKey": "02ab", "userId": null});
        let tx: Vec<u8> = (0..=255u8).chain([0, 9, 10, 99, 100, 255]).collect();
        for args in [
            serde_json::json!({"outputs": [{"a": 1}], "description": "d"}),
            serde_json::json!({"outputs": [], "description": "d", "labels": ["x", "y"]}),
            serde_json::json!({"a": 1}),
            serde_json::json!({"zz": 1}),
            serde_json::json!({"tw": 1, "ty": 2, "u": 3}),
            serde_json::json!({}),
        ] {
            let mut with = args.clone();
            with["tx"] = serde_json::json!(tx);
            let rid = [3u8; 32];
            let mut p = internalize_payload(3, &auth, &args, &tx).unwrap();
            p.set_request_id(&rid);
            let want = reference(3, "internalizeAction", vec![auth.clone(), with], rid);
            assert_eq!(p.signed(), want.as_slice(), "{args}");
        }
        assert!(internalize_payload(1, &auth, &serde_json::json!([]), &tx).is_err());
        assert!(internalize_payload(1, &auth, &serde_json::json!({"tx": 1}), &tx).is_err());
    }

    #[test]
    fn insertion_order_puts_tx_first() {
        let args = serde_json::json!({"outputs": [], "description": "d"});
        let map = args.as_object().unwrap();
        let mut out = Vec::new();
        ArgsWithTx {
            args: map,
            tx: &[1, 2],
            tx_first: true,
        }
        .serialize(&mut serde_json::Serializer::new(&mut out))
        .unwrap();
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        let rest: Vec<String> = keys
            .iter()
            .map(|k| format!("\"{k}\":{}", map[*k]))
            .collect();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{{\"tx\":[1,2],{}}}", rest.join(","))
        );
        assert!(!maps_keep_insertion_order(), "this crate's own build sorts");
    }
}
