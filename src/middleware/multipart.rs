//! Multipart form-data payment transport for BRC-29.
//!
//! When a BSV payment transaction is too large for HTTP headers (~16KB limit),
//! the client sends it as a `multipart/form-data` body part instead. This module
//! provides [`prepare_multipart_payment`] which agents call after auth verification
//! and before payment processing.
//!
//! The multipart body contains two named parts:
//! - `x-bsv-payment`: payment JSON (same format as the header value)
//! - `body`: the original request payload with its own Content-Type
//!
//! Auth verification is unaffected — it operates on the raw multipart body bytes
//! before this extraction happens.

use crate::error::{AuthCloudflareError, Result};
use worker::Request;

/// A parsed multipart body part.
struct MultipartPart {
    #[allow(dead_code)]
    content_type: Option<String>,
    bytes: Vec<u8>,
}

// ─── Public API ──────────────────────────────────────────────────────

/// Prepare payment extraction for a request that may use multipart transport.
///
/// If the request `Content-Type` is `multipart/form-data`:
/// 1. Parses the body to extract the `x-bsv-payment` part (payment JSON)
/// 2. Returns `(body_bytes, Some(payment_json))` — the clean payload and payment string
///
/// If the request is NOT multipart, returns `(body, None)`.
///
/// Call this after auth verification and before payment processing:
///
/// ```rust,ignore
/// let (auth_context, req, session, request_body) = match auth_result { ... };
/// let (request_body, multipart_payment) = prepare_multipart_payment(&req, request_body)?;
/// // Use multipart_payment.or_else(|| header read) for payment extraction
/// ```
pub fn prepare_multipart_payment(req: &Request, body: Vec<u8>) -> Result<(Vec<u8>, Option<String>)> {
    let content_type = req
        .headers()
        .get("content-type")
        .ok()
        .flatten()
        .unwrap_or_default();

    if !content_type.starts_with("multipart/form-data") {
        return Ok((body, None));
    }

    let boundary = extract_boundary(&content_type).ok_or_else(|| {
        AuthCloudflareError::TransportError(
            "Multipart Content-Type missing boundary parameter".into(),
        )
    })?;

    let parts = parse_multipart(&body, &boundary)?;

    // Extract payment JSON from the x-bsv-payment part.
    let mut payment_json = None;
    for (name, part) in &parts {
        if name == "x-bsv-payment" {
            let json = String::from_utf8(part.bytes.clone()).map_err(|_| {
                AuthCloudflareError::MalformedPayment(
                    "x-bsv-payment multipart part is not valid UTF-8".into(),
                )
            })?;
            payment_json = Some(json);
            break;
        }
    }

    // Return clean body bytes from the "body" part.
    for (name, part) in parts {
        if name == "body" {
            return Ok((part.bytes, payment_json));
        }
    }

    // No body part — return empty (payment-only request).
    Ok((Vec::new(), payment_json))
}

// ─── Multipart Parser ────────────────────────────────────────────────

/// Extract the boundary string from a multipart/form-data Content-Type.
///
/// `multipart/form-data; boundary=----Bsv123` → `Some("----Bsv123")`
fn extract_boundary(content_type: &str) -> Option<String> {
    for segment in content_type.split(';') {
        let trimmed = segment.trim();
        if let Some(value) = trimmed.strip_prefix("boundary=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

/// Parse a multipart/form-data body into named parts.
///
/// Minimal RFC 7578 parser for a fixed 2-part format. Splits by boundary,
/// extracts Content-Disposition name and Content-Type for each part.
/// No streaming, no external crates — works in CF Workers Wasm.
fn parse_multipart(body: &[u8], boundary: &str) -> Result<Vec<(String, MultipartPart)>> {
    let delimiter = format!("--{}", boundary);
    let delimiter_bytes = delimiter.as_bytes();

    let mut parts = Vec::new();
    let mut search_from = 0;

    // Find and skip the first delimiter.
    let mut pos = match find_bytes(body, delimiter_bytes, search_from) {
        Some(p) => p + delimiter_bytes.len(),
        None => {
            return Err(AuthCloudflareError::TransportError(
                "Multipart body: initial boundary not found".into(),
            ))
        }
    };

    // Skip \r\n after first delimiter.
    if body.get(pos..pos + 2) == Some(b"\r\n") {
        pos += 2;
    }

    loop {
        // Check for closing delimiter (--boundary--).
        if pos + 2 <= body.len() && &body[pos..pos + 2] == b"--" {
            break;
        }

        // Find end of part headers (\r\n\r\n).
        let header_end = match find_bytes(body, b"\r\n\r\n", pos) {
            Some(p) => p,
            None => break,
        };

        // Parse part headers.
        let header_text = String::from_utf8_lossy(&body[pos..header_end]);
        let name = extract_part_name(&header_text);
        let content_type = extract_part_content_type(&header_text);

        // Part body starts after \r\n\r\n.
        let body_start = header_end + 4;

        // Find the next delimiter to determine where this part's body ends.
        search_from = body_start;
        let next_delim = find_bytes(body, delimiter_bytes, search_from);

        let body_end = match next_delim {
            Some(p) => {
                // Strip trailing \r\n before delimiter.
                if p >= 2 && &body[p - 2..p] == b"\r\n" {
                    p - 2
                } else {
                    p
                }
            }
            None => body.len(),
        };

        if let Some(name) = name {
            parts.push((
                name,
                MultipartPart {
                    content_type,
                    bytes: body[body_start..body_end].to_vec(),
                },
            ));
        }

        // Advance past the next delimiter.
        match next_delim {
            Some(p) => {
                pos = p + delimiter_bytes.len();
                // Skip \r\n after delimiter.
                if body.get(pos..pos + 2) == Some(b"\r\n") {
                    pos += 2;
                }
            }
            None => break,
        }
    }

    Ok(parts)
}

/// Find a byte pattern in a slice starting from `start`.
fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start + needle.len() > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

/// Extract the `name` value from a Content-Disposition header line.
///
/// `Content-Disposition: form-data; name="x-bsv-payment"` → `Some("x-bsv-payment")`
fn extract_part_name(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if !lower.starts_with("content-disposition:") {
            continue;
        }
        // Try name="quoted"
        if let Some(idx) = line.find("name=\"") {
            let start = idx + 6;
            if let Some(end) = line[start..].find('"') {
                return Some(line[start..start + end].to_string());
            }
        }
        // Try name=unquoted
        if let Some(idx) = line.find("name=") {
            let start = idx + 5;
            let end = line[start..]
                .find(|c: char| c == ';' || c == ' ' || c == '\r')
                .unwrap_or(line.len() - start);
            return Some(line[start..start + end].to_string());
        }
    }
    None
}

/// Extract Content-Type from part headers (case-insensitive).
fn extract_part_content_type(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-type:") {
            return Some(line["content-type:".len()..].trim().to_string());
        }
    }
    None
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_boundary_standard() {
        let ct = "multipart/form-data; boundary=----BsvPayment123";
        assert_eq!(extract_boundary(ct), Some("----BsvPayment123".into()));
    }

    #[test]
    fn test_extract_boundary_quoted() {
        let ct = "multipart/form-data; boundary=\"----BsvPayment123\"";
        assert_eq!(extract_boundary(ct), Some("----BsvPayment123".into()));
    }

    #[test]
    fn test_extract_boundary_missing() {
        assert_eq!(extract_boundary("application/json"), None);
        assert_eq!(extract_boundary("multipart/form-data"), None);
    }

    #[test]
    fn test_extract_part_name() {
        assert_eq!(
            extract_part_name("Content-Disposition: form-data; name=\"x-bsv-payment\""),
            Some("x-bsv-payment".into())
        );
        assert_eq!(
            extract_part_name("content-disposition: form-data; name=\"body\""),
            Some("body".into())
        );
    }

    #[test]
    fn test_extract_part_content_type() {
        assert_eq!(
            extract_part_content_type("Content-Type: application/json"),
            Some("application/json".into())
        );
        assert_eq!(
            extract_part_content_type("content-type: audio/wav"),
            Some("audio/wav".into())
        );
        assert_eq!(extract_part_content_type("X-Custom: foo"), None);
    }

    #[test]
    fn test_parse_multipart_two_parts() {
        let boundary = "----BsvBoundary";
        let body = format!(
            "------BsvBoundary\r\n\
             Content-Disposition: form-data; name=\"x-bsv-payment\"\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {{\"derivationPrefix\":\"abc\",\"derivationSuffix\":\"def\",\"transaction\":\"dHg=\"}}\r\n\
             ------BsvBoundary\r\n\
             Content-Disposition: form-data; name=\"body\"\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {{\"prompt\":\"hello\"}}\r\n\
             ------BsvBoundary--\r\n"
        );

        let parts = parse_multipart(body.as_bytes(), boundary).unwrap();
        assert_eq!(parts.len(), 2);

        assert_eq!(parts[0].0, "x-bsv-payment");
        assert_eq!(
            parts[0].1.content_type.as_deref(),
            Some("application/json")
        );
        let payment_str = std::str::from_utf8(&parts[0].1.bytes).unwrap();
        assert!(payment_str.contains("derivationPrefix"));

        assert_eq!(parts[1].0, "body");
        let body_str = std::str::from_utf8(&parts[1].1.bytes).unwrap();
        assert!(body_str.contains("prompt"));
    }

    #[test]
    fn test_parse_multipart_binary_body() {
        let boundary = "bsv123";
        let payment_json = r#"{"derivationPrefix":"p","derivationSuffix":"s","transaction":"dHg="}"#;
        let audio_bytes: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03];

        let mut body = Vec::new();
        body.extend_from_slice(b"--bsv123\r\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"x-bsv-payment\"\r\n");
        body.extend_from_slice(b"Content-Type: application/json\r\n");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(payment_json.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(b"--bsv123\r\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"body\"\r\n");
        body.extend_from_slice(b"Content-Type: audio/wav\r\n");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&audio_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(b"--bsv123--\r\n");

        let parts = parse_multipart(&body, boundary).unwrap();
        assert_eq!(parts.len(), 2);

        assert_eq!(parts[0].0, "x-bsv-payment");
        assert_eq!(
            std::str::from_utf8(&parts[0].1.bytes).unwrap(),
            payment_json
        );

        assert_eq!(parts[1].0, "body");
        assert_eq!(parts[1].1.bytes, audio_bytes);
        assert_eq!(parts[1].1.content_type.as_deref(), Some("audio/wav"));
    }

    #[test]
    fn test_parse_multipart_no_body_part() {
        let boundary = "b";
        let body = b"--b\r\n\
            Content-Disposition: form-data; name=\"x-bsv-payment\"\r\n\
            \r\n\
            {\"tx\":\"data\"}\r\n\
            --b--\r\n";

        let parts = parse_multipart(body, boundary).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0, "x-bsv-payment");
    }

    #[test]
    fn test_parse_multipart_missing_boundary() {
        let result = parse_multipart(b"no boundary here", "missing");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_bytes_basic() {
        let haystack = b"hello world";
        assert_eq!(find_bytes(haystack, b"world", 0), Some(6));
        assert_eq!(find_bytes(haystack, b"hello", 0), Some(0));
        assert_eq!(find_bytes(haystack, b"xyz", 0), None);
        assert_eq!(find_bytes(haystack, b"hello", 1), None);
    }

    #[test]
    fn test_find_bytes_with_offset() {
        let haystack = b"abcabcabc";
        assert_eq!(find_bytes(haystack, b"abc", 0), Some(0));
        assert_eq!(find_bytes(haystack, b"abc", 1), Some(3));
        assert_eq!(find_bytes(haystack, b"abc", 4), Some(6));
        assert_eq!(find_bytes(haystack, b"abc", 7), None);
    }

    /// Round-trip test: build multipart bytes in the same format as the Rust client
    /// (rust-bsv-worm build_multipart_body) and verify the parser extracts correctly.
    #[test]
    fn test_roundtrip_client_format() {
        let boundary = "----BsvPayment00a1b2c3d4e5f678";
        let payment_json = r#"{"derivationPrefix":"pfx","derivationSuffix":"sfx","transaction":"AQAAAA=="}"#;
        let original_body = br#"{"model":"gpt-5-nano","messages":[{"role":"user","content":"hello"}]}"#;
        let original_ct = "application/json";

        // Build multipart body in client format (mirrors rust-bsv-worm build_multipart_body)
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        buf.extend_from_slice(b"Content-Disposition: form-data; name=\"x-bsv-payment\"\r\n");
        buf.extend_from_slice(b"Content-Type: application/json\r\n");
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(payment_json.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        buf.extend_from_slice(b"Content-Disposition: form-data; name=\"body\"\r\n");
        buf.extend_from_slice(format!("Content-Type: {original_ct}\r\n").as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(original_body);
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        // Parse with server parser
        let parts = parse_multipart(&buf, boundary).unwrap();
        assert_eq!(parts.len(), 2);

        // Verify payment part
        assert_eq!(parts[0].0, "x-bsv-payment");
        assert_eq!(std::str::from_utf8(&parts[0].1.bytes).unwrap(), payment_json);

        // Verify body part
        assert_eq!(parts[1].0, "body");
        assert_eq!(parts[1].1.bytes, original_body);
        assert_eq!(parts[1].1.content_type.as_deref(), Some(original_ct));
    }

    /// Round-trip test with binary body (e.g., audio for whisper-agent).
    #[test]
    fn test_roundtrip_binary_body() {
        let boundary = "----BsvPaymentdeadbeefcafe1234";
        let payment_json = r#"{"derivationPrefix":"p","derivationSuffix":"s","transaction":"dHg="}"#;
        let audio_bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();

        let mut buf = Vec::new();
        buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        buf.extend_from_slice(b"Content-Disposition: form-data; name=\"x-bsv-payment\"\r\n");
        buf.extend_from_slice(b"Content-Type: application/json\r\n");
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(payment_json.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        buf.extend_from_slice(b"Content-Disposition: form-data; name=\"body\"\r\n");
        buf.extend_from_slice(b"Content-Type: audio/wav\r\n");
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&audio_bytes);
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let parts = parse_multipart(&buf, boundary).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(std::str::from_utf8(&parts[0].1.bytes).unwrap(), payment_json);
        assert_eq!(parts[1].1.bytes, audio_bytes);
    }
}
