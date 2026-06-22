//! ISO/IEC 18013-5 mdoc / `mso_mdoc` decoding.
//!
//! The German PID is an SD-JWT VC, but the other major EUDI credential format is
//! the ISO mdoc (mDL and friends), carried as CBOR. This module decodes what a
//! wallet presents in that format so the workbench can show it the same way it
//! shows SD-JWT VC: the document type, the disclosed namespaces and elements,
//! the issuer authentication (the COSE_Sign1 algorithm and its X.509 chain), and
//! the Mobile Security Object (validity window, the per-namespace value-digest
//! counts, and the device key).
//!
//! This is decode only. No COSE signature is verified and no value digest is
//! recomputed; the output says as much. Cryptographic mdoc verification (COSE +
//! digest matching + device binding) is later work, mirrored on the SD-JWT side
//! by the `verify` commands.

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use ciborium::value::{Integer, Value as Cbor};
use serde_json::{json, Map, Value};

use crate::commands::decode::Decoded;

/// Decode an mdoc artifact (a `DeviceResponse`, a single `Document`, an
/// `IssuerSigned`, or a bare `MobileSecurityObject`) from raw CBOR bytes, hex, or
/// base64 / base64url.
pub fn decode_mdoc(input: &[u8]) -> Result<Decoded> {
    let bytes = cbor_bytes_from_input(input)?;
    let cbor: Cbor = ciborium::from_reader(bytes.as_slice())
        .context("input is not valid CBOR (after any hex/base64 decoding)")?;
    let json = classify(&cbor)?;
    let text = render(&json);
    Ok(Decoded { json, text })
}

/// Heuristic for the artifact sniffer: does this text decode (as hex, base64, or
/// base64url, falling back to raw bytes) to a recognizable mdoc structure? Used
/// by `inspect`; the explicit `decode mdoc` does not rely on it.
pub fn looks_like_mdoc(input: &str) -> bool {
    let bytes = match cbor_bytes_from_input(input.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    match ciborium::from_reader::<Cbor, _>(bytes.as_slice()) {
        Ok(c) => classify(&c).is_ok(),
        Err(_) => false,
    }
}

/// Resolve the input to CBOR bytes. Prefer a text interpretation (hex or
/// base64/base64url) when the input is clean ASCII for those alphabets, since a
/// hex/base64 string would otherwise be mis-read as raw CBOR; fall back to the
/// raw bytes (a binary mdoc file or stdin).
fn cbor_bytes_from_input(input: &[u8]) -> Result<Vec<u8>> {
    if let Ok(s) = std::str::from_utf8(input) {
        let t = s.trim();
        if !t.is_empty() && t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return hex_decode(t);
        }
        let base64ish = !t.is_empty()
            && t.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'/' | b'=')
            });
        if base64ish {
            if let Ok(b) = BASE64_URL_SAFE_NO_PAD.decode(t.trim_end_matches('=')) {
                return Ok(b);
            }
            if let Ok(b) = BASE64_STANDARD.decode(t) {
                return Ok(b);
            }
        }
    }
    Ok(input.to_vec())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .context("invalid hex digit")?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .context("invalid hex digit")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

// --- CBOR accessors --------------------------------------------------------

fn as_map(c: &Cbor) -> Option<&Vec<(Cbor, Cbor)>> {
    match c {
        Cbor::Map(m) => Some(m),
        _ => None,
    }
}

fn as_array(c: &Cbor) -> Option<&Vec<Cbor>> {
    match c {
        Cbor::Array(a) => Some(a),
        _ => None,
    }
}

fn text(c: &Cbor) -> Option<String> {
    match c {
        Cbor::Text(t) => Some(t.clone()),
        _ => None,
    }
}

fn bytes(c: &Cbor) -> Option<&Vec<u8>> {
    match c {
        Cbor::Bytes(b) => Some(b),
        _ => None,
    }
}

fn int_of(i: &Integer) -> i128 {
    i128::from(*i)
}

fn as_int(c: &Cbor) -> Option<i128> {
    match c {
        Cbor::Integer(i) => Some(int_of(i)),
        _ => None,
    }
}

/// Look up a text key in a CBOR map.
fn get<'a>(m: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    m.iter()
        .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
        .map(|(_, v)| v)
}

/// Look up an integer key in a CBOR map (COSE headers and keys use integer keys).
fn get_int(m: &[(Cbor, Cbor)], key: i128) -> Option<&Cbor> {
    m.iter()
        .find(|(k, _)| matches!(k, Cbor::Integer(i) if int_of(i) == key))
        .map(|(_, v)| v)
}

fn has(m: &[(Cbor, Cbor)], key: &str) -> bool {
    get(m, key).is_some()
}

// --- classification --------------------------------------------------------

fn classify(c: &Cbor) -> Result<Value> {
    let m = as_map(c).context("top-level mdoc artifact is not a CBOR map")?;
    if has(m, "version") && (has(m, "documents") || has(m, "status")) {
        Ok(decode_device_response(m))
    } else if has(m, "docType") && has(m, "issuerSigned") {
        Ok(json!({ "type": "Document", "document": decode_document(c) }))
    } else if has(m, "nameSpaces") || has(m, "issuerAuth") {
        let mut obj = decode_issuer_signed(m);
        obj.insert("type".into(), json!("IssuerSigned"));
        Ok(Value::Object(obj))
    } else if has(m, "valueDigests") || has(m, "validityInfo") {
        Ok(json!({ "type": "MobileSecurityObject", "mso": decode_mso_map(m) }))
    } else {
        let keys: Vec<String> = m
            .iter()
            .map(|(k, _)| text(k).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        bail!("unrecognized mdoc structure; top-level CBOR map keys: {keys:?}");
    }
}

fn decode_device_response(m: &[(Cbor, Cbor)]) -> Value {
    let documents = get(m, "documents")
        .and_then(as_array)
        .map(|docs| docs.iter().map(decode_document).collect::<Vec<_>>())
        .unwrap_or_default();
    let doc_errors = get(m, "documentErrors")
        .and_then(as_array)
        .map(|e| e.len())
        .unwrap_or(0);
    let mut obj = Map::new();
    obj.insert("type".into(), json!("DeviceResponse"));
    if let Some(v) = get(m, "version").and_then(text) {
        obj.insert("version".into(), json!(v));
    }
    if let Some(s) = get(m, "status").and_then(as_int) {
        obj.insert("status".into(), json!(s));
    }
    obj.insert("documentCount".into(), json!(documents.len()));
    if doc_errors > 0 {
        obj.insert("documentErrors".into(), json!(doc_errors));
    }
    obj.insert("documents".into(), json!(documents));
    Value::Object(obj)
}

fn decode_document(c: &Cbor) -> Value {
    let m = match as_map(c) {
        Some(m) => m,
        None => return json!({ "error": "document is not a CBOR map" }),
    };
    let mut obj = Map::new();
    if let Some(dt) = get(m, "docType").and_then(text) {
        obj.insert("docType".into(), json!(dt));
    }
    if let Some(is) = get(m, "issuerSigned").and_then(as_map) {
        let issuer = decode_issuer_signed(is);
        for (k, v) in issuer {
            obj.insert(k, v);
        }
    }
    // deviceSigned is the holder's response part; note its presence and which
    // namespaces it carried, without verifying the device signature.
    if let Some(ds) = get(m, "deviceSigned").and_then(as_map) {
        let ns = ds
            .iter()
            .find(|(k, _)| matches!(k, Cbor::Text(t) if t == "nameSpaces"))
            .map(|_| true)
            .unwrap_or(false);
        obj.insert(
            "deviceSigned".into(),
            json!({ "present": true, "hasNameSpaces": ns }),
        );
    }
    if let Some(errs) = get(m, "errors").and_then(as_map) {
        obj.insert("errors".into(), json!({ "namespaceCount": errs.len() }));
    }
    Value::Object(obj)
}

fn decode_issuer_signed(m: &[(Cbor, Cbor)]) -> Map<String, Value> {
    let mut obj = Map::new();
    if let Some(ns) = get(m, "nameSpaces").and_then(as_map) {
        obj.insert("namespaces".into(), decode_namespaces(ns));
    }
    if let Some(ia) = get(m, "issuerAuth") {
        obj.insert("issuerAuth".into(), decode_issuer_auth(ia));
    }
    obj
}

/// Decode `IssuerSigned.nameSpaces`: each namespace maps to a list of
/// `IssuerSignedItemBytes` (a tag-24 CBOR-in-bstr wrapping an IssuerSignedItem).
fn decode_namespaces(m: &[(Cbor, Cbor)]) -> Value {
    let mut out = Map::new();
    for (k, v) in m {
        let ns = match text(k) {
            Some(t) => t,
            None => continue,
        };
        let items: Vec<Value> = as_array(v)
            .map(|arr| arr.iter().filter_map(decode_issuer_signed_item).collect())
            .unwrap_or_default();
        out.insert(ns, json!(items));
    }
    Value::Object(out)
}

fn decode_issuer_signed_item(c: &Cbor) -> Option<Value> {
    let inner = unwrap_tag24(c)?;
    let m = as_map(&inner)?;
    let mut obj = Map::new();
    if let Some(d) = get(m, "digestID").and_then(as_int) {
        obj.insert("digestID".into(), json!(d));
    }
    if let Some(id) = get(m, "elementIdentifier").and_then(text) {
        obj.insert("elementIdentifier".into(), json!(id));
    }
    if let Some(v) = get(m, "elementValue") {
        obj.insert("elementValue".into(), cbor_to_json(v));
    }
    Some(Value::Object(obj))
}

/// Decode the issuer authentication `COSE_Sign1`:
/// `[protected: bstr, unprotected: map, payload, signature: bstr]`.
fn decode_issuer_auth(c: &Cbor) -> Value {
    let arr = match as_array(c) {
        Some(a) if a.len() == 4 => a,
        _ => return json!({ "error": "issuerAuth is not a 4-element COSE_Sign1" }),
    };
    let mut obj = Map::new();

    // Protected header (a bstr wrapping a CBOR map); alg is integer key 1.
    if let Some(proto) = bytes(&arr[0]) {
        if let Ok(ph) = ciborium::from_reader::<Cbor, _>(proto.as_slice()) {
            if let Some(pm) = as_map(&ph) {
                if let Some(alg) = get_int(pm, 1).and_then(as_int) {
                    obj.insert("alg".into(), json!(cose_alg_name(alg)));
                }
            }
        }
    }

    // Unprotected header; the X.509 chain is integer key 33.
    if let Some(um) = as_map(&arr[1]) {
        if let Some(x5) = get_int(um, 33) {
            obj.insert("x5chain".into(), decode_x5chain(x5));
        }
    }

    // Payload: the COSE_Sign1 payload is a bstr whose bytes encode the
    // MobileSecurityObjectBytes (a `#6.24(bstr .cbor MSO)`). So parse the bstr
    // into CBOR, then unwrap the tag-24 to reach the MSO map.
    let payload_inner: Option<Cbor> = match &arr[2] {
        Cbor::Bytes(b) => ciborium::from_reader::<Cbor, _>(b.as_slice()).ok(),
        other => Some(other.clone()),
    };
    if let Some(p) = payload_inner {
        let mso = unwrap_tag24(&p).unwrap_or(p);
        if let Some(mm) = as_map(&mso) {
            obj.insert("mso".into(), decode_mso_map(mm));
        }
    }
    obj.insert("signatureVerified".into(), json!(false));
    Value::Object(obj)
}

fn decode_x5chain(c: &Cbor) -> Value {
    // x5chain is either a single bstr (one cert) or an array of bstr.
    let ders: Vec<&Vec<u8>> = match c {
        Cbor::Bytes(b) => vec![b],
        Cbor::Array(a) => a.iter().filter_map(bytes).collect(),
        _ => vec![],
    };
    let mut obj = Map::new();
    obj.insert("present".into(), json!(!ders.is_empty()));
    obj.insert("count".into(), json!(ders.len()));
    if let Some(leaf) = ders.first() {
        match crate::x509util::cert_info_from_der((*leaf).clone()) {
            Ok(info) => {
                obj.insert(
                    "leaf".into(),
                    json!({
                        "subject": info.subject,
                        "issuer": info.issuer,
                        "x509Hash": info.x509_hash,
                        "notBeforeUnix": info.not_before_unix,
                        "notAfterUnix": info.not_after_unix,
                    }),
                );
            }
            Err(e) => {
                obj.insert("leaf".into(), json!({ "parseError": e.to_string() }));
            }
        }
    }
    Value::Object(obj)
}

fn decode_mso_map(m: &[(Cbor, Cbor)]) -> Value {
    let mut obj = Map::new();
    if let Some(v) = get(m, "version").and_then(text) {
        obj.insert("version".into(), json!(v));
    }
    if let Some(v) = get(m, "digestAlgorithm").and_then(text) {
        obj.insert("digestAlgorithm".into(), json!(v));
    }
    if let Some(v) = get(m, "docType").and_then(text) {
        obj.insert("docType".into(), json!(v));
    }
    if let Some(vi) = get(m, "validityInfo").and_then(as_map) {
        let mut vobj = Map::new();
        for field in ["signed", "validFrom", "validUntil", "expectedUpdate"] {
            if let Some(v) = get(vi, field) {
                vobj.insert(field.into(), cbor_to_json(v));
            }
        }
        obj.insert("validityInfo".into(), Value::Object(vobj));
    }
    if let Some(vd) = get(m, "valueDigests").and_then(as_map) {
        let mut counts = Map::new();
        for (k, v) in vd {
            if let (Some(ns), Some(digests)) = (text(k), as_map(v)) {
                counts.insert(ns, json!(digests.len()));
            }
        }
        obj.insert("valueDigestCounts".into(), Value::Object(counts));
    }
    if let Some(dki) = get(m, "deviceKeyInfo").and_then(as_map) {
        if let Some(dk) = get(dki, "deviceKey").and_then(as_map) {
            obj.insert("deviceKey".into(), decode_cose_key(dk));
        }
    }
    Value::Object(obj)
}

fn decode_cose_key(m: &[(Cbor, Cbor)]) -> Value {
    // COSE_Key: kty is integer key 1, crv is integer key -1.
    let kty = get_int(m, 1).and_then(as_int).map(cose_kty_name);
    let crv = get_int(m, -1).and_then(as_int).map(cose_crv_name);
    json!({ "kty": kty, "crv": crv })
}

/// Unwrap a `#6.24(bstr)` (CBOR-in-byte-string) into the inner CBOR value.
fn unwrap_tag24(c: &Cbor) -> Option<Cbor> {
    match c {
        Cbor::Tag(24, inner) => {
            let b = bytes(inner)?;
            ciborium::from_reader::<Cbor, _>(b.as_slice()).ok()
        }
        _ => None,
    }
}

fn cose_alg_name(alg: i128) -> String {
    match alg {
        -7 => "ES256".into(),
        -35 => "ES384".into(),
        -36 => "ES512".into(),
        -8 => "EdDSA".into(),
        -37 => "PS256".into(),
        other => format!("COSE alg {other}"),
    }
}

fn cose_kty_name(kty: i128) -> String {
    match kty {
        1 => "OKP".into(),
        2 => "EC2".into(),
        other => format!("kty {other}"),
    }
}

fn cose_crv_name(crv: i128) -> String {
    match crv {
        1 => "P-256".into(),
        2 => "P-384".into(),
        3 => "P-521".into(),
        6 => "Ed25519".into(),
        other => format!("crv {other}"),
    }
}

/// Convert an arbitrary CBOR value to JSON for display. Byte strings become a
/// length-tagged hex preview so a large value (a portrait) does not flood the
/// output; date tags (0, 1, 1004) pass their inner value through.
fn cbor_to_json(c: &Cbor) -> Value {
    match c {
        Cbor::Null => Value::Null,
        Cbor::Bool(b) => json!(b),
        Cbor::Integer(i) => json!(int_of(i) as i64),
        Cbor::Float(f) => json!(f),
        Cbor::Text(t) => json!(t),
        Cbor::Bytes(b) => json!({ "length": b.len(), "hex": hex_preview(b) }),
        Cbor::Array(a) => Value::Array(a.iter().map(cbor_to_json).collect()),
        Cbor::Map(m) => {
            let mut obj = Map::new();
            for (k, v) in m {
                let key = match k {
                    Cbor::Text(t) => t.clone(),
                    Cbor::Integer(i) => int_of(i).to_string(),
                    other => format!("{other:?}"),
                };
                obj.insert(key, cbor_to_json(v));
            }
            Value::Object(obj)
        }
        Cbor::Tag(t, inner) => match t {
            0 | 1 | 1004 => cbor_to_json(inner),
            other => json!({ "_tag": other, "value": cbor_to_json(inner) }),
        },
        _ => json!("<unsupported cbor>"),
    }
}

fn hex_preview(b: &[u8]) -> String {
    const MAX: usize = 32;
    let shown = &b[..b.len().min(MAX)];
    let mut s = String::with_capacity(shown.len() * 2 + 3);
    for byte in shown {
        s.push_str(&format!("{byte:02x}"));
    }
    if b.len() > MAX {
        s.push_str("...");
    }
    s
}

// --- text rendering --------------------------------------------------------

fn render(json: &Value) -> String {
    let mut out = String::new();
    let kind = json.get("type").and_then(Value::as_str).unwrap_or("mdoc");
    out.push_str(&format!("Decoded mdoc ({kind})\n"));
    out.push_str(
        "Note: structure decoded only; COSE signature and value digests are NOT verified.\n",
    );

    match kind {
        "DeviceResponse" => {
            if let Some(v) = json.get("version").and_then(Value::as_str) {
                out.push_str(&format!("version: {v}\n"));
            }
            if let Some(s) = json.get("status").and_then(Value::as_i64) {
                out.push_str(&format!("status: {s}\n"));
            }
            if let Some(docs) = json.get("documents").and_then(Value::as_array) {
                out.push_str(&format!("documents: {}\n", docs.len()));
                for (i, d) in docs.iter().enumerate() {
                    out.push_str(&format!("\n--- document {} ---\n", i + 1));
                    render_document(d, &mut out);
                }
            }
        }
        "Document" => {
            if let Some(d) = json.get("document") {
                render_document(d, &mut out);
            }
        }
        "IssuerSigned" => render_document(json, &mut out),
        "MobileSecurityObject" => {
            if let Some(mso) = json.get("mso") {
                render_mso(mso, &mut out);
            }
        }
        _ => {}
    }
    out
}

fn render_document(d: &Value, out: &mut String) {
    if let Some(dt) = d.get("docType").and_then(Value::as_str) {
        out.push_str(&format!("docType: {dt}\n"));
    }
    if let Some(ns) = d.get("namespaces").and_then(Value::as_object) {
        for (namespace, items) in ns {
            let items = items.as_array().cloned().unwrap_or_default();
            out.push_str(&format!(
                "namespace {namespace} ({} element(s)):\n",
                items.len()
            ));
            for it in &items {
                let id = it
                    .get("elementIdentifier")
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                let val = it.get("elementValue").map(short_value).unwrap_or_default();
                out.push_str(&format!("  {id} = {val}\n"));
            }
        }
    }
    if let Some(ia) = d.get("issuerAuth") {
        if let Some(alg) = ia.get("alg").and_then(Value::as_str) {
            out.push_str(&format!("issuerAuth alg: {alg}\n"));
        }
        if let Some(x5) = ia.get("x5chain") {
            let count = x5.get("count").and_then(Value::as_u64).unwrap_or(0);
            out.push_str(&format!("issuerAuth x5chain: {count} cert(s)"));
            if let Some(subj) = x5
                .get("leaf")
                .and_then(|l| l.get("subject"))
                .and_then(Value::as_str)
            {
                out.push_str(&format!(", leaf subject {subj}"));
            }
            if let Some(h) = x5
                .get("leaf")
                .and_then(|l| l.get("x509Hash"))
                .and_then(Value::as_str)
            {
                out.push_str(&format!(", x509_hash {h}"));
            }
            out.push('\n');
        }
        if let Some(mso) = ia.get("mso") {
            render_mso(mso, out);
        }
    }
    if let Some(ds) = d.get("deviceSigned") {
        if ds.get("present").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("deviceSigned: present (device signature not verified)\n");
        }
    }
}

fn render_mso(mso: &Value, out: &mut String) {
    out.push_str("MSO:\n");
    for field in ["version", "digestAlgorithm", "docType"] {
        if let Some(v) = mso.get(field).and_then(Value::as_str) {
            out.push_str(&format!("  {field}: {v}\n"));
        }
    }
    if let Some(vi) = mso.get("validityInfo").and_then(Value::as_object) {
        for (k, v) in vi {
            out.push_str(&format!("  validity {k}: {}\n", short_value(v)));
        }
    }
    if let Some(counts) = mso.get("valueDigestCounts").and_then(Value::as_object) {
        for (ns, n) in counts {
            out.push_str(&format!("  valueDigests[{ns}]: {n}\n"));
        }
    }
    if let Some(dk) = mso.get("deviceKey") {
        let kty = dk.get("kty").and_then(Value::as_str).unwrap_or("?");
        let crv = dk.get("crv").and_then(Value::as_str).unwrap_or("?");
        out.push_str(&format!("  deviceKey: {kty} {crv}\n"));
    }
}

fn short_value(v: &Value) -> String {
    match v {
        Value::String(s) => {
            if s.len() > 60 {
                format!("{}...", &s[..60])
            } else {
                s.clone()
            }
        }
        Value::Object(o) => {
            if let Some(len) = o.get("length").and_then(Value::as_u64) {
                format!("<{len} bytes>")
            } else {
                let s = v.to_string();
                if s.len() > 60 {
                    format!("{}...", &s[..60])
                } else {
                    s
                }
            }
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_signed() -> Vec<u8> {
        std::fs::read("fixtures/mdoc/issuer-signed.hex").expect("read mdoc issuer-signed fixture")
    }

    fn device_response() -> Vec<u8> {
        std::fs::read("fixtures/mdoc/device-response.hex")
            .expect("read mdoc device-response fixture")
    }

    #[test]
    fn decodes_real_mdl_issuer_signed() {
        let decoded = decode_mdoc(&issuer_signed()).expect("decode mdoc");
        let j = &decoded.json;
        assert_eq!(j["type"], "IssuerSigned");

        // The standard mDL namespace is present, with the disclosed elements.
        let items = j["namespaces"]["org.iso.18013.5.1"]
            .as_array()
            .expect("mDL namespace items");
        let family = items
            .iter()
            .find(|it| it["elementIdentifier"] == "family_name")
            .expect("family_name element");
        assert_eq!(family["elementValue"], "Doe");

        // Issuer authentication: a COSE alg, an unverified flag, and an x5chain
        // leaf whose x509_hash our engine computed.
        assert_eq!(j["issuerAuth"]["alg"], "ES256");
        assert_eq!(j["issuerAuth"]["signatureVerified"], false);
        assert!(j["issuerAuth"]["x5chain"]["leaf"]["x509Hash"].is_string());

        // The MSO decoded: docType and a per-namespace value-digest count.
        let mso = &j["issuerAuth"]["mso"];
        assert!(
            mso["docType"]
                .as_str()
                .unwrap_or("")
                .contains("iso.18013.5.1"),
            "MSO docType is an mDL: {:?}",
            mso["docType"]
        );
        assert!(
            mso["valueDigestCounts"]["org.iso.18013.5.1"]
                .as_u64()
                .unwrap_or(0)
                > 0,
            "value-digest count present"
        );
    }

    #[test]
    fn decodes_device_response_structure() {
        let decoded = decode_mdoc(&device_response()).expect("decode mdoc");
        let j = &decoded.json;
        assert_eq!(j["type"], "DeviceResponse");
        assert!(
            j["documentCount"].as_u64().unwrap_or(0) >= 1,
            "at least one document"
        );
        assert!(j["documents"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn hex_and_raw_bytes_agree() {
        let hex_input = issuer_signed();
        let raw = hex_decode(std::str::from_utf8(&hex_input).unwrap().trim()).unwrap();
        let from_hex = decode_mdoc(&hex_input).unwrap();
        let from_raw = decode_mdoc(&raw).unwrap();
        assert_eq!(from_hex.json, from_raw.json);
    }
}
