//! Registration certificate decoding and the registered-scope model.
//!
//! A relying party's registration certificate (WRPRC, `typ rc-wrp+jwt`) is the
//! machine-readable declaration of what it may ask for: a `purpose`, a
//! `privacy_policy` and `support_uri`, and an authorized `credentials` set
//! (`format`, `meta.vct_values`, and `claim[].path`). A verifier can fetch it
//! publicly from the registrar; the inspector reads it as the real "registered
//! scope" rather than a hand-built mock.
//!
//! Field shapes here are grounded in a real registration certificate fetched
//! from the live registrar (`fixtures/live/rc-payload.json`, 2026-06-02): the
//! payload uses snake_case `privacy_policy`/`support_uri`, `purpose` is an array
//! of `{lang, content}`, and each credential's claims are under the singular key
//! `claim` (we also accept `claims` defensively).
//!
//! Claim paths are OpenID4VP claims path pointers (strings, nulls and
//! non-negative integers; EUDI TS5 section 2.4.2) and are kept typed. A request
//! is compared with the registration by [`RegisteredScope::covers`]: the
//! credential is matched by format and type first, then the paths segment by
//! segment ([`path_covers`]), never as joined strings.
//!
//! This decodes the JWT payload only. The WRPRC signature (against the
//! registrar CA, the `x5c` chain in the header), its issuer and its revocation
//! status are not verified here; that is a separate trust step.

use anyhow::{Context, Result};
use base64::prelude::*;
use serde_json::Value;

/// A localized string, `{lang, content}`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LangString {
    pub lang: String,
    pub content: String,
}

/// The OpenID4VP credential format identifier of ISO mdoc credentials.
pub const FORMAT_MSO_MDOC: &str = "mso_mdoc";

/// One segment of a claims path pointer (OpenID4VP 1.0 section 7): a string
/// selects an object member (or, for `mso_mdoc`, names the namespace or the
/// data element), a non-negative integer one array element, and null every
/// element of an array. Serializes back to the JSON segment it was read from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(untagged)]
pub enum PathSeg {
    Key(String),
    Index(u64),
    All,
}

impl PathSeg {
    /// The segment for one JSON value, or `None` for anything that is not a
    /// string, null, or a non-negative integer (booleans, negative or
    /// fractional numbers, arrays, objects).
    pub fn from_json(v: &Value) -> Option<Self> {
        match v {
            Value::String(s) => Some(Self::Key(s.clone())),
            Value::Null => Some(Self::All),
            Value::Number(n) => n.as_u64().map(Self::Index),
            _ => None,
        }
    }

    /// Display form: the key, the index, or `*` for null. For display only;
    /// coverage compares typed segments, never these strings.
    pub fn display(&self) -> String {
        match self {
            Self::Key(s) => s.clone(),
            Self::Index(i) => i.to_string(),
            Self::All => "*".to_string(),
        }
    }
}

/// Parse a claims path pointer: a non-empty JSON array of strings, nulls and
/// non-negative integers (OpenID4VP 1.0 section 7). Anything else is `None`.
pub fn parse_claim_path(v: &Value) -> Option<Vec<PathSeg>> {
    let segs = v.as_array()?;
    if segs.is_empty() {
        return None;
    }
    segs.iter().map(PathSeg::from_json).collect()
}

/// Whether a parsed claims path pointer is valid for a credential of `format`:
/// non-empty, and for `mso_mdoc` exactly two strings, `[namespace, data
/// element]` (OpenID4VP 1.0 section 7.2.1: "If the claims path pointer does not
/// contain exactly two components or one of the components is not a string
/// then abort processing and return an error").
pub fn valid_claim_path(format: &str, path: &[PathSeg]) -> bool {
    if format == FORMAT_MSO_MDOC {
        matches!(path, [PathSeg::Key(_), PathSeg::Key(_)])
    } else {
        !path.is_empty()
    }
}

/// Dotted display key of a path, null shown as `*`. Display only.
pub fn display_path(path: &[PathSeg]) -> String {
    path.iter()
        .map(PathSeg::display)
        .collect::<Vec<_>>()
        .join(".")
}

/// Whether a registered claims path pointer covers a requested one, compared
/// segment by segment and never as joined strings. Coverage is structural: no
/// concrete credential is evaluated.
///
/// JSON-based formats (OpenID4VP 1.0 section 7.1): the requested path is
/// covered when the registered path is a prefix of it in which every segment
/// equals the requested segment at the same position, or is null where the
/// requested segment is an integer (null selects every array element, so one
/// element is within it). Hence an equal path is covered, null segments
/// included; a child of a registered object is covered (section 7.3: the
/// object is selected "with its sub-claims"); a parent of a registered child,
/// a requested null under a registered index, and a string `"0"` against an
/// integer `0` are not.
///
/// `mso_mdoc` (section 7.2): a path is `[namespace, data element]`; it is
/// covered only by an equal registered path, with no prefix, wildcard or index
/// semantics, so an element of another namespace is never covered. A path that
/// is not exactly two strings ([`valid_claim_path`]) is invalid on either side
/// and covers nothing, even an equal invalid path.
///
/// An empty path on either side covers nothing.
pub fn path_covers(registered: &[PathSeg], requested: &[PathSeg], mdoc: bool) -> bool {
    if registered.is_empty() || requested.is_empty() {
        return false;
    }
    if mdoc {
        return valid_claim_path(FORMAT_MSO_MDOC, requested) && registered == requested;
    }
    registered.len() <= requested.len()
        && registered
            .iter()
            .zip(requested)
            .all(|(r, q)| r == q || (*r == PathSeg::All && matches!(q, PathSeg::Index(_))))
}

/// The credential types a DCQL credential query of `format` accepts, read from
/// its `meta` (OpenID4VP 1.0 appendix B.2.3 `doctype_value` for `mso_mdoc`,
/// appendix B.3.5 `vct_values` otherwise). Empty when the type is missing or
/// malformed: such a request may be answered with any type, so it matches no
/// registered credential (fail closed).
pub fn requested_types(format: &str, meta: &serde_json::Map<String, Value>) -> Vec<String> {
    if format == FORMAT_MSO_MDOC {
        return meta
            .get("doctype_value")
            .and_then(Value::as_str)
            .map(|d| vec![d.to_string()])
            .unwrap_or_default();
    }
    string_array(meta.get("vct_values")).unwrap_or_default()
}

/// A non-empty array of strings, or `None` when absent, empty, or when any
/// element is not a string (the whole array is rejected, not filtered).
fn string_array(v: Option<&Value>) -> Option<Vec<String>> {
    let arr = v?.as_array()?;
    if arr.is_empty() {
        return None;
    }
    arr.iter().map(|s| s.as_str().map(String::from)).collect()
}

/// One credential a relying party is authorized to request.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredCredential {
    pub format: String,
    /// SD-JWT VC types (`meta.vct_values`); empty when absent or malformed.
    pub vct_values: Vec<String>,
    /// The mdoc doctype (`meta.doctype_value`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype_value: Option<String>,
    /// Authorized claims path pointers. A registered path that is not a valid
    /// pointer is dropped when decoding, so it authorizes nothing.
    pub claims: Vec<Vec<PathSeg>>,
}

impl RegisteredCredential {
    /// Dotted keys of the authorized claims, e.g. `age_equal_or_over.18`, with
    /// null shown as `*`. For display only: coverage uses [`path_covers`].
    pub fn claim_keys(&self) -> Vec<String> {
        self.claims.iter().map(|p| display_path(p)).collect()
    }

    /// Whether this is an `mso_mdoc` credential.
    pub fn is_mdoc(&self) -> bool {
        self.format == FORMAT_MSO_MDOC
    }

    /// Whether this registered credential is of `format` and type
    /// `credential_type` (the doctype for `mso_mdoc`, one of the `vct_values`
    /// otherwise). Types are compared as exact strings; SD-JWT VC type
    /// inheritance and `aka_vcts` are not evaluated.
    pub fn has_type(&self, format: &str, credential_type: &str) -> bool {
        self.format == format
            && if self.is_mdoc() {
                self.doctype_value.as_deref() == Some(credential_type)
            } else {
                self.vct_values.iter().any(|v| v == credential_type)
            }
    }

    /// Canonical fingerprint over (format, sorted vct_values, doctype_value,
    /// sorted claim paths as JSON). This is set-membership oriented (is every
    /// requested claim authorized), which is what an over-ask check needs; it
    /// deliberately does not preserve DCQL array order the way an exact-match
    /// cache key would. Paths keep their typed segments, so `["a", 0]`,
    /// `["a", "0"]` and `["a.0"]` differ.
    pub fn fingerprint(&self) -> String {
        let mut vcts = self.vct_values.clone();
        vcts.sort();
        let mut paths: Vec<String> = self
            .claims
            .iter()
            .map(|p| serde_json::to_string(p).unwrap_or_default())
            .collect();
        paths.sort();
        format!(
            "{}|{}|{}|{}",
            self.format,
            vcts.join(","),
            self.doctype_value.as_deref().unwrap_or(""),
            paths.join(",")
        )
    }
}

/// The registered scope read from a registration certificate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredScope {
    pub purpose: Vec<LangString>,
    pub privacy_policy: Option<String>,
    pub support_uri: Option<String>,
    pub credentials: Vec<RegisteredCredential>,
}

impl RegisteredScope {
    /// The purpose text, preferring an English locale, else the first entry.
    pub fn purpose_text(&self) -> Option<&str> {
        self.purpose
            .iter()
            .find(|p| p.lang.starts_with("en"))
            .or_else(|| self.purpose.first())
            .map(|p| p.content.as_str())
    }

    /// Every authorized claim key across all credentials (display only).
    pub fn all_claim_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .credentials
            .iter()
            .flat_map(|c| c.claim_keys())
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// Whether a credential of the given format and type is registered at all.
    pub fn authorizes_vct(&self, format: &str, vct: &str) -> bool {
        self.credentials.iter().any(|c| c.has_type(format, vct))
    }

    /// Whether `path` of a credential of `format` and type `credential_type`
    /// is within the registration: some registered credential of that same
    /// format and type has a claim path that covers it ([`path_covers`]).
    /// Entries of the same format and type add up path by path; a path never
    /// borrows authorization from a credential of another format or type.
    pub fn covers(&self, format: &str, credential_type: &str, path: &[PathSeg]) -> bool {
        let mdoc = format == FORMAT_MSO_MDOC;
        self.credentials
            .iter()
            .filter(|c| c.has_type(format, credential_type))
            .any(|c| c.claims.iter().any(|r| path_covers(r, path, mdoc)))
    }
}

/// Decode the payload of a WRPRC JWT (no signature check) into a scope.
pub fn decode_registration_jwt(jwt: &str) -> Result<RegisteredScope> {
    let payload_b64 = jwt.split('.').nth(1).context("not a compact JWT")?;
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("invalid base64url payload")?;
    let payload: Value = serde_json::from_slice(&bytes).context("payload not JSON")?;
    scope_from_payload(&payload)
}

/// Build the registered scope from a decoded WRPRC payload.
pub fn scope_from_payload(payload: &Value) -> Result<RegisteredScope> {
    let purpose = payload
        .get("purpose")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_lang_string).collect())
        .unwrap_or_default();

    let credentials = payload
        .get("credentials")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_credential).collect())
        .unwrap_or_default();

    Ok(RegisteredScope {
        purpose,
        privacy_policy: str_field(payload, "privacy_policy"),
        support_uri: str_field(payload, "support_uri"),
        credentials,
    })
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(String::from)
}

fn parse_lang_string(v: &Value) -> Option<LangString> {
    Some(LangString {
        lang: v.get("lang")?.as_str()?.to_string(),
        content: v.get("content")?.as_str()?.to_string(),
    })
}

fn parse_credential(v: &Value) -> Option<RegisteredCredential> {
    let format = v.get("format")?.as_str()?.to_string();
    let meta = v.get("meta");
    let vct_values = string_array(meta.and_then(|m| m.get("vct_values"))).unwrap_or_default();
    let doctype_value = meta
        .and_then(|m| m.get("doctype_value"))
        .and_then(Value::as_str)
        .map(String::from);

    // The registrar payload uses the singular key `claim`; accept `claims` too.
    // A path that is not a valid claims path pointer is dropped (fail closed).
    let claims = v
        .get("claim")
        .or_else(|| v.get("claims"))
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("path").and_then(parse_claim_path))
                .collect()
        })
        .unwrap_or_default();

    Some(RegisteredCredential {
        format,
        vct_values,
        doctype_value,
        claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn path(v: Value) -> Vec<PathSeg> {
        parse_claim_path(&v).expect("valid path")
    }

    fn covers(registered: Value, requested: Value) -> bool {
        path_covers(&path(registered), &path(requested), false)
    }

    #[test]
    fn parse_claim_path_keeps_types_and_rejects_invalid_segments() {
        assert_eq!(
            path(json!(["a", 0, null])),
            vec![PathSeg::Key("a".into()), PathSeg::Index(0), PathSeg::All]
        );
        for bad in [
            json!([]),
            json!("a"),
            json!(["a", true]),
            json!(["a", -1]),
            json!(["a", 1.5]),
            json!(["a", ["b"]]),
            json!(["a", { "b": 1 }]),
        ] {
            assert!(parse_claim_path(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn typed_segments_serialize_back_to_json() {
        let p = path(json!(["nationalities", null, 2, "x"]));
        assert_eq!(
            serde_json::to_value(&p).expect("json"),
            json!(["nationalities", null, 2, "x"])
        );
        assert_eq!(display_path(&p), "nationalities.*.2.x");
    }

    #[test]
    fn json_path_coverage_rules() {
        // Equal paths, null segments included.
        assert!(covers(json!(["n", null]), json!(["n", null])));
        // A requested index under a registered null.
        assert!(covers(json!(["n", null]), json!(["n", 3])));
        assert!(covers(json!(["d", null, "t"]), json!(["d", 0, "t"])));
        // A requested null under a registered index.
        assert!(!covers(json!(["n", 0]), json!(["n", null])));
        assert!(!covers(json!(["n", 0]), json!(["n", 1])));
        // Child of a registered parent, not the parent of a registered child.
        assert!(covers(json!(["address"]), json!(["address", "locality"])));
        assert!(!covers(json!(["address", "locality"]), json!(["address"])));
        // Type and spelling differences.
        assert!(!covers(json!(["n", "0"]), json!(["n", 0])));
        assert!(!covers(json!(["n", 0]), json!(["n", "0"])));
        assert!(!covers(json!(["n", "*"]), json!(["n", null])));
        assert!(!covers(
            json!(["address", "locality"]),
            json!(["address.locality"])
        ));
        assert!(!covers(
            json!(["address.locality"]),
            json!(["address", "locality"])
        ));
    }

    #[test]
    fn empty_registered_path_covers_nothing() {
        for requested in [json!(["a"]), json!(["a", 0]), json!(["a", null])] {
            assert!(
                !path_covers(&[], &path(requested.clone()), false),
                "{requested}"
            );
            assert!(!path_covers(&[], &path(requested), true));
        }
        assert!(!path_covers(&path(json!(["a"])), &[], false));
    }

    #[test]
    fn mdoc_paths_cover_only_equal_paths() {
        let reg = path(json!(["org.example.ns1", "member_name"]));
        assert!(path_covers(&reg, &reg, true));
        for requested in [
            json!(["org.example.ns2", "member_name"]),
            json!(["org.example", "ns1.member_name"]),
            json!(["org.example.ns1", null]),
            json!(["org.example.ns1", "member_name", "x"]),
        ] {
            assert!(
                !path_covers(&reg, &path(requested.clone()), true),
                "{requested}"
            );
        }
        let ns_only = path(json!(["org.example.ns1"]));
        assert!(!path_covers(&ns_only, &reg, true));
    }

    #[test]
    fn equal_invalid_mdoc_paths_cover_nothing() {
        for invalid in [
            json!(["org.example.ns1", null]),
            json!(["org.example.ns1", 0]),
            json!(["org.example.ns1"]),
            json!(["org.example.ns1", "member_name", "town"]),
        ] {
            let p = path(invalid.clone());
            assert!(!valid_claim_path(FORMAT_MSO_MDOC, &p), "{invalid}");
            assert!(!path_covers(&p, &p, true), "{invalid}");
            // The same segments are a valid JSON pointer for other formats.
            assert!(valid_claim_path("dc+sd-jwt", &p), "{invalid}");
        }
        assert!(valid_claim_path(
            FORMAT_MSO_MDOC,
            &path(json!(["org.example.ns1", "member_name"]))
        ));
        assert!(!valid_claim_path("dc+sd-jwt", &[]));
    }

    fn scope(credentials: Value) -> RegisteredScope {
        scope_from_payload(&json!({ "credentials": credentials })).expect("scope")
    }

    #[test]
    fn covers_matches_format_and_type_before_paths() {
        let s = scope(json!([
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:a:1"] },
              "claim": [{ "path": ["x"] }] },
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:a:1"] },
              "claim": [{ "path": ["y"] }] },
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:b:1"] },
              "claim": [{ "path": ["z"] }] },
            { "format": "mso_mdoc", "meta": { "doctype_value": "org.example.d.1" },
              "claim": [{ "path": ["org.example.ns1", "x"] }] },
        ]));
        let p = |v: Value| path(v);
        // Same-type entries add up path by path.
        assert!(s.covers("dc+sd-jwt", "urn:example:a:1", &p(json!(["x"]))));
        assert!(s.covers("dc+sd-jwt", "urn:example:a:1", &p(json!(["y"]))));
        // No borrowing from another type or format.
        assert!(!s.covers("dc+sd-jwt", "urn:example:a:1", &p(json!(["z"]))));
        assert!(!s.covers("vc+sd-jwt", "urn:example:a:1", &p(json!(["x"]))));
        assert!(!s.covers(
            "dc+sd-jwt",
            "org.example.d.1",
            &p(json!(["org.example.ns1", "x"]))
        ));
        assert!(s.covers(
            "mso_mdoc",
            "org.example.d.1",
            &p(json!(["org.example.ns1", "x"]))
        ));
        assert!(!s.covers(
            "mso_mdoc",
            "org.example.e.1",
            &p(json!(["org.example.ns1", "x"]))
        ));
        assert!(s.authorizes_vct("mso_mdoc", "org.example.d.1"));
        assert!(!s.authorizes_vct("mso_mdoc", "urn:example:a:1"));
    }

    #[test]
    fn malformed_registered_metadata_and_paths_authorize_nothing() {
        let s = scope(json!([
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:a:1", 7] },
              "claim": [{ "path": ["x"] }] },
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:b:1"] },
              "claim": [{ "path": [] }, { "path": ["y", true] }, { "path": "y" }] },
        ]));
        assert!(s.credentials[0].vct_values.is_empty());
        assert!(!s.covers("dc+sd-jwt", "urn:example:a:1", &path(json!(["x"]))));
        assert!(s.credentials[1].claims.is_empty());
        assert!(!s.covers("dc+sd-jwt", "urn:example:b:1", &path(json!(["y"]))));
    }

    #[test]
    fn requested_types_fail_closed() {
        let meta = |v: Value| v.as_object().cloned().expect("object");
        assert_eq!(
            requested_types("dc+sd-jwt", &meta(json!({ "vct_values": ["a", "b"] }))),
            vec!["a", "b"]
        );
        assert!(requested_types("dc+sd-jwt", &meta(json!({}))).is_empty());
        assert!(requested_types("dc+sd-jwt", &meta(json!({ "vct_values": [] }))).is_empty());
        assert!(requested_types("dc+sd-jwt", &meta(json!({ "vct_values": ["a", 1] }))).is_empty());
        assert_eq!(
            requested_types("mso_mdoc", &meta(json!({ "doctype_value": "d" }))),
            vec!["d"]
        );
        assert!(requested_types("mso_mdoc", &meta(json!({ "vct_values": ["d"] }))).is_empty());
    }

    #[test]
    fn fingerprint_includes_doctype_and_typed_paths() {
        let one = |doctype: &str, p: Value| {
            scope(
                json!([{ "format": "mso_mdoc", "meta": { "doctype_value": doctype },
                           "claim": [{ "path": p }] }]),
            )
            .credentials[0]
                .fingerprint()
        };
        assert_ne!(one("d1", json!(["n", "e"])), one("d2", json!(["n", "e"])));
        let sd = |p: Value| {
            scope(
                json!([{ "format": "dc+sd-jwt", "meta": { "vct_values": ["v"] },
                           "claim": [{ "path": p }] }]),
            )
            .credentials[0]
                .fingerprint()
        };
        assert_ne!(sd(json!(["a", 0])), sd(json!(["a", "0"])));
        assert_ne!(sd(json!(["a", "b"])), sd(json!(["a.b"])));
    }
}
