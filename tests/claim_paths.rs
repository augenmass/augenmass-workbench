//! Claims path pointer coverage: the shared vectors in
//! `fixtures/claim-paths/path-vectors.json` and the property that a request
//! built from exactly the registered claims of every registration fixture in
//! the repository is never flagged as beyond the registration.
//!
//! The harness drives the public engine entry point (`inspector::analyze`)
//! with a registered scope decoded from a registration payload, so the vectors
//! exercise the same comparison the `audit` and `check` commands use.

use std::fs;
use std::path::Path;

use augenmass_core::inspector::{self, ClaimStatus, OverAskReport};
use augenmass_core::regcert;
use base64::prelude::*;
use openid4vp::core::dcql_query::DcqlQuery;
use serde_json::{json, Value};

const VECTORS: &str = "fixtures/claim-paths/path-vectors.json";

fn read_json(path: &str) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn vectors() -> Value {
    read_json(VECTORS)
}

/// A registration payload with one entry per registered credential.
fn registration(credentials: &[Value]) -> Value {
    json!({
        "purpose": [{ "lang": "en", "content": "Example Rowing Club membership check" }],
        "privacy_policy": "https://club.example.org/privacy",
        "support_uri": "support@club.example.org",
        "credentials": credentials,
    })
}

fn registered_credential(format: &str, meta: &Value, paths: &[Value]) -> Value {
    json!({
        "format": format,
        "meta": meta,
        "claim": paths.iter().map(|p| json!({ "path": p })).collect::<Vec<_>>(),
    })
}

/// The dotted display key the report uses for a requested path.
fn display_key(path: &Value) -> String {
    path.as_array()
        .expect("path array")
        .iter()
        .map(|seg| match seg {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Null => "*".to_string(),
            other => panic!("segment {other}"),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn analyze(payload: &Value, request: Value) -> Result<OverAskReport, serde_json::Error> {
    let query: DcqlQuery = serde_json::from_value(request)?;
    let scope = regcert::scope_from_payload(payload).expect("registration payload decodes");
    Ok(inspector::analyze(
        "urn:example:membership:1",
        &query,
        Some(&scope),
        None,
        &[],
    ))
}

fn result_of(status: ClaimStatus) -> &'static str {
    if status == ClaimStatus::BeyondRegistration {
        "not_covered"
    } else {
        "covered"
    }
}

/// The result of one pointer case: `invalid` when the request does not parse
/// as DCQL or its path is not a valid claims path pointer for the format
/// (`regcert::valid_claim_path`); an invalid path that parses must still be
/// reported beyond the registration, never covered.
fn pointer_case_result(case: &Value, meta: &Value) -> (String, Option<OverAskReport>) {
    let format = case["format"].as_str().expect("format");
    let valid = regcert::parse_claim_path(&case["requested"])
        .is_some_and(|segs| regcert::valid_claim_path(format, &segs));
    let meta = &meta[format];
    let registered: Vec<Value> = case["registered"].as_array().expect("registered").clone();
    let payload = registration(&[registered_credential(format, meta, &registered)]);
    let request = json!({ "credentials": [{
        "id": "req",
        "format": format,
        "meta": meta,
        "claims": [{ "path": case["requested"] }],
    }]});
    match analyze(&payload, request) {
        Err(_) => ("invalid".to_string(), None),
        Ok(report) => {
            assert_eq!(
                report.requested.len(),
                1,
                "{}: one verdict row expected, got {:?}",
                case["id"],
                report.requested
            );
            let result = result_of(report.requested[0].status);
            if !valid {
                assert_eq!(
                    result, "not_covered",
                    "{}: an invalid path must never be covered",
                    case["id"]
                );
                return ("invalid".to_string(), Some(report));
            }
            (result.to_string(), Some(report))
        }
    }
}

/// Run every pointer case and return the ids whose result differs.
fn failing_pointer_cases() -> Vec<String> {
    let v = vectors();
    let meta = &v["pointer_defaults"]["meta"];
    let mut failing = Vec::new();
    for case in v["pointer_cases"].as_array().expect("pointer_cases") {
        let (got, _) = pointer_case_result(case, meta);
        if got != case["expected"].as_str().expect("expected") {
            failing.push(format!(
                "{}: expected {}, got {got}",
                case["id"].as_str().unwrap_or("?"),
                case["expected"]
            ));
        }
    }
    failing
}

fn credential_case_failures(case: &Value) -> Vec<String> {
    let id = case["id"].as_str().expect("id");
    let registered: Vec<Value> = case["registered"]
        .as_array()
        .expect("registered")
        .iter()
        .map(|c| {
            registered_credential(
                c["format"].as_str().expect("format"),
                &c["meta"],
                c["claims"].as_array().expect("claims"),
            )
        })
        .collect();
    let payload = registration(&registered);

    let req = &case["request"];
    let mut credential = json!({
        "id": "req",
        "format": req["format"],
        "meta": req["meta"],
    });
    if let Some(claims) = req.get("claims").and_then(Value::as_array) {
        let claims: Vec<Value> = claims
            .iter()
            .map(|c| {
                if c.is_array() {
                    json!({ "path": c })
                } else {
                    c.clone()
                }
            })
            .collect();
        credential["claims"] = Value::Array(claims);
    }
    if let Some(sets) = req.get("claim_sets") {
        credential["claim_sets"] = sets.clone();
    }
    let report = match analyze(&payload, json!({ "credentials": [credential] })) {
        Ok(report) => report,
        Err(e) => return vec![format!("{id}: request does not parse: {e}")],
    };

    let expected = case["expected"].as_array().expect("expected");
    let mut failures = Vec::new();
    if let [only] = expected.as_slice() {
        if only["path"].is_null() {
            let beyond = report
                .requested
                .iter()
                .any(|v| v.status == ClaimStatus::BeyondRegistration);
            let got = if beyond { "not_covered" } else { "covered" };
            if got != only["result"] {
                failures.push(format!(
                    "{id}: credential expected {}, got {got}",
                    only["result"]
                ));
            }
            return failures;
        }
    }
    if report.requested.len() != expected.len() {
        failures.push(format!(
            "{id}: expected {} audited paths, got {}: {:?}",
            expected.len(),
            report.requested.len(),
            report
                .requested
                .iter()
                .map(|v| v.key.as_str())
                .collect::<Vec<_>>()
        ));
        return failures;
    }
    for (row, want) in report.requested.iter().zip(expected) {
        let key = display_key(&want["path"]);
        if row.key != key {
            failures.push(format!("{id}: expected row {key}, got {}", row.key));
        } else if result_of(row.status) != want["result"] {
            failures.push(format!(
                "{id}: {key} expected {}, got {}",
                want["result"],
                result_of(row.status)
            ));
        }
    }
    failures
}

/// The result of one query case: the failures, empty when it holds. The
/// query is parsed by the binary's own DCQL parser (`dcql::parse_dcql`), which
/// rejects an empty credential set option before any audit.
fn query_case_failures(case: &Value) -> Vec<String> {
    let id = case["id"].as_str().expect("id");
    let registered: Vec<Value> = case["registered"]
        .as_array()
        .expect("registered")
        .iter()
        .map(|c| {
            registered_credential(
                c["format"].as_str().expect("format"),
                &c["meta"],
                c["claims"].as_array().expect("claims"),
            )
        })
        .collect();
    let payload = registration(&registered);
    let parsed = augenmass_workbench::dcql::parse_dcql(&case["query"].to_string());

    if case["expected"] == "malformed" {
        return match parsed {
            Err(e) if format!("{e:#}").contains("section 6.2") => Vec::new(),
            Err(e) => vec![format!("{id}: rejected without citing section 6.2: {e:#}")],
            Ok(_) => vec![format!("{id}: expected malformed, but the query parses")],
        };
    }
    let query = match parsed {
        Ok(query) => query,
        Err(e) => return vec![format!("{id}: query does not parse: {e:#}")],
    };
    let mut failures = Vec::new();

    // The rows carry no credential id, so the case itself must tie each
    // expected row to exactly one credential query, by a path only that
    // credential query requests, in declaration order.
    let declared = case["query"]["credentials"]
        .as_array()
        .expect("query.credentials");
    let expected = case["expected"].as_array().expect("expected list");
    let mut last_index = 0;
    for want in expected {
        let named: Vec<usize> = declared
            .iter()
            .enumerate()
            .filter(|(_, c)| c["id"] == want["credential"])
            .map(|(i, _)| i)
            .collect();
        let [index] = named.as_slice() else {
            failures.push(format!(
                "{id}: {} must name exactly one credential query",
                want["credential"]
            ));
            continue;
        };
        let carries = |c: &Value| {
            c["claims"]
                .as_array()
                .is_some_and(|claims| claims.iter().any(|claim| claim["path"] == want["path"]))
        };
        if !carries(&declared[*index]) {
            failures.push(format!(
                "{id}: {} does not request {}",
                want["credential"], want["path"]
            ));
        }
        if declared
            .iter()
            .enumerate()
            .any(|(i, c)| i != *index && carries(c))
        {
            failures.push(format!(
                "{id}: path {} is also requested by a credential query other than {}",
                want["path"], want["credential"]
            ));
        }
        if *index < last_index {
            failures.push(format!(
                "{id}: rows must follow the declaration order of query.credentials"
            ));
        }
        last_index = *index;
    }

    let scope = regcert::scope_from_payload(&payload).expect("registration payload decodes");
    let report = inspector::analyze("urn:example:membership:1", &query, Some(&scope), None, &[]);
    if report.requested.len() != expected.len() {
        failures.push(format!(
            "{id}: expected {} audited paths, got {}: {:?}",
            expected.len(),
            report.requested.len(),
            report
                .requested
                .iter()
                .map(|v| v.key.as_str())
                .collect::<Vec<_>>()
        ));
        return failures;
    }
    for (row, want) in report.requested.iter().zip(expected) {
        let key = display_key(&want["path"]);
        if row.key != key {
            failures.push(format!("{id}: expected row {key}, got {}", row.key));
        } else if result_of(row.status) != want["result"] {
            failures.push(format!(
                "{id}: {key} expected {}, got {}",
                want["result"],
                result_of(row.status)
            ));
        }
    }
    failures
}

/// SHA-256 over every version 1 key that defines an input or an expected
/// result. A minor version step adds cases and never changes these.
fn version_1_digest(v: &Value) -> String {
    use sha2::{Digest, Sha256};
    let frozen = json!([
        v["specification"],
        v["semantics"],
        v["results"],
        v["pointer_defaults"],
        v["pointer_cases"],
        v["credential_cases_description"],
        v["credential_cases"],
    ]);
    let text = serde_json::to_string(&frozen).expect("serialize");
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// [`version_1_digest`] of the version 1 file shipped in 0.4.0 (SHA-256 of
/// that file: b865299887cb6400d0d3f069d5bfc787a44cfc94ec36a3c15e8e274c81ea8146).
const VERSION_1_DIGEST: &str = "aa59a96c43d027c4bee7bcd064998136d45c3e64b8b3592527c0a6409aaff3e5";

#[test]
fn path_vectors_version_1_cases_are_unchanged() {
    assert_eq!(version_1_digest(&vectors()), VERSION_1_DIGEST);
}

#[test]
fn path_vectors_ids_are_unique_and_version_is_1_1() {
    let v = vectors();
    assert_eq!(v["version"], "1.1");
    let mut ids: Vec<&str> = Vec::new();
    for list in ["pointer_cases", "credential_cases", "query_cases"] {
        for case in v[list].as_array().expect(list) {
            let id = case["id"].as_str().expect("id");
            assert!(!ids.contains(&id), "duplicate case id {id}");
            ids.push(id);
        }
    }
    assert_eq!(ids.len(), 39 + 19 + 5);
}

#[test]
fn path_vectors_query_cases_hold() {
    let v = vectors();
    let cases = v["query_cases"].as_array().expect("query_cases");
    assert!(cases.iter().any(|c| c["expected"] == "malformed"));
    assert!(cases.iter().any(|c| c["expected"].is_array()));
    let failing: Vec<String> = cases.iter().flat_map(query_case_failures).collect();
    assert!(
        failing.is_empty(),
        "failing query cases:\n{}",
        failing.join("\n")
    );
}

#[test]
fn path_vectors_header_states_licence_and_reuse() {
    let v = vectors();
    assert_eq!(v["licence"], "Apache-2.0");
    assert!(v["reuse"].as_str().is_some_and(|s| s.contains("reuse")));
    assert!(v["query_cases_description"].is_string());
    for case in v["pointer_cases"]
        .as_array()
        .expect("pointer_cases")
        .iter()
        .chain(v["credential_cases"].as_array().expect("credential_cases"))
        .chain(v["query_cases"].as_array().expect("query_cases"))
    {
        for field in ["id", "expected", "reason", "section"] {
            assert!(!case[field].is_null(), "{}: missing {field}", case["id"]);
        }
        assert!(
            case["section"]
                .as_str()
                .is_some_and(|s| s.contains("OpenID4VP")),
            "{}: section names the specification",
            case["id"]
        );
    }
    for case in v["pointer_cases"].as_array().expect("pointer_cases") {
        for field in ["format", "registered", "requested"] {
            assert!(
                !case[field].is_null() || field == "requested",
                "{}: {field}",
                case["id"]
            );
        }
        let expected = case["expected"].as_str().expect("expected");
        assert!(["covered", "not_covered", "invalid"].contains(&expected));
    }
}

#[test]
fn path_vectors_use_invented_names_only() {
    let text = fs::read_to_string(VECTORS).expect("vectors");
    for real in [
        "urn:eudi",
        "eu.europa",
        "org.iso",
        "given_name",
        "family_name",
    ] {
        assert!(
            !text.contains(real),
            "vectors name a real identifier: {real}"
        );
    }
}

#[test]
fn path_vectors_pointer_cases_hold() {
    let failing = failing_pointer_cases();
    assert!(
        failing.is_empty(),
        "failing pointer cases:\n{}",
        failing.join("\n")
    );
}

#[test]
fn path_vectors_credential_cases_hold() {
    let v = vectors();
    let failing: Vec<String> = v["credential_cases"]
        .as_array()
        .expect("credential_cases")
        .iter()
        .flat_map(credential_case_failures)
        .collect();
    assert!(
        failing.is_empty(),
        "failing credential cases:\n{}",
        failing.join("\n")
    );
}

// --- property over every registration fixture -------------------------------

/// Every registration fixture in the repository, as (path, payload).
const REGISTRATION_FIXTURES: &[&str] = &[
    "fixtures/regcert/rc-by-id.json",
    "fixtures/regcert/rc-payload.json",
    "examples/min.json",
    "examples/over.json",
    "fixtures/claim-paths/rc-null-segment.jwt",
    "fixtures/claim-paths/registration-structured.json",
    "examples/age-broad-registration.jwt",
    "examples/age-broad-registration.payload.json",
    "examples/merged-path-registration.jwt",
    "examples/merged-path-registration.payload.json",
    "fixtures/hub-shape/registration-hub-shape.jwt",
    "fixtures/hub-shape/registration-hub-shape.payload.json",
];

/// Files in the scanned directories that are not registrations, with the reason.
const NOT_REGISTRATIONS: &[(&str, &str)] = &[
    (
        "examples/bad-path.json",
        "string path, rejected by check as CHECK-PATH-STRING",
    ),
    (
        "examples/bad-request.json",
        "a signed request, not a registration",
    ),
    (
        "examples/kyc-request-plus-birthdate.json",
        "a DCQL request, not a registration",
    ),
    (
        "examples/age-broad-request.json",
        "a DCQL request, not a registration",
    ),
    (
        "examples/age-minimal-request-sdjwt.json",
        "a DCQL request, not a registration",
    ),
    (
        "examples/age-minimal-request-mdoc.json",
        "a DCQL request, not a registration",
    ),
    (
        "examples/merged-path-request.json",
        "a DCQL request, not a registration",
    ),
    ("fixtures/claim-paths/path-vectors.json", "the vector set"),
    (
        "fixtures/claim-paths/request-identical.json",
        "a DCQL request, not a registration",
    ),
];

fn jwt_payload(jwt: &str) -> Value {
    let b64 = jwt.trim().split('.').nth(1).expect("compact JWT");
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(b64)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("payload JSON")
}

fn registration_payload(path: &str) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    if path.ends_with(".jwt") {
        return jwt_payload(&text);
    }
    let value: Value = serde_json::from_str(&text).expect("JSON");
    match value.get("jwt").and_then(Value::as_str) {
        Some(jwt) => jwt_payload(jwt),
        None => value,
    }
}

/// A DCQL request with one credential per registered credential, carrying the
/// registered format, type and exactly the registered claim paths.
fn request_from_registration(payload: &Value) -> (Value, usize) {
    let mut total = 0;
    let credentials: Vec<Value> = payload["credentials"]
        .as_array()
        .expect("credentials")
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut meta = serde_json::Map::new();
            for key in ["vct_values", "doctype_value"] {
                if let Some(v) = c["meta"].get(key) {
                    meta.insert(key.to_string(), v.clone());
                }
            }
            let claims: Vec<Value> = c
                .get("claim")
                .or_else(|| c.get("claims"))
                .and_then(Value::as_array)
                .expect("claims")
                .iter()
                .map(|claim| json!({ "path": claim["path"] }))
                .collect();
            total += claims.len();
            json!({ "id": format!("c{i}"), "format": c["format"], "meta": meta, "claims": claims })
        })
        .collect();
    (json!({ "credentials": credentials }), total)
}

#[test]
fn registration_fixtures_list_is_complete() {
    for dir in [
        "fixtures/regcert",
        "examples",
        "fixtures/claim-paths",
        "fixtures/hub-shape",
    ] {
        for entry in fs::read_dir(dir).expect("dir") {
            let path = entry.expect("entry").path();
            let rel = path.to_string_lossy().replace('\\', "/");
            assert!(
                REGISTRATION_FIXTURES.contains(&rel.as_str())
                    || NOT_REGISTRATIONS.iter().any(|(p, _)| *p == rel),
                "unclassified fixture {rel}: add it to REGISTRATION_FIXTURES or NOT_REGISTRATIONS"
            );
        }
    }
    for path in REGISTRATION_FIXTURES {
        assert!(Path::new(path).is_file(), "{path}");
    }
}

#[test]
fn request_of_exactly_the_registered_claims_is_never_flagged() {
    for path in REGISTRATION_FIXTURES {
        let payload = registration_payload(path);
        let (request, total) = request_from_registration(&payload);
        let report = analyze(&payload, request).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert!(total > 0, "{path}: no registered claims");
        assert_eq!(report.counts.requested, total, "{path}");
        assert_eq!(
            report.counts.beyond_registration, 0,
            "{path}: {:?}",
            report.requested
        );
    }
}

/// A compact certificate and the readable payload file that documents it.
const READABLE_PAYLOAD_PAIRS: &[(&str, &str)] = &[
    (
        "examples/age-broad-registration.jwt",
        "examples/age-broad-registration.payload.json",
    ),
    (
        "examples/merged-path-registration.jwt",
        "examples/merged-path-registration.payload.json",
    ),
    (
        "fixtures/hub-shape/registration-hub-shape.jwt",
        "fixtures/hub-shape/registration-hub-shape.payload.json",
    ),
];

#[test]
fn readable_payload_files_match_their_certificates() {
    for (jwt, payload) in READABLE_PAYLOAD_PAIRS {
        let text = fs::read_to_string(jwt).unwrap_or_else(|e| panic!("read {jwt}: {e}"));
        assert_eq!(
            jwt_payload(&text),
            read_json(payload),
            "{jwt} and {payload}"
        );
    }
}
