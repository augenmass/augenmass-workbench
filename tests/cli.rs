//! End-to-end CLI tests against the committed offline fixtures. These pin the
//! observable behavior of every read-only command (detection, decoding,
//! verification, over-ask, exit codes) so refactors cannot silently regress it.
//! The registrar write path (register/list/clone) needs a live local server and
//! is exercised by `just verify` and the `clone_server` unit test, not here.

use assert_cmd::Command;
use augenmass_core::crypto::{encrypt_jwe, generate_response_encryption_key_pair};
use base64::prelude::*;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::DecodePrivateKey;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

// Shared binding values for the ERICA / synthetic fixtures (see fixtures MANIFEST).
const NONCE: &str = "b4ba2623-76a2-486b-a1f6-f1656025d07b";
const AUD: &str = "https://self-issued.me/v2";
const NOW: &str = "1780435200";
const STATUS_KEY: &str = "fixtures/status/status-list-verify-key.pub.pem";

fn bin() -> Command {
    Command::cargo_bin("augenmass").expect("binary builds")
}

fn test_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_evidence_source_artifact(
    dir: &Path,
    filename: &str,
    label: &str,
    text: &str,
) -> serde_json::Value {
    fs::write(dir.join(filename), text).expect("write evidence source artifact");
    json!({
        "label": label,
        "filename": filename,
        "path": dir.join(filename).display().to_string(),
        "len": text.len(),
        "sha256": sha256_hex(text.as_bytes()),
    })
}

fn encrypted_direct_post_artifacts(auth_response: &str) -> (String, String) {
    let (private_jwk, public_jwk) =
        generate_response_encryption_key_pair("enc-test").expect("generate response enc key");
    let payload: serde_json::Value =
        serde_json::from_str(auth_response).expect("auth response value");
    let response = encrypt_jwe(&payload, &public_jwk).expect("encrypt direct_post.jwt");
    let private_jwk = serde_json::to_string(&private_jwk).expect("private jwk json");
    (format!("response={response}&state=abc"), private_jwk)
}

fn evidence_source_session() -> PathBuf {
    let dir = test_temp_dir("augenmass-cli-evidence-source");
    fs::create_dir_all(&dir).expect("create evidence source dir");
    let entries = vec![
        write_evidence_source_artifact(
            &dir,
            "request.payload.json",
            "decoded authorization request payload",
            r#"{"client_id":"https://self-issued.me/v2","nonce":"n","client_metadata":{"jwks":{"keys":[{"kid":"enc-1"}]}},"dcql_query":{"credentials":[{"id":"pid"}]}}"#,
        ),
        write_evidence_source_artifact(
            &dir,
            "direct-post.body",
            "raw direct_post form body",
            "vp_token=secret-claim&state=abc",
        ),
        write_evidence_source_artifact(
            &dir,
            "verification-context.json",
            "verification replay context",
            r#"{"nonce":"n","aud":"https://self-issued.me/v2","nowUnix":1780435200,"maxAgeSecs":300,"vct":"urn:eudi:pid:de:1"}"#,
        ),
    ];
    let manifest = json!({
        "schemaVersion": 1,
        "kind": "serve-unsafe-debug-artifacts",
        "session": "11111111-1111-4111-8111-111111111111",
        "sensitive": true,
        "entries": entries,
    });
    fs::write(
        dir.join("debug-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write evidence source manifest");
    dir
}

fn live_evidence_source_session() -> PathBuf {
    let dir = test_temp_dir("augenmass-cli-live-evidence-source");
    fs::create_dir_all(&dir).expect("create live evidence source dir");
    let request_jwt =
        fs::read_to_string("fixtures/requests/eudiplo-request.jwt").expect("read request fixture");
    let presentation = fs::read_to_string("fixtures/presentations/erica-vp-VALID.sdjwt")
        .expect("read presentation fixture");
    let auth_response = serde_json::to_string(&json!({
        "vp_token": presentation.trim(),
        "state": "abc",
    }))
    .expect("auth response json");
    let request_payload = serde_json::to_string(&json!({
        "client_id": AUD,
        "nonce": NONCE,
        "client_metadata": {
            "jwks": {
                "keys": [
                    {"kid": "enc-1"}
                ]
            }
        },
        "dcql_query": {
            "credentials": [
                {"id": "pid"}
            ]
        }
    }))
    .expect("request payload json");
    let verification_context = serde_json::to_string(&json!({
        "nonce": NONCE,
        "aud": AUD,
        "nowUnix": NOW.parse::<i64>().expect("now"),
        "maxAgeSecs": 300,
        "vct": "urn:eudi:pid:de:1",
    }))
    .expect("verification context json");
    let (direct_post_body, private_jwk) = encrypted_direct_post_artifacts(&auth_response);
    let entries = vec![
        write_evidence_source_artifact(
            &dir,
            "request.payload.json",
            "decoded authorization request payload",
            &request_payload,
        ),
        write_evidence_source_artifact(
            &dir,
            "request.jwt",
            "signed authorization request JAR",
            request_jwt.trim(),
        ),
        write_evidence_source_artifact(
            &dir,
            "direct-post.body",
            "raw direct_post form body",
            &direct_post_body,
        ),
        write_evidence_source_artifact(
            &dir,
            "session-enc-key.jwk",
            "session response encryption private JWK",
            &private_jwk,
        ),
        write_evidence_source_artifact(
            &dir,
            "auth-response.json",
            "decrypted authorization response",
            &auth_response,
        ),
        write_evidence_source_artifact(
            &dir,
            "verification-context.json",
            "verification replay context",
            &verification_context,
        ),
    ];
    let manifest = json!({
        "schemaVersion": 1,
        "kind": "serve-unsafe-debug-artifacts",
        "session": "22222222-2222-4222-8222-222222222222",
        "sensitive": true,
        "entries": entries,
    });
    fs::write(
        dir.join("debug-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write live evidence source manifest");
    dir
}

fn artifact_only_live_evidence_source_session() -> PathBuf {
    let dir = live_evidence_source_session();
    fs::write(
        dir.join("direct-post.body"),
        "response=not-a-real-jwe&state=abc",
    )
    .expect("replace direct_post body");
    fs::remove_file(dir.join("session-enc-key.jwk")).expect("remove session key");

    let manifest_path = dir.join("debug-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest"))
            .expect("manifest json");
    let entries = manifest
        .get_mut("entries")
        .and_then(serde_json::Value::as_array_mut)
        .expect("entries");
    entries.retain(|entry| entry["filename"] != "session-enc-key.jwk");
    for entry in entries {
        if entry["filename"] == "direct-post.body" {
            let text = fs::read_to_string(dir.join("direct-post.body")).expect("body");
            entry["len"] = json!(text.len());
            entry["sha256"] = json!(sha256_hex(text.as_bytes()));
        }
    }
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");
    dir
}

fn status_evidence_source_session() -> PathBuf {
    let presentation = fs::read_to_string("fixtures/presentations/synthetic-pid-with-status.sdjwt")
        .expect("read presentation fixture");
    status_evidence_source_session_with_vp_token(json!(presentation.trim()))
}

fn status_evidence_source_session_with_vp_token(vp_token: serde_json::Value) -> PathBuf {
    let dir = test_temp_dir("augenmass-cli-status-evidence-source");
    fs::create_dir_all(&dir).expect("create status evidence source dir");
    let request_jwt =
        fs::read_to_string("fixtures/requests/eudiplo-request.jwt").expect("read request fixture");
    let auth_response = serde_json::to_string(&json!({
        "vp_token": vp_token,
        "state": "abc",
    }))
    .expect("auth response json");
    let request_payload = serde_json::to_string(&json!({
        "client_id": AUD,
        "nonce": NONCE,
        "client_metadata": {
            "jwks": {
                "keys": [
                    {"kid": "enc-1"}
                ]
            }
        },
        "dcql_query": {
            "credentials": [
                {"id": "pid"}
            ]
        }
    }))
    .expect("request payload json");
    let verification_context = serde_json::to_string(&json!({
        "nonce": NONCE,
        "aud": AUD,
        "nowUnix": NOW.parse::<i64>().expect("now"),
        "maxAgeSecs": 300,
        "vct": "urn:eudi:pid:de:1",
    }))
    .expect("verification context json");
    let (direct_post_body, private_jwk) = encrypted_direct_post_artifacts(&auth_response);
    let entries = vec![
        write_evidence_source_artifact(
            &dir,
            "request.payload.json",
            "decoded authorization request payload",
            &request_payload,
        ),
        write_evidence_source_artifact(
            &dir,
            "request.jwt",
            "signed authorization request JAR",
            request_jwt.trim(),
        ),
        write_evidence_source_artifact(
            &dir,
            "direct-post.body",
            "raw direct_post form body",
            &direct_post_body,
        ),
        write_evidence_source_artifact(
            &dir,
            "session-enc-key.jwk",
            "session response encryption private JWK",
            &private_jwk,
        ),
        write_evidence_source_artifact(
            &dir,
            "auth-response.json",
            "decrypted authorization response",
            &auth_response,
        ),
        write_evidence_source_artifact(
            &dir,
            "verification-context.json",
            "verification replay context",
            &verification_context,
        ),
    ];
    let manifest = json!({
        "schemaVersion": 1,
        "kind": "serve-unsafe-debug-artifacts",
        "session": "33333333-3333-4333-8333-333333333333",
        "sensitive": true,
        "entries": entries,
    });
    fs::write(
        dir.join("debug-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write status evidence source manifest");
    dir
}

// --- inspect / detection ---------------------------------------------------

#[test]
fn inspect_detects_sd_jwt_vc() {
    bin()
        .args(["inspect", "fixtures/presentations/erica-vp-VALID.sdjwt"])
        .assert()
        .success()
        .stderr(contains("SD-JWT VC"))
        .stdout(contains("urn:eudi:pid:de:1"));
}

#[test]
fn inspect_detects_registration_cert_entity() {
    bin()
        .args(["inspect", "fixtures/regcert/rc-by-id.json"])
        .assert()
        .success()
        .stderr(contains("registration certificate"));
}

#[test]
fn inspect_detects_authorization_request() {
    bin()
        .args(["inspect", "fixtures/requests/eudiplo-request.jwt"])
        .assert()
        .success()
        .stdout(contains("x509_hash"))
        .stdout(contains("direct_post.jwt"));
}

#[test]
fn inspect_detects_status_list() {
    bin()
        .args(["inspect", "fixtures/status/status-list-CLEAR.jwt"])
        .assert()
        .success()
        .stdout(contains("status list"));
}

// --- decode ----------------------------------------------------------------

#[test]
fn decode_sd_jwt_reveals_claims() {
    bin()
        .args([
            "decode",
            "sd-jwt",
            "fixtures/presentations/erica-vp-VALID.sdjwt",
        ])
        .assert()
        .success()
        .stdout(contains("given_name"))
        .stdout(contains("family_name"));
}

#[test]
fn decode_regcert_shows_purpose() {
    bin()
        .args(["decode", "regcert", "fixtures/regcert/rc-by-id.json"])
        .assert()
        .success()
        .stdout(contains("age-over-18"));
}

#[test]
fn decode_offer_uri_parses_params() {
    bin()
        .args(["decode", "offer", "fixtures/offers/eudiplo-offer-uri.txt"])
        .assert()
        .success()
        .stdout(contains("request_uri"));
}

// --- check (registration body gate) ----------------------------------------

#[test]
fn check_minimal_is_clean() {
    bin()
        .args(["check", "examples/min.json"])
        .assert()
        .success();
}

#[test]
fn check_over_broad_blocks() {
    bin()
        .args(["check", "examples/over.json"])
        .assert()
        .failure()
        .stdout(contains("OVER-ASK"));
}

#[test]
fn check_bad_path_blocks() {
    bin()
        .args(["check", "examples/bad-path.json"])
        .assert()
        .failure()
        .stdout(contains("CHECK-PATH-STRING"));
}

#[test]
fn check_json_output_is_valid_json() {
    let out = bin()
        .args(["--json", "check", "examples/over.json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["overAsk"], serde_json::Value::Bool(true));
}

// --- cached sandbox target -------------------------------------------------

#[test]
fn cache_serve_help_exposes_loopback_proxy_options() {
    bin()
        .args(["cache", "serve", "--help"])
        .assert()
        .success()
        .stdout(contains("--host"))
        .stdout(contains("--upstream"))
        .stdout(contains("--ttl-secs"))
        .stdout(contains("--timeout-secs"))
        .stdout(contains("--max-entries"))
        .stdout(contains("--admin-token"))
        .stdout(contains("--allowed-rp"))
        .stdout(contains("AUGENMASS_CACHE_ALLOWED_RPS"));
}

#[test]
fn register_cached_sandbox_dry_run_does_not_need_oidc() {
    bin()
        .args([
            "register",
            "examples/min.json",
            "--target",
            "cached-sandbox",
        ])
        .assert()
        .success()
        .stdout(contains("DRY RUN"))
        .stdout(contains("cached-sandbox"));
}

#[test]
fn register_cached_sandbox_confirmed_write_is_refused() {
    bin()
        .args([
            "register",
            "examples/min.json",
            "--target",
            "cached-sandbox",
            "--yes",
        ])
        .assert()
        .failure()
        .stdout(contains("Writing to").not())
        .stderr(contains("cached-sandbox is read-only"));
}

// --- audit (over-ask lint) -------------------------------------------------

#[test]
fn audit_minimal_event_checkin_is_ok() {
    bin()
        .args([
            "audit",
            "--request",
            "minimal",
            "--purpose",
            "event_checkin",
        ])
        .assert()
        .success();
}

#[test]
fn audit_overask_event_checkin_flags() {
    bin()
        .args([
            "audit",
            "--request",
            "overask",
            "--purpose",
            "event_checkin",
        ])
        .assert()
        .failure()
        .stdout(contains("OVER-ASK"));
}

#[test]
fn audit_accepts_wrapped_dcql_fixture() {
    bin()
        .args([
            "audit",
            "--request",
            "fixtures/dcql/eudiplo-haip-pid-de.dcql.json",
            "--purpose",
            "age_gate_18",
        ])
        .assert()
        .failure()
        .stdout(contains("OVER-ASK"))
        .stdout(contains(
            "Suggested minimal request for \"pid-sd-jwt\" (dc+sd-jwt, urn:eudi:pid:de:1), as claim paths:\n  [\"age_equal_or_over\", \"18\"]\n",
        ))
        .stdout(contains(
            "Suggested minimal request for \"pid-mso-mdoc\" (mso_mdoc, eu.europa.ec.eudi.pid.1), as [namespace, element]:\n  [\"eu.europa.ec.eudi.pid.de.1\", \"age_over_18\"] (German PID only)\n",
        ));
}

#[test]
fn audit_accepts_stdin_dcql() {
    let query = bin()
        .args(["generate", "dcql", "--claim", "age_equal_or_over.18"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let query = String::from_utf8(query).expect("utf8");
    bin()
        .args(["audit", "--request", "-", "--purpose", "age_gate_18"])
        .write_stdin(query)
        .assert()
        .success();
}

// --- baselines -------------------------------------------------------------

#[test]
fn baselines_lists_known_ids() {
    bin()
        .args(["baselines"])
        .assert()
        .success()
        .stdout(contains("age_gate_18"))
        .stdout(contains("bank_kyc"));
}

#[test]
fn baselines_text_lists_mdoc_elements_like_the_json() {
    let text = stdout_of(&["baselines"], 0);
    assert!(
        text.contains("    mdoc elements: eu.europa.ec.eudi.pid.1/place_of_birth\n"),
        "{text}"
    );
    let text = stdout_of(&["baselines", "bank_kyc"], 0);
    assert!(
        text.contains("  mdoc elements: eu.europa.ec.eudi.pid.1/place_of_birth\n"),
        "{text}"
    );
    let value: serde_json::Value =
        serde_json::from_str(&stdout_of(&["baselines", "bank_kyc", "--json"], 0)).expect("json");
    assert_eq!(
        value["mdoc_elements"],
        json!([["eu.europa.ec.eudi.pid.1", "place_of_birth"]])
    );
    // Baselines without mdoc elements print no such line.
    let text = stdout_of(&["baselines", "age_gate_18"], 0);
    assert!(!text.contains("mdoc elements"), "{text}");
}

#[test]
fn baselines_bank_kyc_lists_gwg_claims() {
    let out = bin()
        .args(["baselines", "bank_kyc", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("baselines json");
    let keys: Vec<&str> = value["minimal_keys"]
        .as_array()
        .expect("minimal_keys")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "given_name",
            "family_name",
            "birthdate",
            "place_of_birth.locality",
            "place_of_birth.region",
            "place_of_birth.country",
            "nationalities",
            "address.resident_street",
            "address.house_number",
            "address.resident_city",
            "address.resident_postal_code",
            "address.region",
            "address.resident_country",
            "address.formatted",
        ]
    );
    assert_eq!(
        value["mdoc_elements"],
        serde_json::json!([["eu.europa.ec.eudi.pid.1", "place_of_birth"]])
    );
    assert!(value["note"]
        .as_str()
        .expect("note")
        .contains("GwG § 11 Abs. 4 Nr. 1"));
}

/// Regulation (EU) No 910/2014, Article 5b(3), verbatim from the consolidated
/// English text of 18.10.2024.
const ART_5B_3: &str = "Relying parties shall not request users to provide any data other than that indicated pursuant to paragraph 2, point (c).";

#[test]
fn legal_basis_quotes_article_5b_3_verbatim_in_text_and_json() {
    let text = bin()
        .args(["baselines"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(text).expect("utf8");
    assert!(
        text.contains(&format!(
            "  Regulation (EU) No 910/2014, Article 5b(3)\n    {ART_5B_3}\n"
        )),
        "{text}"
    );
    assert!(!text.contains("2024/1183"));

    let out = bin()
        .args(["baselines", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(
        value["legalBasis"][0],
        serde_json::json!({
            "source": "Regulation (EU) No 910/2014",
            "locator": "Article 5b(3)",
            "text": ART_5B_3,
        })
    );

    let out = bin()
        .args([
            "audit",
            "--request",
            "overask",
            "--purpose",
            "age_gate_18",
            "--json",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).expect("audit json");
    assert_eq!(report["legal_basis"][0], value["legalBasis"][0]);

    bin()
        .args(["audit", "--request", "overask", "--purpose", "age_gate_18"])
        .assert()
        .code(1)
        .stdout(contains(format!(
            "  Regulation (EU) No 910/2014, Article 5b(3)\n    {ART_5B_3}\n"
        )));
}

/// The bank_kyc request with every GwG § 11 Abs. 4 Nr. 1 claim, as SD-JWT.
const GWG_SD_JWT_DCQL: &str = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[
{"path":["given_name"]},{"path":["family_name"]},{"path":["birthdate"]},
{"path":["place_of_birth","locality"]},{"path":["nationalities"]},
{"path":["address","resident_street"]},{"path":["address","resident_city"]},
{"path":["address","resident_postal_code"]},{"path":["address","resident_country"]}]}]}"#;

/// The same request with the standard SD-JWT address components of the PID
/// Rulebook (the shape of fixtures/presentations/erica-pid-template-normal.json).
const GWG_SD_JWT_STANDARD_ADDRESS_DCQL: &str = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[
{"path":["given_name"]},{"path":["family_name"]},{"path":["birthdate"]},
{"path":["place_of_birth","locality"]},{"path":["nationalities"]},
{"path":["address","street_address"]},{"path":["address","locality"]},
{"path":["address","postal_code"]},{"path":["address","country"]}]}]}"#;

/// The same request in the EU PID mdoc encoding.
const GWG_MDOC_DCQL: &str = r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[
{"path":["eu.europa.ec.eudi.pid.1","given_name"]},{"path":["eu.europa.ec.eudi.pid.1","family_name"]},
{"path":["eu.europa.ec.eudi.pid.1","birth_date"]},{"path":["eu.europa.ec.eudi.pid.1","birth_place"]},
{"path":["eu.europa.ec.eudi.pid.1","nationality"]},{"path":["eu.europa.ec.eudi.pid.1","resident_street"]},
{"path":["eu.europa.ec.eudi.pid.1","resident_city"]},{"path":["eu.europa.ec.eudi.pid.1","resident_postal_code"]},
{"path":["eu.europa.ec.eudi.pid.1","resident_country"]}]}]}"#;

fn audit_json(
    request: &str,
    purpose: &str,
    cert: Option<&str>,
    success: bool,
) -> serde_json::Value {
    let mut args = vec![
        "audit",
        "--request",
        request,
        "--purpose",
        purpose,
        "--json",
    ];
    if let Some(cert) = cert {
        args.extend(["--cert", cert]);
    }
    let assert = bin().args(&args).assert();
    let assert = if success {
        assert.success()
    } else {
        assert.code(1)
    };
    serde_json::from_slice(&assert.get_output().stdout).expect("audit json")
}

#[test]
fn audit_bank_kyc_gwg_complete_request_passes() {
    for request in [
        GWG_SD_JWT_DCQL,
        GWG_SD_JWT_STANDARD_ADDRESS_DCQL,
        GWG_MDOC_DCQL,
    ] {
        let report = audit_json(request, "bank_kyc", None, true);
        assert_eq!(report["counts"]["requested"], 9);
        assert_eq!(report["counts"]["minimal"], 9);
        assert_eq!(report["counts"]["beyond_purpose"], 0);
    }
}

#[test]
fn audit_bank_kyc_gwg_request_beyond_purpose_elsewhere_fails() {
    for purpose in ["age_gate_18", "event_checkin", "car_rental"] {
        for request in [
            GWG_SD_JWT_DCQL,
            GWG_SD_JWT_STANDARD_ADDRESS_DCQL,
            GWG_MDOC_DCQL,
        ] {
            let report = audit_json(request, purpose, None, false);
            let flagged: Vec<&str> = report["requested"]
                .as_array()
                .expect("requested")
                .iter()
                .filter(|v| v["status"] == "BeyondPurpose")
                .filter_map(|v| v["key"].as_str())
                .collect();
            assert!(
                flagged.iter().any(|k| k.contains("nationalit")),
                "{purpose}: {flagged:?}"
            );
            assert!(
                flagged
                    .iter()
                    .any(|k| k.contains("birth_place") || k.contains("place_of_birth")),
                "{purpose}: {flagged:?}"
            );
        }
    }
}

/// The bank_kyc request in the current EU PID Rulebook mdoc encoding, with
/// the structured `place_of_birth` element and the remaining address elements.
const GWG_MDOC_RULEBOOK_DCQL: &str = r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[
{"path":["eu.europa.ec.eudi.pid.1","given_name"]},{"path":["eu.europa.ec.eudi.pid.1","family_name"]},
{"path":["eu.europa.ec.eudi.pid.1","birth_date"]},{"path":["eu.europa.ec.eudi.pid.1","place_of_birth"]},
{"path":["eu.europa.ec.eudi.pid.1","nationality"]},{"path":["eu.europa.ec.eudi.pid.1","resident_street"]},
{"path":["eu.europa.ec.eudi.pid.1","resident_city"]},{"path":["eu.europa.ec.eudi.pid.1","resident_postal_code"]},
{"path":["eu.europa.ec.eudi.pid.1","resident_state"]},{"path":["eu.europa.ec.eudi.pid.1","resident_country"]},
{"path":["eu.europa.ec.eudi.pid.1","resident_address"]}]}]}"#;

/// The bank_kyc request with the SD-JWT spellings of
/// fixtures/presentations/erica-pid-template-normal.json (flat birth place,
/// standard address members) and a nationalities wildcard.
const GWG_SD_JWT_FIXTURE_DCQL: &str = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[
{"path":["given_name"]},{"path":["family_name"]},{"path":["birthdate"]},
{"path":["birth_place"]},{"path":["birth_country"]},{"path":["nationalities",null]},
{"path":["address","street_address"]},{"path":["address","house_number"]},{"path":["address","locality"]},
{"path":["address","postal_code"]},{"path":["address","region"]},{"path":["address","country"]},
{"path":["address","formatted"]},{"path":["place_of_birth","region"]},{"path":["place_of_birth","country"]}]}]}"#;

#[test]
fn audit_bank_kyc_rulebook_and_fixture_spellings_pass() {
    for (request, n) in [(GWG_MDOC_RULEBOOK_DCQL, 11), (GWG_SD_JWT_FIXTURE_DCQL, 15)] {
        let report = audit_json(request, "bank_kyc", None, true);
        assert_eq!(report["counts"]["requested"], n);
        assert_eq!(report["counts"]["minimal"], n);
        assert_eq!(report["counts"]["correlatable_requested"], n);
        assert_eq!(report["counts"]["beyond_purpose"], 0);
    }
}

#[test]
fn audit_bank_kyc_flags_mdoc_path_in_another_namespace() {
    // The dotted key equals a model key, but the namespace is not the PID's.
    let request = r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["address","resident_city"]},{"path":["place_of_birth","country"]}]}]}"#;
    let report = audit_json(request, "bank_kyc", None, false);
    assert_eq!(report["counts"]["beyond_purpose"], 2);
}

#[test]
fn audit_bank_kyc_with_cert_flags_unregistered_claims() {
    // The committed certificate registers SD-JWT given_name, family_name and
    // age_equal_or_over.18 only.
    let cert = "fixtures/regcert/rc-by-id.json";
    let report = audit_json(GWG_SD_JWT_DCQL, "bank_kyc", Some(cert), false);
    assert_eq!(report["counts"]["beyond_registration"], 7);

    // The mdoc given_name is a different path from the registered SD-JWT one.
    let mdoc_given = r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","given_name"]}]}]}"#;
    let report = audit_json(mdoc_given, "bank_kyc", Some(cert), false);
    assert_eq!(report["counts"]["beyond_registration"], 1);
    assert_eq!(report["requested"][0]["status"], "BeyondRegistration");
}

// --- registration coverage and the registration-certificate notice ---------

const REGCERT_NOTICE: &str =
    "Registration certificate: payload decoded; signature, issuer and revocation status not verified.";
const NULL_SEGMENT_CERT: &str = "fixtures/claim-paths/rc-null-segment.jwt";
const IDENTICAL_REQUEST: &str = "fixtures/claim-paths/request-identical.json";

fn not_verified_json() -> serde_json::Value {
    json!({
        "decoded": true,
        "signature_verified": false,
        "issuer_verified": false,
        "revocation_checked": false,
    })
}

fn stdout_of(args: &[&str], code: i32) -> String {
    let out = bin()
        .args(args)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).expect("utf8")
}

#[test]
fn audit_request_identical_to_null_segment_registration_is_ok() {
    let text = stdout_of(
        &[
            "audit",
            "--request",
            IDENTICAL_REQUEST,
            "--purpose",
            "bank_kyc",
            "--cert",
            NULL_SEGMENT_CERT,
        ],
        0,
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "OK: Minimal: all 3 requested claims are within purpose and registration."
    );
    assert_eq!(lines[1], REGCERT_NOTICE);
    assert!(text.contains("nationalities.*"), "{text}");
    assert!(!text.contains("[over]"), "{text}");

    let report = audit_json(IDENTICAL_REQUEST, "bank_kyc", Some(NULL_SEGMENT_CERT), true);
    assert_eq!(report["counts"]["beyond_registration"], 0);
    assert_eq!(report["registration_certificate"], not_verified_json());
}

#[test]
fn audit_request_for_an_unregistered_type_is_beyond_registration() {
    let request = r#"{"credentials":[{"id":"x","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:other:1"]},"claims":[{"path":["given_name"]}]}]}"#;
    let report = audit_json(request, "bank_kyc", Some(NULL_SEGMENT_CERT), false);
    assert_eq!(report["counts"]["beyond_registration"], 1);
    assert_eq!(report["requested"][0]["status"], "BeyondRegistration");

    // One segment with a dot is not the registered two-segment path.
    let dotted = r#"{"credentials":[{"id":"x","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["address.locality"]}]}]}"#;
    let report = audit_json(dotted, "bank_kyc", Some(NULL_SEGMENT_CERT), false);
    assert_eq!(report["requested"][0]["status"], "BeyondRegistration");
}

#[test]
fn audit_over_ask_with_cert_carries_the_notice_under_the_verdict() {
    let cert = "fixtures/regcert/rc-by-id.json";
    let text = stdout_of(
        &[
            "audit",
            "--request",
            GWG_SD_JWT_DCQL,
            "--purpose",
            "bank_kyc",
            "--cert",
            cert,
        ],
        1,
    );
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("OVER-ASK: "), "{text}");
    assert_eq!(lines[1], REGCERT_NOTICE);
    let report = audit_json(GWG_SD_JWT_DCQL, "bank_kyc", Some(cert), false);
    assert_eq!(report["registration_certificate"], not_verified_json());
}

#[test]
fn audit_without_cert_says_registration_not_evaluated() {
    let text = stdout_of(
        &[
            "audit",
            "--request",
            "minimal",
            "--purpose",
            "event_checkin",
        ],
        0,
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "OK: Within the purpose-minimal baseline; registration not evaluated."
    );
    assert!(!text.contains("Registration certificate:"), "{text}");

    let report = audit_json("minimal", "event_checkin", None, true);
    assert_eq!(report["counts"]["registration_evaluated"], false);
    let obj = report.as_object().expect("object");
    assert!(obj.contains_key("registration_certificate"));
    assert!(report["registration_certificate"].is_null());

    // The over-ask path without a certificate has no notice either.
    let text = stdout_of(
        &[
            "audit",
            "--request",
            "overask",
            "--purpose",
            "event_checkin",
        ],
        1,
    );
    assert!(!text.contains("Registration certificate:"), "{text}");
}

#[test]
fn decode_and_inspect_regcert_state_that_nothing_was_verified() {
    for args in [
        &["decode", "regcert", "fixtures/regcert/rc-by-id.json"][..],
        &["inspect", "fixtures/regcert/rc-by-id.json"][..],
    ] {
        let text = stdout_of(args, 0);
        assert!(
            text.lines().any(|line| line == REGCERT_NOTICE),
            "{args:?}: {text}"
        );
        let mut json_args = vec!["--json"];
        json_args.extend_from_slice(args);
        let value: serde_json::Value =
            serde_json::from_str(&stdout_of(&json_args, 0)).expect("json");
        assert_eq!(
            value["registration_certificate"],
            not_verified_json(),
            "{args:?}"
        );
    }
}

#[test]
fn regcert_list_with_several_entries_is_refused() {
    let entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("fixtures/regcert/rc-by-id.json").unwrap())
            .unwrap();
    let mut other = entry.clone();
    other["id"] = json!("second-registration");
    let dir = test_temp_dir("augenmass-cli-regcert-list");
    fs::create_dir_all(&dir).unwrap();
    let two = dir.join("two.json");
    fs::write(&two, serde_json::to_string(&json!([entry, other])).unwrap()).unwrap();
    let one = dir.join("one.json");
    fs::write(&one, serde_json::to_string(&json!([entry])).unwrap()).unwrap();

    bin()
        .args(["decode", "regcert", two.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("lists 2 registration certificates"))
        .stderr(contains("second-registration"));
    bin()
        .args([
            "audit",
            "--request",
            "minimal",
            "--purpose",
            "event_checkin",
            "--cert",
            two.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("lists 2 registration certificates"));
    bin()
        .args(["decode", "regcert", one.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("given_name"));
}

#[test]
fn check_and_register_block_a_path_that_is_not_a_pointer() {
    let mut body: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("examples/min.json").unwrap()).unwrap();
    body["credentials"][0]["claims"] = json!([{ "path": ["birthdate", true] }]);
    let dir = test_temp_dir("augenmass-cli-bad-pointer");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("body.json");
    fs::write(&file, serde_json::to_string(&body).unwrap()).unwrap();
    let file = file.to_str().unwrap();

    bin()
        .args(["check", file])
        .assert()
        .code(1)
        .stdout(contains("CHECK-CLAIM-PATH"));
    let value: serde_json::Value =
        serde_json::from_str(&stdout_of(&["--json", "check", file], 1)).expect("json");
    assert_eq!(value["block"], true);
    assert_eq!(value["blockingFormatError"], true);

    bin()
        .args(["register", file, "--target", "cached-sandbox"])
        .assert()
        .failure()
        .stdout(contains("CHECK-CLAIM-PATH"))
        .stdout(contains("DRY RUN").not())
        .stdout(contains("Writing to").not());
}

#[test]
fn check_accepts_null_segments_within_its_own_registration() {
    let mut body: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("examples/min.json").unwrap()).unwrap();
    body["credentials"][0]["claims"] = json!([
        { "path": ["age_equal_or_over", "18"] },
        { "path": ["nationalities", null] },
    ]);
    let dir = test_temp_dir("augenmass-cli-null-body");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("body.json");
    fs::write(&file, serde_json::to_string(&body).unwrap()).unwrap();
    // nationalities is beyond the age-gate purpose, but within the body's
    // own registration.
    let value: serde_json::Value =
        serde_json::from_str(&stdout_of(&["--json", "check", file.to_str().unwrap()], 1))
            .expect("json");
    assert_eq!(value["report"]["counts"]["beyond_registration"], 0);
    assert_eq!(value["report"]["counts"]["beyond_purpose"], 1);
    assert_eq!(value["blockingFormatError"], false);
}

// --- verify presentation ---------------------------------------------------

#[test]
fn verify_valid_presentation_succeeds() {
    bin()
        .args([
            "verify",
            "presentation",
            "fixtures/presentations/erica-vp-VALID.sdjwt",
            "--nonce",
            NONCE,
            "--aud",
            AUD,
            "--now",
            NOW,
        ])
        .assert()
        .success()
        .stdout(contains("VERIFIED"));
}

#[test]
fn verify_wrong_nonce_is_rejected() {
    bin()
        .args([
            "verify",
            "presentation",
            "fixtures/presentations/erica-vp-WRONG_NONCE.sdjwt",
            "--nonce",
            NONCE,
            "--aud",
            AUD,
            "--now",
            NOW,
        ])
        .assert()
        .failure()
        .stdout(contains("NonceMismatch"));
}

#[test]
fn verify_wrong_audience_is_rejected() {
    bin()
        .args([
            "verify",
            "presentation",
            "fixtures/presentations/erica-vp-WRONG_AUDIENCE.sdjwt",
            "--nonce",
            NONCE,
            "--aud",
            AUD,
            "--now",
            NOW,
        ])
        .assert()
        .failure()
        .stdout(contains("AudienceMismatch"));
}

#[test]
fn verify_expired_is_rejected() {
    bin()
        .args([
            "verify",
            "presentation",
            "fixtures/presentations/erica-vp-EXPIRED.sdjwt",
            "--nonce",
            NONCE,
            "--aud",
            AUD,
            "--now",
            NOW,
        ])
        .assert()
        .failure()
        .stdout(contains("Expired"));
}

// --- verify trust ----------------------------------------------------------

#[test]
fn verify_trust_correct_anchor() {
    bin()
        .args([
            "verify",
            "trust",
            "fixtures/presentations/erica-vp-VALID.sdjwt",
            "--anchor",
            "fixtures/certs/erica-trust-anchor.pem",
            "--now",
            NOW,
        ])
        .assert()
        .success()
        .stdout(contains("TRUSTED"));
}

#[test]
fn verify_trust_wrong_anchor() {
    bin()
        .args([
            "verify",
            "trust",
            "fixtures/presentations/erica-vp-VALID.sdjwt",
            "--anchor",
            "fixtures/certs/registrar-ca.pem",
            "--now",
            NOW,
        ])
        .assert()
        .failure()
        .stdout(contains("UNTRUSTED"));
}

// --- verify request (JAR signature) ----------------------------------------

const JAR_FIXTURE: &str = "fixtures/requests/eudiplo-request.jwt";

fn p256_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate P-256 key")
}

fn signing_key(kp: &KeyPair) -> p256::ecdsa::SigningKey {
    let secret = p256::SecretKey::from_pkcs8_der(&kp.serialize_der()).expect("PKCS#8 private key");
    p256::ecdsa::SigningKey::from_bytes(&secret.to_bytes()).expect("signing key")
}

fn self_signed(kp: &KeyPair, cn: &str) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params
        .self_signed(kp)
        .expect("self-sign leaf")
        .der()
        .as_ref()
        .to_vec()
}

fn mint_request_without_client_id() -> String {
    let now = NOW.parse::<i64>().expect("NOW parses");
    let kp = p256_key();
    let der = self_signed(&kp, "CLI Minted Verifier");
    let header = json!({
        "typ": "oauth-authz-req+jwt",
        "alg": "ES256",
        "x5c": [BASE64_STANDARD.encode(&der)],
    });
    let payload = json!({
        "response_type": "vp_token",
        "nonce": NONCE,
        "iat": now - 3600,
        "exp": now + 60,
    });
    let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig: p256::ecdsa::Signature = signing_key(&kp).sign(signing_input.as_bytes());
    let s = BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{s}")
}

#[test]
fn verify_request_valid_fixture_succeeds() {
    bin()
        .args(["verify", "request", JAR_FIXTURE, "--now", NOW])
        .assert()
        .success()
        .stdout(contains("VERIFIED").and(contains("client_id binding: matches")));
}

#[test]
fn verify_request_self_anchor_is_trusted() {
    bin()
        .args([
            "verify",
            "request",
            JAR_FIXTURE,
            "--anchor",
            "fixtures/certs/eudiplo-verifier-leaf.pem",
            "--now",
            NOW,
        ])
        .assert()
        .success()
        .stdout(contains(
            "trust anchored: yes, but the verified leaf is self-issued",
        ));
}

#[test]
fn verify_request_missing_client_id_rejects() {
    let token = mint_request_without_client_id();

    bin()
        .args(["verify", "request", &token, "--now", NOW])
        .assert()
        .failure()
        .stdout(contains("JarClientIdUnbound").and(contains(
            "request has no client_id, so x509_hash binding cannot be established",
        )));
}

#[test]
fn verify_request_wrong_anchor_is_untrusted() {
    bin()
        .args([
            "verify",
            "request",
            JAR_FIXTURE,
            "--anchor",
            "fixtures/certs/erica-trust-anchor.pem",
            "--now",
            NOW,
        ])
        .assert()
        .failure()
        .stdout(contains("UntrustedIssuer"));
}

#[test]
fn verify_request_tampered_signature_is_rejected() {
    // Flip the final signature character; the token stays a well-formed 3-segment
    // JWS but its signature no longer matches the signing input.
    let jwt = fs::read_to_string(JAR_FIXTURE).expect("read JAR fixture");
    let jwt = jwt.trim();
    let last = jwt.chars().last().unwrap();
    let flipped = if last == 'A' { 'B' } else { 'A' };
    let tampered: String = jwt[..jwt.len() - 1].chars().chain([flipped]).collect();
    bin()
        .args(["verify", "request", &tampered, "--now", NOW])
        .assert()
        .failure()
        .stdout(contains("JarSignature"));
}

#[test]
fn verify_request_expired_without_clock_is_rejected() {
    // The captured fixture's exp is in the past relative to any real run, so the
    // system clock (no --now) must fail it closed.
    bin()
        .args(["verify", "request", JAR_FIXTURE])
        .assert()
        .failure()
        .stdout(contains("JarExpired"));
}

#[test]
fn verify_request_json_contract() {
    let assert = bin()
        .args([
            "--json",
            "verify",
            "request",
            JAR_FIXTURE,
            "--anchor",
            "fixtures/certs/eudiplo-verifier-leaf.pem",
            "--now",
            NOW,
        ])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&out).expect("verify request emits valid JSON");
    assert_eq!(v["verified"], serde_json::json!(true));
    assert_eq!(v["clientIdBound"], serde_json::json!(true));
    assert_eq!(v["trustAnchored"], serde_json::json!(true));
    assert_eq!(v["alg"], serde_json::json!("ES256"));
    // Integral NumericDates render as JSON integers, absent claims as null.
    assert_eq!(v["iat"], serde_json::json!(1_780_434_972_i64));
    assert_eq!(v["exp"], serde_json::json!(1_780_438_572_i64));
    assert_eq!(v["nbf"], serde_json::Value::Null);
}

// --- verify status / revocation --------------------------------------------

#[test]
fn status_list_revoked_index_is_revoked() {
    bin()
        .args([
            "verify",
            "status-list",
            "--token",
            "fixtures/status/status-list-REVOKED.jwt",
            "--key",
            STATUS_KEY,
            "--index",
            "42",
        ])
        .assert()
        .failure()
        .stdout(contains("REVOKED"));
}

#[test]
fn status_list_clear_index_is_valid() {
    bin()
        .args([
            "verify",
            "status-list",
            "--token",
            "fixtures/status/status-list-REVOKED.jwt",
            "--key",
            STATUS_KEY,
            "--index",
            "43",
        ])
        .assert()
        .success()
        .stdout(contains("VALID"));
}

#[test]
fn full_verify_revoked_synthetic_pid_is_rejected() {
    bin()
        .args([
            "verify",
            "presentation",
            "fixtures/presentations/synthetic-pid-with-status.sdjwt",
            "--nonce",
            NONCE,
            "--aud",
            AUD,
            "--now",
            NOW,
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-REVOKED.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .failure()
        .stdout(contains("Revoked"));
}

// --- x509-hash -------------------------------------------------------------

#[test]
fn x509_hash_matches_known_binding() {
    bin()
        .args([
            "x509-hash",
            "fixtures/certs/access-leaf.pem",
            "--client-id",
            "x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI",
        ])
        .assert()
        .success()
        .stdout(contains("MATCH"));
}

#[test]
fn x509_hash_mismatch_fails() {
    bin()
        .args([
            "x509-hash",
            "fixtures/certs/access-leaf.pem",
            "--client-id",
            "x509_hash:WRONG",
        ])
        .assert()
        .failure()
        .stdout(contains("MISMATCH"));
}

#[test]
fn x509_hash_from_jar() {
    bin()
        .args(["x509-hash", "fixtures/requests/eudiplo-request.jwt"])
        .assert()
        .success()
        .stdout(contains(
            "x509_hash:7zvIjJaM1KQPpN7IZBuVLuh8anw1gcbZ0a6Wj3M9i4w",
        ));
}

// --- generate --------------------------------------------------------------

#[test]
fn generate_regbody_is_clean_when_checked() {
    // generate the proportionate body, pipe it to check via stdin, expect clean.
    let body = bin()
        .args(["generate", "regbody"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let body = String::from_utf8(body).expect("utf8");
    bin()
        .args(["check", "-"])
        .write_stdin(body)
        .assert()
        .success();
}

#[test]
fn generate_overbroad_body_blocks_when_checked() {
    let body = bin()
        .args(["generate", "regbody", "--over-broad"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let body = String::from_utf8(body).expect("utf8");
    bin()
        .args(["check", "-"])
        .write_stdin(body)
        .assert()
        .failure();
}

#[test]
fn generate_dcql_builds_query() {
    bin()
        .args(["generate", "dcql", "--claim", "age_equal_or_over.18"])
        .assert()
        .success()
        .stdout(contains("dc+sd-jwt"));
}

// --- doctor ----------------------------------------------------------------

#[test]
fn doctor_flags_bad_request() {
    bin()
        .args(["doctor", "examples/bad-request.json"])
        .assert()
        .failure()
        .stdout(contains("DOCTOR-X5C-STRING"));
}

// --- mdoc (ISO 18013-5) ----------------------------------------------------

#[test]
fn decode_mdoc_reveals_mdl_elements() {
    bin()
        .args(["decode", "mdoc", "fixtures/mdoc/issuer-signed.hex"])
        .assert()
        .success()
        .stdout(contains("org.iso.18013.5.1"))
        .stdout(contains("family_name = Doe"))
        .stdout(contains("ES256"))
        .stdout(contains("org.iso.18013.5.1.mDL"));
}

#[test]
fn inspect_detects_mdoc() {
    bin()
        .args(["inspect", "fixtures/mdoc/issuer-signed.hex"])
        .assert()
        .success()
        .stderr(contains("ISO 18013-5 mdoc"))
        .stdout(contains("family_name"));
}

#[test]
fn decode_mdoc_json_is_valid() {
    let out = bin()
        .args([
            "--json",
            "decode",
            "mdoc",
            "fixtures/mdoc/issuer-signed.hex",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["type"], "IssuerSigned");
}

// --- validate dcql ---------------------------------------------------------

#[test]
fn validate_dcql_good_fixture_passes() {
    bin()
        .args([
            "validate",
            "dcql",
            "fixtures/dcql/eudiplo-haip-pid-de.dcql.json",
        ])
        .assert()
        .success()
        .stdout(contains("DCQL VALID"));
}

#[test]
fn validate_dcql_bad_query_blocks() {
    let bad = r#"{"credentials":[{"id":"a","format":"mso_mdoc","claims":[{"path":["org.iso.18013.5.1"]}]},{"id":"a","format":"dc+sd-jwt"}],"credential_sets":[{"options":[["missing"]]}]}"#;
    bin()
        .args(["validate", "dcql", bad])
        .assert()
        .failure()
        .stdout(contains("DCQL-CRED-ID-DUPLICATE"))
        .stdout(contains("DCQL-MDOC-PATH"))
        .stdout(contains("DCQL-SET-REF-DANGLING"));
}

#[test]
fn empty_credential_set_option_is_rejected_not_skipped() {
    // Before, `options: [[]]` selected no credential, so the audit judged
    // nothing and passed a request for an unregistered type with exit 0.
    let request = r#"{"credentials":[{"id":"x","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:other:1"]}}],"credential_sets":[{"options":[[]]}]}"#;
    bin()
        .args([
            "audit",
            "--request",
            request,
            "--purpose",
            "bank_kyc",
            "--cert",
            NULL_SEGMENT_CERT,
        ])
        .assert()
        .failure()
        .stderr(contains(
            "malformed DCQL query: credential_sets[0].options[0] is an empty list",
        ));
    bin()
        .args(["inspect", request])
        .assert()
        .failure()
        .stderr(contains("is an empty list"));
    bin()
        .args(["validate", "dcql", request])
        .assert()
        .failure()
        .stdout(contains("DCQL-SET-OPTION-EMPTY"));
}

// --- evidence export / replay ---------------------------------------------

#[test]
fn evidence_export_verify_and_replay_stays_redacted() {
    let source = evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("EVIDENCE BUNDLE EXPORTED"))
        .stdout(contains("sensitive: true"));

    bin()
        .args(["evidence", "verify", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("EVIDENCE BUNDLE VALID"));

    bin()
        .args(["evidence", "replay", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("EVIDENCE REPLAY"))
        .stdout(contains("bodySha256").not())
        .stdout(contains("secret-claim").not());

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_assert_live_accepts_verified_wallet_bundle() {
    let source = live_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-live-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args(["evidence", "assert-live", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("LIVE WALLET EVIDENCE PROVEN"))
        .stdout(contains("RESPONSE_DECRYPTED"))
        .stdout(contains("VERIFIED"))
        .stdout(contains("trust/status/over-ask are not claimed"));

    let out = bin()
        .args([
            "--json",
            "evidence",
            "assert-live",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["valid"], true);
    assert_eq!(value["claims"]["presentationVerified"], true);
    assert_eq!(value["claims"]["trustChecked"], false);
    assert_eq!(value["claims"]["overAskAnalyzed"], false);

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_assert_live_requires_decryptable_direct_post_jwt() {
    let source = artifact_only_live_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-artifact-only-live-evidence");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args(["evidence", "assert-live", bundle.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains(
            "evidence bundle does not contain session-enc-key.jwk",
        ));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_profile_reports_redacted_readiness() {
    let source = live_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-profile-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args(["evidence", "profile", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("EVIDENCE PROFILE"))
        .stdout(contains("presentations: 1"))
        .stdout(contains("issuerX5cPresent: true"))
        .stdout(contains("trustAnchorClaimPossible: true"));

    let out = bin()
        .args(["--json", "evidence", "profile", bundle.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["redacted"], true);
    assert_eq!(value["presentations"].as_array().unwrap().len(), 1);
    assert_eq!(value["readiness"]["issuerX5cPresent"], true);

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_accepts_redacted_bundle() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .success()
        .stdout(contains("EVIDENCE TRUST/STATUS PROVEN"))
        .stdout(contains("trust anchored: true"))
        .stdout(contains("status checked: true"))
        .stdout(contains("output is redacted"));

    let out = bin()
        .args([
            "--json",
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["valid"], true);
    assert_eq!(value["redacted"], true);
    assert_eq!(value["statusTokenSource"], "supplied");
    assert_eq!(value["presentations"][0]["trustAnchored"], true);
    assert_eq!(value["presentations"][0]["statusChecked"], true);

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_accepts_inline_pem_anchor() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-inline-anchor-bundle");
    let bundle = bundle_dir.join("bundle.json");
    let anchor_pem = fs::read_to_string("fixtures/certs/synthetic-pid-anchor.pem")
        .expect("read synthetic PID anchor fixture");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args(["evidence", "prove-trust-status", bundle.to_str().unwrap()])
        .arg(format!("--trust-anchor={anchor_pem}"))
        .args([
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .success();

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_inline_status_key_reaches_signer() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-inline-key-bundle");
    let bundle = bundle_dir.join("bundle.json");
    let status_key_pem = fs::read_to_string("fixtures/certs/synthetic-pid-anchor.pem")
        .expect("read synthetic PID anchor fixture");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
        ])
        .arg(format!("--status-key={status_key_pem}"))
        .assert()
        .failure()
        .stderr(contains("input file not found").not())
        .stdout(contains("status-list token"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_rejects_mixed_presentations() {
    let valid = fs::read_to_string("fixtures/presentations/synthetic-pid-with-status.sdjwt")
        .expect("read status presentation fixture");
    let missing_status_ref = fs::read_to_string("fixtures/presentations/erica-vp-VALID.sdjwt")
        .expect("read erica presentation fixture");
    let source = status_evidence_source_session_with_vp_token(json!([
        valid.trim(),
        missing_status_ref.trim()
    ]));
    let bundle_dir = test_temp_dir("augenmass-cli-status-mixed-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .failure()
        .stdout(contains("EVIDENCE TRUST/STATUS REJECTED"))
        .stdout(contains("reason:"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_rejects_revoked_status() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-revoked-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-REVOKED.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .failure()
        .stdout(contains("EVIDENCE TRUST/STATUS REJECTED"))
        .stdout(contains("reason:"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_rejects_missing_status_key_path() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-missing-key-path-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            "fixtures/status/does-not-exist.pem",
        ])
        .assert()
        .failure()
        .stderr(contains(
            "input file not found: fixtures/status/does-not-exist.pem",
        ));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_rejects_wrong_anchor() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-wrong-anchor-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/erica-trust-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .failure()
        .stdout(contains("EVIDENCE TRUST/STATUS REJECTED"))
        .stdout(contains("reason:"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_rejects_wrong_status_key() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-wrong-key-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--status-key",
            "fixtures/certs/erica-trust-anchor.pem",
        ])
        .assert()
        .failure()
        .stdout(contains("EVIDENCE TRUST/STATUS REJECTED"))
        .stdout(contains("reason:"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_rejects_ambiguous_status_source() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-ambiguous-source-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-token",
            "fixtures/status/status-list-CLEAR.jwt",
            "--fetch-status-token",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .failure()
        .stderr(contains("cannot be used with '--fetch-status-token'"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_prove_trust_status_requires_status_source() {
    let source = status_evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-status-missing-source-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args([
            "evidence",
            "prove-trust-status",
            bundle.to_str().unwrap(),
            "--trust-anchor",
            "fixtures/certs/synthetic-pid-anchor.pem",
            "--status-key",
            STATUS_KEY,
        ])
        .assert()
        .failure()
        .stderr(contains("set --status-token <jwt> or --fetch-status-token"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_assert_live_rejects_plaintext_or_failed_bundle() {
    let source = evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-failed-evidence-bundle");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args(["evidence", "assert-live", bundle.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("terminal failure event REJECTED"));

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn evidence_json_verify_reports_valid_bundle() {
    let source = evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-evidence-json");
    let bundle = bundle_dir.join("bundle.json");

    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = bin()
        .args(["--json", "evidence", "verify", bundle.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["valid"], true);
    assert_eq!(value["sensitive"], true);
    assert_eq!(value["signature"], "absent");

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn validate_dcql_json_output_is_valid() {
    let out = bin()
        .args(["--json", "validate", "dcql", r#"{"credentials":[]}"#])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["valid"], serde_json::Value::Bool(false));
}

// --- v0.4.1: mdoc age element, suggestion spelling, demo inputs -------------

/// An inline mdoc PID request (doctype eu.europa.ec.eudi.pid.1) for the given
/// `[namespace, element]` paths.
fn mdoc_request(paths: &[[&str; 2]]) -> String {
    let claims: Vec<serde_json::Value> = paths.iter().map(|p| json!({ "path": p })).collect();
    json!({ "credentials": [{
        "id": "pid-mdoc",
        "format": "mso_mdoc",
        "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
        "claims": claims,
    }]})
    .to_string()
}

#[test]
fn audit_mdoc_age_request_is_minimal_in_both_pid_namespaces() {
    for ns in ["eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.pid.de.1"] {
        let request = mdoc_request(&[[ns, "age_over_18"]]);
        let text = stdout_of(
            &["audit", "--request", &request, "--purpose", "age_gate_18"],
            0,
        );
        assert!(
            text.starts_with(
                "OK: Within the purpose-minimal baseline; registration not evaluated.\n"
            ),
            "{ns}: {text}"
        );
        let request = mdoc_request(&[[ns, "age_over_21"]]);
        stdout_of(
            &["audit", "--request", &request, "--purpose", "car_rental"],
            0,
        );
        let request = mdoc_request(&[[ns, "age_over_16"]]);
        stdout_of(
            &["audit", "--request", &request, "--purpose", "age_gate_18"],
            1,
        );
    }
}

#[test]
fn audit_mdoc_age_with_birth_date_is_still_over_ask() {
    let request = mdoc_request(&[
        ["eu.europa.ec.eudi.pid.de.1", "age_over_18"],
        ["eu.europa.ec.eudi.pid.1", "birth_date"],
    ]);
    let text = stdout_of(
        &["audit", "--request", &request, "--purpose", "age_gate_18"],
        1,
    );
    assert!(text.starts_with("OVER-ASK"), "{text}");
}

#[test]
fn suggestion_is_printed_in_the_request_spelling() {
    let text = stdout_of(
        &["audit", "--request", "overask", "--purpose", "age_gate_18"],
        1,
    );
    assert!(
        text.contains("as claim paths:\n  [\"age_equal_or_over\", \"18\"]\n"),
        "{text}"
    );
    assert!(!text.contains("\n  age_equal_or_over.18\n"), "{text}");

    let text = stdout_of(
        &[
            "audit",
            "--request",
            "examples/kyc-request-plus-birthdate.json",
            "--purpose",
            "bank_kyc",
            "--cert",
            NULL_SEGMENT_CERT,
        ],
        1,
    );
    assert!(
        text.contains("\n  [\"address\", \"street_address\"]\n"),
        "{text}"
    );
    assert!(
        text.contains("\n  No known claim for this credential type: Place of birth (region), Place of birth (country), Resident house number, Resident address.\n"),
        "{text}"
    );
    assert!(!text.contains("address.resident_street"), "{text}");

    // An mdoc request that over-asks: the suggestion is in [namespace,
    // element] form with the profile mark and its explanation.
    let request = mdoc_request(&[["eu.europa.ec.eudi.pid.1", "birth_date"]]);
    let text = stdout_of(
        &["audit", "--request", &request, "--purpose", "age_gate_18"],
        1,
    );
    assert!(
        text.contains("Suggested minimal request (mso_mdoc, eu.europa.ec.eudi.pid.1), as [namespace, element]:\n  [\"eu.europa.ec.eudi.pid.de.1\", \"age_over_18\"] (German PID only)\n  The EU PID and the German PID share the doctype eu.europa.ec.eudi.pid.1; a marked element exists in only one of them.\n"),
        "{text}"
    );

    // An unknown credential type gets labels, never internal keys.
    let request = json!({ "credentials": [{
        "id": "club", "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:example:membership:1"] },
        "claims": [{ "path": ["member_name"] }],
    }]})
    .to_string();
    let text = stdout_of(
        &["audit", "--request", &request, "--purpose", "age_gate_18"],
        1,
    );
    assert!(
        text.contains("Suggested minimal request (dc+sd-jwt, urn:example:membership:1):\n  No claim names are known for this credential type. The purpose baseline asks only for: Age over 18.\n"),
        "{text}"
    );

    let report = audit_json("overask", "age_gate_18", None, false);
    assert_eq!(
        report["suggested_minimal_request"][0]["paths"][0]["path"],
        json!(["age_equal_or_over", "18"])
    );
    // The baseline keys stay in their 0.4.0 field.
    assert_eq!(report["suggested_minimal"], json!(["age_equal_or_over.18"]));
}

#[test]
fn check_over_example_suggests_claim_paths() {
    bin()
        .args(["check", "examples/over.json"])
        .assert()
        .failure()
        .stdout(contains(
            "Suggested minimal request (dc+sd-jwt, urn:eudi:pid:de:1), as claim paths:\n  [\"age_equal_or_over\", \"18\"]\n",
        ));
}

#[test]
fn demo_pair_is_inside_registration_beyond_purpose() {
    let report = audit_json(
        "examples/age-broad-request.json",
        "age_gate_18",
        Some("examples/age-broad-registration.jwt"),
        false,
    );
    assert_eq!(report["counts"]["requested"], 5);
    assert_eq!(report["counts"]["beyond_purpose"], 5);
    assert_eq!(report["counts"]["beyond_registration"], 0);
    for row in report["requested"].as_array().expect("requested") {
        assert_eq!(row["status"], "BeyondPurpose", "{row}");
    }
    assert_eq!(report["registration_certificate"]["decoded"], true);
}

#[test]
fn demo_minimal_age_requests_pass() {
    for request in [
        "examples/age-minimal-request-sdjwt.json",
        "examples/age-minimal-request-mdoc.json",
    ] {
        let text = stdout_of(
            &["audit", "--request", request, "--purpose", "age_gate_18"],
            0,
        );
        assert!(text.starts_with("OK: "), "{request}: {text}");
    }
}

#[test]
fn check_integer_age_segment_is_not_minimal() {
    // examples/min.json with the integer 18, which selects an array element
    // and does not name the member "18" of the age object.
    let body = std::fs::read_to_string("examples/min.json").expect("min.json");
    let body = body.replace("\"18\"", "18");
    assert!(
        body.contains("\"age_equal_or_over\",\n            18"),
        "{body}"
    );
    let out = bin()
        .args(["check", &body, "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let text = report.to_string();
    assert!(text.contains("\"BeyondPurpose\""), "{text}");
    assert!(!text.contains("\"MinimalForPurpose\""), "{text}");
    bin()
        .args(["check", "examples/min.json"])
        .assert()
        .success();
}

#[test]
fn audit_unmodelled_format_gets_no_purpose_verdict() {
    let request = r#"{"credentials":[{"id":"pid","format":"org.example.format","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["age_equal_or_over","18"]}]}]}"#;
    let report = audit_json(request, "age_gate_18", None, false);
    assert_eq!(report["counts"]["beyond_purpose"], 1, "{report}");
    assert_eq!(report["counts"]["minimal"], 0, "{report}");
    let row = &report["requested"][0];
    assert_eq!(row["status"], "BeyondPurpose", "{row}");
    assert!(
        row["rationale"]
            .as_str()
            .is_some_and(|r| r.starts_with("Purpose not judged for this credential format")),
        "{row}"
    );
}

/// ARF Annex 2.02, Topic 44, RPRC_21, verbatim.
const RPRC_21: &str = "After receiving a presentation request from a Relying Party, a Wallet Unit SHALL verify that all attributes requested in the request are included in the list of attributes in the registration certificate included in the same request. If the outcome of the verification is negative, the Wallet Unit SHALL, when asking for User approval according to RPA_07, warn the User that the Relying Party is requesting more information than it has registered. In addition, the Wallet Provider SHALL determine, based on its risk analysis and security policy, whether the Wallet Unit must a) enable the User to approve (or reject) the presentation of all requested attributes, including the non-registered ones, b) enable the User to approve (or reject) the presentation of the registered attributes only, or c) reject the presentation of all requested attributes.";

#[test]
fn legal_basis_quotes_rprc_21_verbatim_in_text_and_json() {
    let line = format!("  EUDI ARF, registration certificate, RPRC_21\n    {RPRC_21}\n");
    let text = stdout_of(&["baselines"], 0);
    assert!(text.contains(&line), "{text}");
    assert!(!text.contains("notifies the user"));

    let value: serde_json::Value =
        serde_json::from_str(&stdout_of(&["baselines", "--json"], 0)).expect("json");
    assert_eq!(
        value["legalBasis"][2],
        json!({
            "source": "EUDI ARF, registration certificate",
            "locator": "RPRC_21",
            "text": RPRC_21,
        })
    );

    let text = stdout_of(
        &["audit", "--request", "overask", "--purpose", "age_gate_18"],
        1,
    );
    assert!(text.contains(&line), "{text}");
    assert!(!text.contains("notifies the user"));
    let report = audit_json("overask", "age_gate_18", None, false);
    assert_eq!(report["legal_basis"][2], value["legalBasis"][2]);
}

// --- v0.4.1: sandbox registrar notice ----------------------------------------

const SANDBOX_NOTICE: &str = "The landing page of the German sandbox registrar (sandbox.eudi-wallet.org, read on 13 November 2026) says that testing in it is possible until 19 November 2026, that the new wallet app version then no longer accepts certificates from it, and that it admits no new users.";

fn sandbox_target_line() -> String {
    format!("note: --target sandbox uses the built-in registrar https://sandbox.eudi-wallet.org/api because AUGENMASS_API_BASE is not set. {SANDBOX_NOTICE}\n")
}

fn cache_upstream_line() -> String {
    format!("note: cache serve uses the built-in upstream https://sandbox.eudi-wallet.org/api because neither --upstream nor AUGENMASS_CACHE_UPSTREAM is set. {SANDBOX_NOTICE}\n")
}

/// A fresh, empty working directory with no `.env` in it or above it, so
/// `dotenvy::dotenv()` in the binary loads nothing.
fn isolated_dir() -> PathBuf {
    let dir = test_temp_dir("augenmass-cli-isolated");
    fs::create_dir_all(&dir).expect("create isolated dir");
    for ancestor in dir.ancestors() {
        assert!(!ancestor.join(".env").exists(), "{}", ancestor.display());
    }
    dir
}

/// The binary with an empty environment except `envs`, run in an isolated
/// directory. Proxy variables point at a closed local port, so a request that
/// a regression might send cannot leave the machine.
fn isolated_command(args: &[&str], envs: &[(&str, &str)]) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_augenmass"));
    cmd.env_clear()
        .current_dir(isolated_dir())
        .args(args)
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd
}

fn isolated_output(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let out = isolated_command(args, envs).output().expect("run binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).expect("utf8"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

fn repo_path(rel: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(rel)
        .display()
        .to_string()
}

fn closed_local_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

#[test]
fn sandbox_target_without_configuration_prints_the_notice_on_stderr() {
    // No token URL is set, so the command stops before any request.
    for args in [
        &["list", "--target", "sandbox", "--rp", "x"][..],
        &["list", "--target", "sandbox", "--rp", "x", "--json"][..],
    ] {
        let (code, stdout, stderr) = isolated_output(args, &[]);
        assert_ne!(code, 0, "{args:?}");
        assert!(
            stderr.starts_with(&sandbox_target_line()),
            "{args:?}: {stderr}"
        );
        assert_eq!(stderr.matches("note: --target sandbox").count(), 1);
        assert!(
            stderr.contains("AUGENMASS_OIDC_TOKEN_URL is required"),
            "{stderr}"
        );
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
    }
}

#[test]
fn sandbox_target_with_configuration_prints_no_notice() {
    for envs in [
        &[("API_BASE", "https://registrar.example.org/api")][..],
        &[("AUGENMASS_API_BASE", "https://sandbox.eudi-wallet.org/api")][..],
    ] {
        let (code, stdout, stderr) =
            isolated_output(&["list", "--target", "sandbox", "--rp", "x"], envs);
        assert_ne!(code, 0, "{envs:?}");
        assert!(
            !stderr.contains("note: --target sandbox"),
            "{envs:?}: {stderr}"
        );
        assert!(
            stderr.contains("AUGENMASS_OIDC_TOKEN_URL is required"),
            "{stderr}"
        );
        assert!(stdout.is_empty());
    }

    // A dry run makes no request and prints no notice.
    let body = repo_path("examples/min.json");
    let (code, stdout, stderr) = isolated_output(&["register", &body, "--target", "sandbox"], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("DRY RUN: nothing written."), "{stdout}");
    assert!(!stderr.contains("note:"), "{stderr}");

    // Another target prints no notice; the request fails locally.
    let clone = format!("http://127.0.0.1:{}/api", closed_local_port());
    let (code, _, stderr) = isolated_output(
        &["list", "--target", "clone", "--rp", "x"],
        &[("AUGENMASS_CLONE_API_BASE", clone.as_str())],
    );
    assert_ne!(code, 0);
    assert!(!stderr.contains("note:"), "{stderr}");
}

/// Spawn the binary isolated, collect stdout and stderr until a line on
/// either stream contains `until` or 20 seconds pass, then kill it and
/// return everything both streams printed.
fn startup_output(args: &[&str], envs: &[(&str, &str)], until: &str) -> (String, String) {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let mut child = isolated_command(args, envs)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn binary");
    let (tx, rx) = mpsc::channel::<(bool, String)>();
    let readers: Vec<_> = [
        (
            false,
            Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
        ),
        (
            true,
            Box::new(child.stderr.take().expect("stderr")) as Box<dyn std::io::Read + Send>,
        ),
    ]
    .into_iter()
    .map(|(is_err, stream)| {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stream)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send((is_err, line));
            }
        })
    })
    .collect();
    drop(tx);

    let (mut stdout, mut stderr) = (String::new(), String::new());
    let mut push = |(is_err, line): (bool, String)| {
        let buf = if is_err { &mut stderr } else { &mut stdout };
        buf.push_str(&line);
        buf.push('\n');
        line.contains(until)
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(item) => {
                if push(item) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    for reader in readers {
        let _ = reader.join();
    }
    for item in rx.try_iter() {
        push(item);
    }
    (stdout, stderr)
}

#[test]
fn cache_serve_prints_the_notice_only_for_the_built_in_upstream() {
    let run = |extra: &[&str], envs: &[(&str, &str)]| {
        let dir = isolated_dir();
        let db = dir.join("c.sqlite").display().to_string();
        let port = closed_local_port().to_string();
        let mut args = vec![
            "cache",
            "serve",
            "--db",
            &db,
            "--host",
            "127.0.0.1",
            "--port",
            &port,
        ];
        args.extend_from_slice(extra);
        startup_output(&args, envs, "admin endpoints:")
    };

    let (stdout, stderr) = run(&[], &[]);
    assert!(stdout.contains("admin endpoints:"), "{stdout}\n{stderr}");
    assert!(stderr.contains(&cache_upstream_line()), "{stderr}");
    assert_eq!(stderr.matches("note: cache serve").count(), 1);
    assert!(!stdout.contains("note:"), "{stdout}");

    for (extra, envs) in [
        (
            &["--upstream", "https://sandbox.eudi-wallet.org/api"][..],
            &[][..],
        ),
        (
            &[][..],
            &[(
                "AUGENMASS_CACHE_UPSTREAM",
                "https://sandbox.eudi-wallet.org/api",
            )][..],
        ),
    ] {
        let (stdout, stderr) = run(extra, envs);
        assert!(stdout.contains("admin endpoints:"), "{stdout}\n{stderr}");
        assert!(
            !stderr.contains("note: cache serve"),
            "{extra:?} {envs:?}: {stderr}"
        );
    }
}

#[test]
fn serve_names_the_bundled_registration_certificate_at_startup() {
    let port = closed_local_port().to_string();
    let (_, stderr) = startup_output(&["serve", "--port", &port], &[], "registration :");
    let line = format!("  registration : bundled certificate fixtures/regcert/rc-by-id.json, issued by the German sandbox registrar (C=DE, CN=German Registrar). {SANDBOX_NOTICE}\n");
    assert!(stderr.contains(&line), "{stderr}");
}
