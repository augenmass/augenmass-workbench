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

/// The JSON a command prints on stdout, with the expected exit code.
fn json_of(args: &[&str], code: i32) -> serde_json::Value {
    serde_json::from_str(&stdout_of(args, code)).expect("json on stdout")
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

/// A signed request object as a compact JWT file (three base64url parts;
/// `doctor` verifies no signature) with the given `client_id` and
/// `dcql_query`. Returns its path.
fn signed_request_object(name: &str, client_id: &str, query: &serde_json::Value) -> String {
    let b64 = |v: &str| BASE64_URL_SAFE_NO_PAD.encode(v.as_bytes());
    let header = json!({ "typ": "oauth-authz-req+jwt", "alg": "ES256", "x5c": ["MIIB"] });
    let payload = json!({
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": NONCE,
        "dcql_query": query,
    });
    let dir = test_temp_dir("augenmass-cli-request");
    fs::create_dir_all(&dir).expect("create request dir");
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            "{}.{}.{}",
            b64(&header.to_string()),
            b64(&payload.to_string()),
            b64("not-a-signature")
        ),
    )
    .expect("write request object");
    path.display().to_string()
}

/// The PID age query with its claims under `member` (`claims`, or a name
/// that resembles it).
fn age_query_with_claims_under(member: &str) -> serde_json::Value {
    let mut credential = json!({
        "id": "pid",
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
    });
    credential[member] = json!([{ "path": ["age_equal_or_over", "18"] }]);
    json!({ "credentials": [credential] })
}

const DOCTOR_OK: &str = "OK: no signed-request gotchas found.\nSet Content-Type: application/json on every POST; the client does this for you.\n";

/// A signed request object whose `dcql_query` says `claim` for `claims`
/// gets no OK headline from `doctor`: the member is a warning finding, with
/// the message that `decode request` prints, and the exit code stays 0.
#[test]
fn doctor_reports_a_near_miss_member_of_the_query_as_a_warning() {
    let request = signed_request_object(
        "near-miss.jwt",
        "x509_hash:abc",
        &age_query_with_claims_under("claim"),
    );
    let (code, stdout, stderr) = run_cli(&["doctor", &request]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(stderr, "");
    assert_eq!(
        stdout,
        format!(
            "Signed-request findings:\n  DCQL-MEMBER-NEAR-MISS [warning]: {}\n{NEAR_MISS_FIX_LINE}\nNo blocking finding (warnings only).\n",
            claim_for_claims_line()
        )
    );
    assert!(!stdout.contains("OK:"), "{stdout}");

    let value = json_of(&["doctor", &request, "--json"], 0);
    assert_eq!(value["ok"], true);
    assert_eq!(value["findings"].as_array().expect("findings").len(), 1);
    assert_eq!(value["findings"][0]["id"], "DCQL-MEMBER-NEAR-MISS");
    assert_eq!(value["findings"][0]["severity"], "warning");
    assert_eq!(value["findings"][0]["message"], claim_for_claims_line());
    // The same array as `decode request --json` and `audit --json` carry.
    let decoded = json_of(&["decode", "request", &request, "--json"], 0);
    assert_eq!(value["warnings"], decoded["warnings"]);
    assert_eq!(value["warnings"][0]["member"], "claim");
    assert_eq!(value["warnings"][0]["resembles"], "claims");

    // The same request as a plain JSON request object (the payload).
    let payload = decoded["payload"].to_string();
    let (code, plain, _) = run_cli(&["doctor", &payload]);
    assert_eq!(code, 0);
    assert_eq!(plain, stdout);
}

/// A member named `dcql_query` in the header of a signed request object does
/// not stand in for the query of the request: the warning of the payload's
/// query is reported as `decode request` reports it, in both input forms.
#[test]
fn doctor_reads_the_query_of_the_payload_not_a_header_member() {
    let b64 = |v: &str| BASE64_URL_SAFE_NO_PAD.encode(v.as_bytes());
    let header = json!({ "alg": "ES256", "dcql_query": {} });
    let payload = json!({
        "client_id": "x509_hash:abc",
        "dcql_query": age_query_with_claims_under("claim"),
    });
    let dir = test_temp_dir("augenmass-cli-request");
    fs::create_dir_all(&dir).expect("create request dir");
    let jwt = dir.join("header-query.jwt");
    fs::write(
        &jwt,
        format!(
            "{}.{}.{}",
            b64(&header.to_string()),
            b64(&payload.to_string()),
            b64("not-a-signature")
        ),
    )
    .expect("write request object");
    let jwt = jwt.display().to_string();
    let pair = json!({ "header": header, "payload": payload }).to_string();

    let decoded = json_of(&["decode", "request", &jwt, "--json"], 0);
    assert_eq!(decoded["warnings"].as_array().expect("warnings").len(), 1);
    for input in [jwt.as_str(), pair.as_str()] {
        let (code, stdout, stderr) = run_cli(&["doctor", input]);
        assert_eq!(code, 0, "{input}: {stdout}{stderr}");
        assert_eq!(
            stdout,
            format!(
                "Signed-request findings:\n  DCQL-MEMBER-NEAR-MISS [warning]: {}\n{NEAR_MISS_FIX_LINE}\nNo blocking finding (warnings only).\n",
                claim_for_claims_line()
            ),
            "{input}"
        );
        let value = json_of(&["doctor", input, "--json"], 0);
        assert_eq!(value["ok"], true, "{input}");
        assert_eq!(value["warnings"], decoded["warnings"], "{input}");
    }
}

/// Runs `doctor` on `input` and checks that it exits 0 with exactly the
/// near-miss warnings `messages` (in this order), or with the OK lines when
/// `messages` is empty. Returns the `--json` value.
fn doctor_warns_exactly(input: &str, messages: &[String]) -> serde_json::Value {
    let (code, stdout, stderr) = run_cli(&["doctor", input]);
    assert_eq!(code, 0, "{input}: {stdout}{stderr}");
    assert_eq!(stderr, "", "{input}");
    if messages.is_empty() {
        assert_eq!(stdout, DOCTOR_OK, "{input}");
    } else {
        let mut expected = String::from("Signed-request findings:\n");
        for message in messages {
            expected.push_str(&format!(
                "  DCQL-MEMBER-NEAR-MISS [warning]: {message}\n{NEAR_MISS_FIX_LINE}"
            ));
        }
        expected.push_str("\nNo blocking finding (warnings only).\n");
        assert_eq!(stdout, expected, "{input}");
    }
    let value = json_of(&["doctor", input, "--json"], 0);
    assert_eq!(value["ok"], true, "{input}");
    let warnings: Vec<&str> = value["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .map(|w| w["message"].as_str().expect("message"))
        .collect();
    assert_eq!(warnings, messages, "{input}");
    value
}

/// A plain request whose top level has the query: a member `payload` that
/// is an empty object does not hide it.
#[test]
fn doctor_reads_the_top_level_query_next_to_an_empty_payload() {
    let input = json!({
        "client_id": "x509_hash:abc",
        "dcql_query": age_query_with_claims_under("claim"),
        "payload": {},
    })
    .to_string();
    let value = doctor_warns_exactly(&input, &[claim_for_claims_line()]);
    assert_eq!(value["warnings"][0]["place"], "credentials[0]");
}

/// A request with a query at the top level and one in its payload: the
/// warning of the top-level query is reported, and its place names that
/// query; the clean query of the payload adds nothing.
#[test]
fn doctor_reads_the_top_level_query_next_to_a_payload_query() {
    let input = json!({
        "client_id": "x509_hash:abc",
        "dcql_query": age_query_with_claims_under("claim"),
        "payload": { "dcql_query": age_query_with_claims_under("claims") },
    })
    .to_string();
    let value = doctor_warns_exactly(
        &input,
        &[near_miss_line(
            "dcql_query.credentials[0]",
            "claim",
            "Credential Query",
            "claims",
        )],
    );
    assert_eq!(value["warnings"][0]["place"], "dcql_query.credentials[0]");
}

/// A pair whose payload holds the query and whose top level has none: the
/// payload's warning is reported as `decode request` reports it.
#[test]
fn doctor_reads_the_payload_query_when_the_top_level_has_none() {
    let input = json!({
        "header": { "alg": "ES256" },
        "payload": {
            "client_id": "x509_hash:abc",
            "dcql_query": age_query_with_claims_under("claim"),
        },
    })
    .to_string();
    doctor_warns_exactly(&input, &[claim_for_claims_line()]);
}

/// A member `dcql_query` whose value is not a JSON object (`null`, a string,
/// an array) holds no query, so `doctor` does not count it as a second query
/// and does not prefix the warning of the one query with its place: the
/// place, and the start of both messages, are the ones `validate dcql` gives.
#[test]
fn doctor_does_not_count_a_member_that_is_not_an_object_as_a_query() {
    for other in [json!(null), json!("x"), json!([])] {
        let top = json!({
            "dcql_query": other,
            "payload": {
                "client_id": "x509_hash:abc",
                "dcql_query": age_query_with_claims_under("claim"),
            },
        })
        .to_string();
        let value = doctor_warns_exactly(&top, &[claim_for_claims_line()]);
        assert_eq!(value["warnings"][0]["place"], "credentials[0]");
        for message in [
            &value["warnings"][0]["message"],
            &value["findings"][0]["message"],
        ] {
            let message = message.as_str().expect("message");
            assert!(message.starts_with("credentials[0]: member"), "{message}");
        }

        let payload = json!({
            "client_id": "x509_hash:abc",
            "dcql_query": age_query_with_claims_under("claim"),
            "payload": { "dcql_query": other },
        })
        .to_string();
        let value = doctor_warns_exactly(&payload, &[claim_for_claims_line()]);
        assert_eq!(value["warnings"][0]["place"], "credentials[0]");
    }

    // A warning about a member of the query object itself has the place
    // `query`, not the name of the member the query was read from.
    let query_level = json!({
        "dcql_query": null,
        "payload": { "client_id": "x509_hash:abc", "dcql_query": { "credential_set": [] } },
    })
    .to_string();
    let value = json_of(&["doctor", &query_level, "--json"], 0);
    assert_eq!(value["ok"], true);
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
    assert_eq!(value["warnings"][0]["place"], "query");
    for message in [
        &value["warnings"][0]["message"],
        &value["findings"][0]["message"],
    ] {
        let message = message.as_str().expect("message");
        assert!(
            message.starts_with("query: member \"credential_set\""),
            "{message}"
        );
    }
}

/// A `dcql_query` in the header only is not the request's query: the OK
/// lines stay.
#[test]
fn doctor_does_not_read_a_query_in_the_header_only() {
    let input = json!({
        "header": { "alg": "ES256", "dcql_query": age_query_with_claims_under("claim") },
        "payload": { "client_id": "x509_hash:abc" },
    })
    .to_string();
    doctor_warns_exactly(&input, &[]);
}

/// A `dcql_query` nested deeper than a direct member of the request or of
/// its payload (here inside `client_metadata`) is not read.
#[test]
fn doctor_does_not_read_a_query_nested_deeper() {
    let nested = json!({ "dcql_query": age_query_with_claims_under("claim") });
    let plain = json!({ "client_id": "x509_hash:abc", "client_metadata": nested }).to_string();
    let pair = json!({
        "header": { "alg": "ES256" },
        "payload": { "client_id": "x509_hash:abc", "client_metadata": nested },
    })
    .to_string();
    for input in [plain, pair] {
        doctor_warns_exactly(&input, &[]);
    }
}

/// The same member in the query of the top level and in the query of the
/// payload is reported once per query, and each line names its query.
#[test]
fn doctor_reports_the_same_member_once_per_query() {
    let input = json!({
        "client_id": "x509_hash:abc",
        "dcql_query": age_query_with_claims_under("claim"),
        "payload": { "dcql_query": age_query_with_claims_under("claim") },
    })
    .to_string();
    let value = doctor_warns_exactly(
        &input,
        &[
            near_miss_line(
                "dcql_query.credentials[0]",
                "claim",
                "Credential Query",
                "claims",
            ),
            near_miss_line(
                "payload.dcql_query.credentials[0]",
                "claim",
                "Credential Query",
                "claims",
            ),
        ],
    );
    assert_eq!(value["findings"].as_array().expect("findings").len(), 2);
}

/// A signed request object whose `dcql_query` has no such member keeps the
/// OK lines, and `--json` carries an empty `warnings` list.
#[test]
fn doctor_without_a_near_miss_member_keeps_its_ok() {
    let request = signed_request_object(
        "clean.jwt",
        "x509_hash:abc",
        &age_query_with_claims_under("claims"),
    );
    for input in [request.as_str(), "fixtures/requests/eudiplo-request.jwt"] {
        let (code, stdout, stderr) = run_cli(&["doctor", input]);
        assert_eq!(code, 0, "{input}: {stdout}{stderr}");
        assert_eq!(stdout, DOCTOR_OK, "{input}");
        let value = json_of(&["doctor", input, "--json"], 0);
        assert_eq!(value["ok"], true, "{input}");
        assert_eq!(value["findings"], json!([]), "{input}");
        assert_eq!(value["warnings"], json!([]), "{input}");
    }
}

/// The findings `doctor` had before are unchanged: the same lines, blocking,
/// exit code 1. Next to a warning they come first and keep the exit code.
#[test]
fn doctor_blocking_findings_are_unchanged_next_to_a_warning() {
    let x5c = "  DOCTOR-X5C-STRING [blocking]: x5c must be a list of strings, even for a single certificate.\n    Fix: Wrap the certificate in an array: \"x5c\": [\"MIIB...\"].\n";
    let client_id = "  DOCTOR-CLIENT-ID-X509HASH [blocking]: client_id must be in the x509_hash form.\n    Fix: Use \"client_id\": \"x509_hash:<base64url(SHA-256(leaf-cert-DER))>\". Compute it with `augenmass x509-hash`.\n";
    let (code, stdout, _) = run_cli(&["doctor", "examples/bad-request.json"]);
    assert_eq!(code, 1);
    assert_eq!(
        stdout,
        format!("Signed-request findings:\n{x5c}{client_id}")
    );
    let value = json_of(&["doctor", "examples/bad-request.json", "--json"], 1);
    assert_eq!(value["ok"], false);
    assert_eq!(value["warnings"], json!([]));
    let findings = value["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f["severity"] == "blocking"));

    let request = signed_request_object(
        "near-miss-and-client-id.jwt",
        "https://verifier.example.org",
        &age_query_with_claims_under("claim"),
    );
    let (code, stdout, _) = run_cli(&["doctor", &request]);
    assert_eq!(code, 1, "{stdout}");
    assert_eq!(
        stdout,
        format!(
            "Signed-request findings:\n{client_id}  DCQL-MEMBER-NEAR-MISS [warning]: {}\n{NEAR_MISS_FIX_LINE}",
            claim_for_claims_line()
        )
    );
    let value = json_of(&["doctor", &request, "--json"], 1);
    assert_eq!(value["ok"], false);
    assert_eq!(value["findings"][0]["id"], "DOCTOR-CLIENT-ID-X509HASH");
    assert_eq!(value["findings"][1]["id"], "DCQL-MEMBER-NEAR-MISS");
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
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
    // The baseline does not model the type, so the request is not evaluated
    // (exit code 3); the block still says what the baseline asks for.
    let text = stdout_of(
        &["audit", "--request", &request, "--purpose", "age_gate_18"],
        3,
    );
    assert!(text.starts_with("NOT EVALUATED: "), "{text}");
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

/// A synthetic registration certificate whose field names follow the public
/// source snapshot of the EUDI Hub; every value is invented.
const HUB_SHAPE_CERT: &str = "fixtures/hub-shape/registration-hub-shape.jwt";
const MERGED_PATH_CERT: &str = "examples/merged-path-registration.jwt";

#[test]
fn hub_shape_registration_decodes() {
    let text = stdout_of(&["decode", "regcert", HUB_SHAPE_CERT], 0);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.contains(&REGCERT_NOTICE), "{text}");
    assert!(
        lines.contains(&"      claim age_equal_or_over.18"),
        "{text}"
    );
    assert!(lines.contains(&"      claim address.postal_code"), "{text}");

    let out = stdout_of(&["decode", "regcert", HUB_SHAPE_CERT, "--json"], 0);
    let decoded: serde_json::Value = serde_json::from_str(&out).expect("decode json");
    let scope = &decoded["scope"];
    assert_eq!(
        scope["purpose"][0]["content"],
        "Example Bottle Shop: confirm the buyer is over 18"
    );
    assert_eq!(
        scope["privacy_policy"],
        "https://bottles.example.org/privacy"
    );
    assert_eq!(scope["support_uri"], "support@bottles.example.org");
    assert_eq!(
        scope["credentials"].as_array().expect("credentials").len(),
        1
    );
    let credential = &scope["credentials"][0];
    assert_eq!(credential["format"], "dc+sd-jwt");
    assert_eq!(credential["vct_values"], json!(["urn:eudi:pid:de:1"]));
    assert_eq!(
        credential["claims"],
        json!([["age_equal_or_over", "18"], ["address", "postal_code"]])
    );
    assert_eq!(decoded["registration_certificate"], not_verified_json());
}

#[test]
fn hub_shape_registration_audits_inside_and_beyond() {
    let inside = audit_json(
        "examples/age-minimal-request-sdjwt.json",
        "age_gate_18",
        Some(HUB_SHAPE_CERT),
        true,
    );
    assert_eq!(inside["counts"]["requested"], 1, "{inside}");
    assert_eq!(inside["counts"]["beyond_registration"], 0, "{inside}");
    assert_eq!(inside["counts"]["beyond_purpose"], 0, "{inside}");
    assert_eq!(inside["registration_certificate"], not_verified_json());

    let request = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["age_equal_or_over","18"]},{"path":["given_name"]}]}]}"#;
    let beyond = audit_json(request, "age_gate_18", Some(HUB_SHAPE_CERT), false);
    assert_eq!(beyond["counts"]["requested"], 2, "{beyond}");
    assert_eq!(beyond["counts"]["beyond_registration"], 1, "{beyond}");
    assert_eq!(beyond["counts"]["beyond_purpose"], 0, "{beyond}");
    let rows = beyond["requested"].as_array().expect("requested");
    assert_eq!(rows[0]["status"], "MinimalForPurpose", "{}", rows[0]);
    assert_eq!(rows[1]["status"], "BeyondRegistration", "{}", rows[1]);
    assert_eq!(
        rows[1]["rationale"], "Not in the relying party's registered scope.",
        "{}",
        rows[1]
    );
}

#[test]
fn merged_path_example_is_beyond_registration() {
    let report = audit_json(
        "examples/merged-path-request.json",
        "event_checkin",
        Some(MERGED_PATH_CERT),
        false,
    );
    assert_eq!(report["counts"]["requested"], 2, "{report}");
    assert_eq!(report["counts"]["beyond_registration"], 2, "{report}");
    assert_eq!(report["counts"]["beyond_purpose"], 0, "{report}");
    for row in report["requested"].as_array().expect("requested") {
        assert_eq!(row["status"], "BeyondRegistration", "{row}");
        assert_eq!(
            row["rationale"], "Not in the relying party's registered scope.",
            "{row}"
        );
    }

    let out = stdout_of(&["decode", "regcert", MERGED_PATH_CERT, "--json"], 0);
    let decoded: serde_json::Value = serde_json::from_str(&out).expect("decode json");
    assert_eq!(
        decoded["scope"]["credentials"][0]["claims"],
        json!([["given_name", "family_name"]])
    );
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
    let report = json_of(
        &[
            "audit",
            "--request",
            request,
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        3,
    );
    assert_eq!(report["outcome"], "not_evaluated", "{report}");
    assert_eq!(report["counts"]["beyond_purpose"], 0, "{report}");
    assert_eq!(report["counts"]["minimal"], 0, "{report}");
    assert_eq!(report["counts"]["could_not_judge"], 1, "{report}");
    let row = &report["requested"][0];
    assert_eq!(row["status"], "NotEvaluated", "{row}");
    assert_eq!(
        row["rationale"],
        "Not evaluated: the purpose baselines model only SD-JWT VC (dc+sd-jwt, vc+sd-jwt) and mso_mdoc claim paths, not the format org.example.format.",
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

// --- the third outcome "not evaluated", credential types of the baselines ---

const PURPOSE_IDS: [&str; 4] = ["age_gate_18", "event_checkin", "car_rental", "bank_kyc"];

const NOT_EVALUATED_LINE: &str =
    "Not evaluated: 1 claim(s). No judged claim asks for too much; exit code 3.";

const PID_TYPES_SENTENCE: &str = "It models dc+sd-jwt and vc+sd-jwt with vct urn:eudi:pid:de:1 or urn:eudi:pid:1, and mso_mdoc with doctype eu.europa.ec.eudi.pid.1.";

/// One DCQL credential query as JSON.
fn credential(
    id: &str,
    format: &str,
    meta: serde_json::Value,
    paths: &[serde_json::Value],
) -> serde_json::Value {
    let claims: Vec<serde_json::Value> = paths.iter().map(|p| json!({ "path": p })).collect();
    json!({ "id": id, "format": format, "meta": meta, "claims": claims })
}

fn dcql(credentials: &[serde_json::Value]) -> String {
    json!({ "credentials": credentials }).to_string()
}

/// The German PID as SD-JWT VC.
fn pid_sd_jwt(paths: &[serde_json::Value]) -> serde_json::Value {
    credential(
        "pid",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:eudi:pid:de:1"] }),
        paths,
    )
}

/// A `jwt_vc_json` credential in the shape of the OpenID4VP 1.0 examples, a
/// format the purpose baselines do not model.
fn jwt_vc(paths: &[serde_json::Value]) -> serde_json::Value {
    credential(
        "vc",
        "jwt_vc_json",
        json!({ "type_values": [["IdentityCredential"]] }),
        paths,
    )
}

/// A mobile driving licence (OpenID4VP 1.0 DCQL example) asking for names
/// in its own namespace and the age element of the German PID namespace.
fn mdl_request() -> String {
    dcql(&[credential(
        "mdl",
        "mso_mdoc",
        json!({ "doctype_value": "org.iso.18013.5.1.mDL" }),
        &[
            json!(["org.iso.18013.5.1", "given_name"]),
            json!(["org.iso.18013.5.1", "family_name"]),
            json!(["eu.europa.ec.eudi.pid.de.1", "age_over_18"]),
        ],
    )])
}

/// An invented membership credential that asks for PID claim names.
fn membership_request() -> String {
    dcql(&[credential(
        "member",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:example:membership:1"] }),
        &[
            json!(["given_name"]),
            json!(["family_name"]),
            json!(["age_equal_or_over", "18"]),
        ],
    )])
}

/// A registration body for the invented "Example Wine Shop".
fn body_with(credentials: serde_json::Value) -> String {
    json!({
        "rpId": "example-wine-shop",
        "support_uri": "support@wine.example.org",
        "privacy_policy": "https://wine.example.org/privacy",
        "purpose": [{ "lang": "en", "content": "Example Wine Shop: confirm the buyer is over 18" }],
        "credentials": credentials,
    })
    .to_string()
}

/// The same credential as [`jwt_vc`], as a registration body entry.
fn jwt_vc_entry(path: serde_json::Value) -> serde_json::Value {
    json!({
        "format": "jwt_vc_json",
        "meta": { "type_values": [["IdentityCredential"]] },
        "claims": [{ "path": path }],
    })
}

fn pid_age_entry() -> serde_json::Value {
    json!({
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["age_equal_or_over", "18"] }],
    })
}

/// An unsigned registration certificate (payload only is read) for the
/// invented "Example Wine Shop" that registers one jwt_vc_json credential
/// with the path `["credentialSubject", "family_name"]`. Returns its path.
fn jwt_vc_certificate() -> String {
    let b64 = |v: &str| BASE64_URL_SAFE_NO_PAD.encode(v.as_bytes());
    let header = json!({ "alg": "ES256", "typ": "rc-wrp+jwt" }).to_string();
    let payload = json!({
        "name": "Example Wine Shop",
        "purpose": [{ "lang": "en", "content": "Example Wine Shop: confirm the buyer's name" }],
        "privacy_policy": "https://wine.example.org/privacy",
        "support_uri": "support@wine.example.org",
        "credentials": [{
            "format": "jwt_vc_json",
            "meta": { "type_values": [["IdentityCredential"]] },
            "claim": [{ "path": ["credentialSubject", "family_name"] }],
        }],
    })
    .to_string();
    let dir = test_temp_dir("augenmass-cli-cert");
    fs::create_dir_all(&dir).expect("create cert dir");
    let path = dir.join("cert-jwt-vc.jwt");
    fs::write(
        &path,
        format!(
            "{}.{}.{}",
            b64(&header),
            b64(&payload),
            b64("not-a-signature")
        ),
    )
    .expect("write certificate");
    path.display().to_string()
}

#[test]
fn audit_unknown_purpose_is_a_usage_error() {
    let cases: [&[&str]; 5] = [
        &[
            "audit",
            "--request",
            "examples/age-minimal-request-sdjwt.json",
            "--purpose",
            "no_such_purpose",
        ],
        &[
            "audit",
            "--request",
            "examples/age-broad-request.json",
            "--purpose",
            "no_such_purpose",
        ],
        &[
            "audit",
            "--request",
            "examples/age-broad-request.json",
            "--cert",
            "examples/age-broad-registration.jwt",
            "--purpose",
            "no_such_purpose",
        ],
        &[
            "--json",
            "audit",
            "--request",
            "examples/age-minimal-request-sdjwt.json",
            "--purpose",
            "no_such_purpose",
        ],
        // The id is checked before the request is read.
        &["audit", "--request", "overask", "--purpose", ""],
    ];
    for args in cases {
        let out = bin().args(args).assert().code(2).get_output().clone();
        assert!(out.stdout.is_empty(), "{args:?}: stdout must stay empty");
        let stderr = String::from_utf8(out.stderr).expect("utf8");
        let id = args.last().expect("purpose id");
        assert!(
            stderr.contains(&format!(
                "unknown purpose '{id}'. Valid purpose ids: age_gate_18, event_checkin, car_rental, bank_kyc (see: augenmass baselines)"
            )),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains("Usage: augenmass audit"), "{stderr}");
        assert!(!stderr.contains("OK"), "{stderr}");
    }
}

#[test]
fn serve_unknown_purpose_is_a_usage_error_at_startup() {
    let port = closed_local_port().to_string();
    // A regression would start the server, so the run is bounded.
    let limit = std::time::Duration::from_secs(30);
    let out = bin()
        .args(["serve", "--purpose", "no_such_purpose", "--port", &port])
        .timeout(limit)
        .assert()
        .code(2)
        .get_output()
        .clone();
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    assert!(
        stderr.contains("unknown purpose 'no_such_purpose'. Valid purpose ids: age_gate_18, event_checkin, car_rental, bank_kyc"),
        "{stderr}"
    );
    assert!(stderr.contains("Usage: augenmass serve"), "{stderr}");
    assert!(!stderr.contains("listening on"), "{stderr}");

    // The environment variable takes the same path.
    bin()
        .env("PURPOSE", "no_such_purpose")
        .args(["serve", "--port", &port])
        .timeout(limit)
        .assert()
        .code(2)
        .stderr(contains("unknown purpose 'no_such_purpose'"));
}

#[test]
fn audit_unmodelled_format_is_not_evaluated_under_every_purpose() {
    let request = dcql(&[jwt_vc(&[json!(["credentialSubject", "family_name"])])]);
    let claim_line = "  [n/a]  credentialSubject.family_name Not evaluated: the purpose baselines model only SD-JWT VC (dc+sd-jwt, vc+sd-jwt) and mso_mdoc claim paths, not the format jwt_vc_json.\n";
    for purpose in PURPOSE_IDS {
        let text = stdout_of(&["audit", "--request", &request, "--purpose", purpose], 3);
        assert!(
            text.starts_with("NOT EVALUATED: 1 of 1 requested claims could not be judged.\n"),
            "{purpose}: {text}"
        );
        assert!(text.contains(claim_line), "{purpose}: {text}");
        assert!(text.contains(NOT_EVALUATED_LINE), "{purpose}: {text}");
        assert!(!text.contains("OVER-ASK"), "{purpose}: {text}");
        assert!(!text.contains("[over]"), "{purpose}: {text}");
        assert!(!text.contains("Legal basis"), "{purpose}: {text}");
        // The baseline's claims are still named.
        assert!(
            text.contains("Suggested minimal request (jwt_vc_json, no type):\n  No claim names are known for this credential type."),
            "{purpose}: {text}"
        );
    }
    // The default purpose (no --purpose) judges the same way.
    let text = stdout_of(&["audit", "--request", &request], 3);
    assert!(text.starts_with("NOT EVALUATED: "), "{text}");
    assert!(text.contains("Baseline: Event check-in"), "{text}");

    let report = json_of(
        &[
            "--json",
            "audit",
            "--request",
            &request,
            "--purpose",
            "age_gate_18",
        ],
        3,
    );
    assert_eq!(report["outcome"], "not_evaluated");
    assert_eq!(report["requested"][0]["status"], "NotEvaluated");
    assert_eq!(report["counts"]["beyond_purpose"], 0);
    assert_eq!(report["counts"]["not_evaluated"], 1);
    assert_eq!(report["counts"]["could_not_judge"], 1);
    assert_eq!(
        report["verdict_line"],
        "1 of 1 requested claims could not be judged."
    );
}

#[test]
fn audit_other_credential_types_are_not_evaluated() {
    let mdl = mdl_request();
    let membership = membership_request();
    for purpose in PURPOSE_IDS {
        for (request, credential_type) in [
            (&mdl, "org.iso.18013.5.1.mDL"),
            (&membership, "urn:example:membership:1"),
        ] {
            let text = stdout_of(&["audit", "--request", request, "--purpose", purpose], 3);
            assert!(
                text.starts_with("NOT EVALUATED: 3 of 3 requested claims could not be judged.\n"),
                "{purpose} {credential_type}: {text}"
            );
            let reason = format!(
                "Not evaluated: the baseline {purpose} does not model the credential type {credential_type}. {PID_TYPES_SENTENCE}\n"
            );
            assert_eq!(text.matches(&reason).count(), 3, "{purpose}: {text}");
            assert!(
                text.contains(
                    "Not evaluated: 3 claim(s). No judged claim asks for too much; exit code 3."
                ),
                "{text}"
            );
            assert!(!text.contains("[ok]"), "{purpose}: {text}");
            assert!(!text.contains("[over]"), "{purpose}: {text}");
        }
    }

    // The Proof of Age attestation is not a PID either.
    let proof_of_age = dcql(&[credential(
        "av",
        "mso_mdoc",
        json!({ "doctype_value": "eu.europa.ec.av.1" }),
        &[json!(["eu.europa.ec.av.1", "age_over_18"])],
    )]);
    let text = stdout_of(
        &[
            "audit",
            "--request",
            &proof_of_age,
            "--purpose",
            "age_gate_18",
        ],
        3,
    );
    assert!(
        text.contains("does not model the credential type eu.europa.ec.av.1."),
        "{text}"
    );

    // A request that names no credential type.
    let untyped_mdoc = json!({ "credentials": [{
        "id": "m", "format": "mso_mdoc",
        "claims": [{ "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"] }],
    }]})
    .to_string();
    let untyped_sd_jwt = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt",
        "claims": [{ "path": ["age_equal_or_over", "18"] }],
    }]})
    .to_string();
    for request in [&untyped_mdoc, &untyped_sd_jwt] {
        let text = stdout_of(
            &["audit", "--request", request, "--purpose", "age_gate_18"],
            3,
        );
        assert!(text.starts_with("NOT EVALUATED: "), "{text}");
        assert!(
            text.contains("Not evaluated: the request names no credential type (meta.vct_values or meta.doctype_value), so the baseline cannot tell which credential is asked for."),
            "{text}"
        );
    }

    let report = json_of(
        &[
            "--json",
            "audit",
            "--request",
            &mdl,
            "--purpose",
            "age_gate_18",
        ],
        3,
    );
    assert_eq!(report["outcome"], "not_evaluated");
    assert_eq!(report["counts"]["could_not_judge"], 3);
    assert_eq!(report["counts"]["minimal"], 0);
    assert_eq!(report["counts"]["beyond_purpose"], 0);
}

#[test]
fn audit_credential_without_claims_is_judged_by_its_type() {
    let no_claims = |id: &str, format: &str, meta: serde_json::Value| {
        json!({ "credentials": [{ "id": id, "format": format, "meta": meta }] }).to_string()
    };
    // A PID credential without claims: nothing to judge, as before.
    let pid = no_claims(
        "pid",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:eudi:pid:de:1"] }),
    );
    let text = stdout_of(&["audit", "--request", &pid, "--purpose", "age_gate_18"], 0);
    assert!(text.starts_with("OK: No claims requested.\n"), "{text}");

    // Another type, and a format the baselines do not model.
    let member = no_claims(
        "member",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:example:membership:1"] }),
    );
    let vc = no_claims(
        "vc",
        "jwt_vc_json",
        json!({ "type_values": [["IdentityCredential"]] }),
    );
    for (request, row) in [
        (&member, "  [n/a]  member (credential, no claims) Not evaluated: the baseline age_gate_18 does not model the credential type urn:example:membership:1."),
        (&vc, "  [n/a]  vc (credential, no claims)   Not evaluated: the purpose baselines model only SD-JWT VC (dc+sd-jwt, vc+sd-jwt) and mso_mdoc claim paths, not the format jwt_vc_json."),
    ] {
        let text = stdout_of(
            &["audit", "--request", request, "--purpose", "age_gate_18"],
            3,
        );
        assert!(text.starts_with("NOT EVALUATED: "), "{text}");
        assert!(text.contains(row), "{text}");
        assert!(!text.contains("No claims requested"), "{text}");
    }
}

#[test]
fn audit_request_accepting_several_types_is_judged_per_type() {
    let two_types = |paths: &[serde_json::Value]| {
        dcql(&[credential(
            "pid",
            "dc+sd-jwt",
            json!({ "vct_values": ["urn:eudi:pid:de:1", "urn:example:membership:1"] }),
            paths,
        )])
    };
    // Within the baseline for the PID; the other accepted type is not modelled.
    let text = stdout_of(
        &[
            "audit",
            "--request",
            &two_types(&[json!(["age_equal_or_over", "18"])]),
            "--purpose",
            "age_gate_18",
        ],
        3,
    );
    assert!(text.starts_with("NOT EVALUATED: "), "{text}");
    assert!(
        text.contains("  [n/a]  age_equal_or_over.18         Not evaluated: within the baseline for urn:eudi:pid:de:1; the request also accepts urn:example:membership:1, which the baseline does not model.\n"),
        "{text}"
    );

    // Beyond the baseline under the PID type stays an over-ask.
    let text = stdout_of(
        &[
            "audit",
            "--request",
            &two_types(&[json!(["age_equal_or_over", "18"]), json!(["birthdate"])]),
            "--purpose",
            "age_gate_18",
        ],
        1,
    );
    assert!(
        text.starts_with(
            "OVER-ASK: Over-ask vs purpose: 1 of 2 requested claims exceed the stated purpose.\n"
        ),
        "{text}"
    );
    assert!(text.contains("  [n/a]  age_equal_or_over.18 "), "{text}");
    assert!(
        text.contains("  [over]  birthdate                    Beyond what the stated purpose needs; registration not evaluated.\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "Over-asking 1 claim(s) beyond the stated purpose.\nNot evaluated: 1 claim(s).\n"
        ),
        "{text}"
    );

    // Both PID types together are modelled: the verdict of 0.4.1.
    let both_pid_types = dcql(&[credential(
        "pid",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:1"] }),
        &[json!(["age_equal_or_over", "18"])],
    )]);
    let text = stdout_of(
        &[
            "audit",
            "--request",
            &both_pid_types,
            "--purpose",
            "age_gate_18",
        ],
        0,
    );
    assert!(
        text.starts_with("OK: Within the purpose-minimal baseline; registration not evaluated.\n"),
        "{text}"
    );
}

#[test]
fn audit_over_ask_wins_over_not_evaluated() {
    let unjudged = jwt_vc(&[json!(["credentialSubject", "family_name"])]);
    let pid_over = pid_sd_jwt(&[json!(["age_equal_or_over", "18"]), json!(["birthdate"])]);
    let pid_minimal = pid_sd_jwt(&[json!(["age_equal_or_over", "18"])]);

    // A PID over-ask next to a credential that cannot be judged: exit 1.
    let request = dcql(&[pid_over, unjudged.clone()]);
    let text = stdout_of(
        &["audit", "--request", &request, "--purpose", "age_gate_18"],
        1,
    );
    assert!(
        text.starts_with(
            "OVER-ASK: Over-ask vs purpose: 1 of 3 requested claims exceed the stated purpose.\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  [ok]  age_equal_or_over.18         Within the purpose-minimal baseline.\n"
        ),
        "{text}"
    );
    assert!(text.contains("  [over]  birthdate "), "{text}");
    assert!(
        text.contains("  [n/a]  credentialSubject.family_name Not evaluated: "),
        "{text}"
    );
    assert!(
        text.contains(
            "Over-asking 1 claim(s) beyond the stated purpose.\nNot evaluated: 1 claim(s).\n"
        ),
        "{text}"
    );
    assert!(text.contains("\nLegal basis:\n"), "{text}");

    // A minimal PID request next to it: nothing judged asks for too much.
    let request = dcql(&[pid_minimal.clone(), unjudged.clone()]);
    let text = stdout_of(
        &["audit", "--request", &request, "--purpose", "age_gate_18"],
        3,
    );
    assert!(
        text.starts_with("NOT EVALUATED: 1 of 2 requested claims could not be judged.\n"),
        "{text}"
    );
    assert!(text.contains("  [ok]  age_equal_or_over.18 "), "{text}");
    assert!(text.contains(NOT_EVALUATED_LINE), "{text}");
    let report = json_of(
        &[
            "--json",
            "audit",
            "--request",
            &request,
            "--purpose",
            "age_gate_18",
        ],
        3,
    );
    assert_eq!(report["outcome"], "not_evaluated");
    assert_eq!(report["counts"]["minimal"], 1);
    assert_eq!(report["counts"]["could_not_judge"], 1);
    assert_eq!(report["requested"][0]["status"], "MinimalForPurpose");
    assert_eq!(report["requested"][1]["status"], "NotEvaluated");

    // The same two credentials as options of one credential set.
    let options = json!({
        "credentials": [pid_minimal, unjudged],
        "credential_sets": [{ "options": [["pid"], ["vc"]] }],
    })
    .to_string();
    let text = stdout_of(
        &["audit", "--request", &options, "--purpose", "age_gate_18"],
        3,
    );
    assert!(text.starts_with("NOT EVALUATED: "), "{text}");
}

#[test]
fn audit_json_outcome_agrees_with_the_exit_code() {
    let not_evaluated = dcql(&[jwt_vc(&[json!(["credentialSubject", "family_name"])])]);
    for (request, code, outcome, headline) in [
        ("examples/age-minimal-request-sdjwt.json", 0, "ok", "OK: "),
        (
            "examples/age-broad-request.json",
            1,
            "over_ask",
            "OVER-ASK: ",
        ),
        (
            not_evaluated.as_str(),
            3,
            "not_evaluated",
            "NOT EVALUATED: ",
        ),
    ] {
        let args = ["audit", "--request", request, "--purpose", "age_gate_18"];
        let text = stdout_of(&args, code);
        assert!(text.starts_with(headline), "{request}: {text}");
        let mut json_args = vec!["--json"];
        json_args.extend(args);
        let report = json_of(&json_args, code);
        assert_eq!(report["outcome"], outcome, "{request}");
        // The fields of 0.4.1 keep their names and types.
        assert!(report["vct"].is_string());
        assert!(report["verdict_line"].is_string());
        assert!(report["requested"].is_array());
        assert!(report["counts"]["beyond_purpose"].is_u64());
        assert!(report["counts"]["not_evaluated"].is_u64());
        assert!(report["counts"]["purpose_evaluated"].is_boolean());
        assert_eq!(report["baseline_label"], "Age gate (over 18)");
        assert_eq!(report["suggested_minimal"], json!(["age_equal_or_over.18"]));
        assert!(report["registration_certificate"].is_null());
        // The additive members.
        assert!(report["counts"]["could_not_judge"].is_u64());
        assert_eq!(report["baseline"]["source"], "built-in");
        assert_eq!(report["baseline"]["id"], "age_gate_18");
        assert_eq!(report["baseline"]["label"], "Age gate (over 18)");
        assert_eq!(
            report["baseline"]["credential_types"],
            json!([
                { "format": "dc+sd-jwt", "vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:1"] },
                { "format": "vc+sd-jwt", "vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:1"] },
                { "format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.pid.1" },
            ])
        );
    }
    let ok = json_of(
        &[
            "--json",
            "audit",
            "--request",
            "examples/age-minimal-request-sdjwt.json",
            "--purpose",
            "age_gate_18",
        ],
        0,
    );
    assert_eq!(ok["counts"]["could_not_judge"], 0);
    assert_eq!(ok["counts"]["not_evaluated"], 0);
}

#[test]
fn pid_requests_keep_their_verdict_and_exit_code() {
    const WITHIN: &str = "OK: Within the purpose-minimal baseline; registration not evaluated.";
    let pid_mdoc = |paths: &[serde_json::Value]| {
        dcql(&[credential(
            "pid-mdoc",
            "mso_mdoc",
            json!({ "doctype_value": "eu.europa.ec.eudi.pid.1" }),
            paths,
        )])
    };
    let eu = "eu.europa.ec.eudi.pid.1";
    let de = "eu.europa.ec.eudi.pid.de.1";
    let eu_vct = dcql(&[credential(
        "pid",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:eudi:pid:1"] }),
        &[json!(["age_equal_or_over", "18"])],
    )]);
    let earlier_format = dcql(&[credential(
        "pid",
        "vc+sd-jwt",
        json!({ "vct_values": ["urn:eudi:pid:de:1"] }),
        &[json!(["age_equal_or_over", "18"])],
    )]);
    let mdoc_de_age = pid_mdoc(&[json!([de, "age_over_18"])]);
    let mdoc_broad_eu = pid_mdoc(&[
        json!([eu, "given_name"]),
        json!([eu, "family_name"]),
        json!([eu, "birth_date"]),
        json!([eu, "nationality"]),
        json!([eu, "age_over_18"]),
    ]);
    let mdoc_broad_de = pid_mdoc(&[
        json!([eu, "given_name"]),
        json!([eu, "family_name"]),
        json!([eu, "birth_date"]),
        json!([de, "age_over_18"]),
    ]);
    let kyc_sd_jwt = dcql(&[pid_sd_jwt(&[
        json!(["given_name"]),
        json!(["family_name"]),
        json!(["birthdate"]),
    ])]);
    let kyc_mdoc = pid_mdoc(&[
        json!([eu, "given_name"]),
        json!([eu, "family_name"]),
        json!([eu, "birth_date"]),
    ]);
    let both_thresholds = dcql(&[pid_sd_jwt(&[
        json!(["age_equal_or_over", "16"]),
        json!(["age_equal_or_over", "18"]),
    ])]);
    let options = json!({
        "credentials": [
            credential("pid-sd", "dc+sd-jwt", json!({ "vct_values": ["urn:eudi:pid:de:1"] }),
                &[json!(["age_equal_or_over", "18"])]),
            credential("pid-mdoc", "mso_mdoc", json!({ "doctype_value": eu }),
                &[json!([de, "age_over_18"])]),
        ],
        "credential_sets": [{ "options": [["pid-sd"], ["pid-mdoc"]] }],
    })
    .to_string();
    // claim_sets and credential_sets that name an id the request does not
    // carry: every declared claim and credential is judged, as before.
    let claim_sets_unresolved = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [
            { "id": "eighteen", "path": ["age_equal_or_over", "18"] },
            { "id": "twentyone", "path": ["age_equal_or_over", "21"] },
        ],
        "claim_sets": [["misspelt"]],
    }]})
    .to_string();
    let credential_sets_unresolved = json!({
        "credentials": [
            credential("pid", "dc+sd-jwt", json!({ "vct_values": ["urn:eudi:pid:de:1"] }),
                &[json!(["age_equal_or_over", "18"])]),
            credential("pid2", "mso_mdoc", json!({ "doctype_value": eu }),
                &[json!([eu, "age_over_18"])]),
        ],
        "credential_sets": [{ "options": [["pid"], ["nosuch"]] }],
    })
    .to_string();
    let cert = "examples/age-broad-registration.jwt";
    let minimal = "examples/age-minimal-request-sdjwt.json";
    let broad = "examples/age-broad-request.json";

    let rows: Vec<(Vec<&str>, i32, &str)> = vec![
        (
            vec!["--request", minimal, "--purpose", "age_gate_18"],
            0,
            WITHIN,
        ),
        (
            vec!["--request", &eu_vct, "--purpose", "age_gate_18"],
            0,
            WITHIN,
        ),
        (
            vec![
                "--request",
                "examples/age-minimal-request-mdoc.json",
                "--purpose",
                "age_gate_18",
            ],
            0,
            WITHIN,
        ),
        (
            vec!["--request", &mdoc_de_age, "--purpose", "age_gate_18"],
            0,
            WITHIN,
        ),
        (
            vec!["--request", broad, "--purpose", "age_gate_18"],
            1,
            "OVER-ASK: Over-ask vs purpose: 5 of 5 requested claims exceed the stated purpose.",
        ),
        (
            vec!["--request", &mdoc_broad_eu, "--purpose", "age_gate_18"],
            1,
            "OVER-ASK: Over-ask vs purpose: 4 of 5 requested claims exceed the stated purpose.",
        ),
        (
            vec!["--request", &mdoc_broad_de, "--purpose", "age_gate_18"],
            1,
            "OVER-ASK: Over-ask vs purpose: 3 of 4 requested claims exceed the stated purpose.",
        ),
        (
            vec!["--request", &kyc_sd_jwt, "--purpose", "bank_kyc"],
            0,
            WITHIN,
        ),
        (
            vec!["--request", &kyc_mdoc, "--purpose", "bank_kyc"],
            0,
            WITHIN,
        ),
        (
            vec![
                "--request",
                "examples/kyc-request-plus-birthdate.json",
                "--purpose",
                "bank_kyc",
            ],
            0,
            WITHIN,
        ),
        // No flags: the built-in minimal request under the default purpose.
        (vec![], 0, WITHIN),
        (vec!["--request", minimal], 0, WITHIN),
        (
            vec!["--request", "overask"],
            1,
            "OVER-ASK: Over-ask vs purpose: 4 of 6 requested claims exceed the stated purpose.",
        ),
        (
            vec!["--request", broad, "--cert", cert],
            1,
            "OVER-ASK: Over-ask vs purpose: 3 of 5 requested claims exceed the stated purpose.",
        ),
        (
            vec!["--cert", "fixtures/regcert/rc-by-id.json"],
            0,
            "OK: Minimal: all 3 requested claims are within purpose and registration.",
        ),
        (
            vec![
                "--request",
                minimal,
                "--cert",
                cert,
                "--purpose",
                "age_gate_18",
            ],
            1,
            "OVER-ASK: Over-ask: 1 of 1 requested claims are outside the registered scope.",
        ),
        (
            vec![
                "--request",
                broad,
                "--cert",
                cert,
                "--purpose",
                "age_gate_18",
            ],
            1,
            "OVER-ASK: Over-ask vs purpose: 5 of 5 requested claims exceed the stated purpose.",
        ),
        (
            vec!["--request", &options, "--purpose", "age_gate_18"],
            0,
            WITHIN,
        ),
        (
            vec!["--request", &earlier_format, "--purpose", "age_gate_18"],
            0,
            WITHIN,
        ),
        (
            vec!["--request", &both_thresholds, "--purpose", "age_gate_18"],
            1,
            "OVER-ASK: Over-ask vs purpose: 1 of 2 requested claims exceed the stated purpose.",
        ),
        (
            vec![
                "--request",
                &claim_sets_unresolved,
                "--purpose",
                "age_gate_18",
            ],
            1,
            "OVER-ASK: Over-ask vs purpose: 1 of 2 requested claims exceed the stated purpose.",
        ),
        (
            vec![
                "--request",
                &credential_sets_unresolved,
                "--purpose",
                "age_gate_18",
            ],
            0,
            WITHIN,
        ),
    ];
    for (flags, code, first_line) in rows {
        let mut args = vec!["audit"];
        args.extend(flags.iter().copied());
        let text = stdout_of(&args, code);
        assert_eq!(text.lines().next(), Some(first_line), "{flags:?}");
        assert!(!text.contains("[n/a]"), "{flags:?}: {text}");
        assert!(!text.contains("Not evaluated"), "{flags:?}: {text}");
    }
}

#[test]
fn exit_codes_of_usage_and_runtime_errors_are_unchanged() {
    // A clap usage error: 2.
    bin().args(["audit", "--no-such-flag"]).assert().code(2);
    // A runtime error returned from main: 1, "Error:" on stderr, no stdout.
    let out = bin()
        .args(["baselines", "no_such_purpose"])
        .assert()
        .code(1)
        .get_output()
        .clone();
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("Error: unknown baseline"));
    let missing = test_temp_dir("augenmass-missing").join("does-not-exist.json");
    let out = bin()
        .args([
            "audit",
            "--request",
            &missing.display().to_string(),
            "--purpose",
            "age_gate_18",
        ])
        .assert()
        .code(1)
        .get_output()
        .clone();
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("Error: "));
}

#[test]
fn audit_help_names_the_default_purpose() {
    let text = stdout_of(&["audit", "--help"], 0);
    assert!(
        text.contains("Purpose baseline id (age_gate_18, event_checkin, car_rental, bank_kyc). Defaults to event_checkin; an unknown id is a usage error"),
        "{text}"
    );
}

#[test]
fn audit_certificate_with_an_unread_credential_type() {
    let cert = jwt_vc_certificate();
    // The registered jwt_vc_json credential covers the requested path; only
    // its type cannot be matched: not evaluated.
    let covered = dcql(&[jwt_vc(&[json!(["credentialSubject", "family_name"])])]);
    let text = stdout_of(
        &[
            "audit",
            "--request",
            &covered,
            "--cert",
            &cert,
            "--purpose",
            "age_gate_18",
        ],
        3,
    );
    assert!(
        text.starts_with("NOT EVALUATED: 1 of 1 requested claims could not be judged.\nRegistration certificate: payload decoded; signature, issuer and revocation status not verified.\n"),
        "{text}"
    );
    assert!(
        text.contains("  [n/a]  credentialSubject.family_name Not evaluated against the registration: a registered jwt_vc_json credential covers this path, but the type of a jwt_vc_json credential is not read (only meta.vct_values and meta.doctype_value are), so the requested credential cannot be matched with it. Not evaluated: the purpose baselines model only SD-JWT VC (dc+sd-jwt, vc+sd-jwt) and mso_mdoc claim paths, not the format jwt_vc_json.\n"),
        "{text}"
    );
    assert!(!text.contains("No registered credential"), "{text}");

    // No registered jwt_vc_json credential covers this path, whatever its
    // type: a proven over-ask, exit code 1.
    let uncovered = dcql(&[jwt_vc(&[json!(["credentialSubject", "birthdate"])])]);
    let args = [
        "audit",
        "--request",
        &uncovered,
        "--cert",
        &cert,
        "--purpose",
        "age_gate_18",
    ];
    let text = stdout_of(&args, 1);
    assert!(
        text.starts_with(
            "OVER-ASK: Over-ask: 1 of 1 requested claims are outside the registered scope.\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  [over]  credentialSubject.birthdate  Not in the registered scope: no registered jwt_vc_json credential covers this path, whatever its type.\n"),
        "{text}"
    );
    let mut json_args = vec!["--json"];
    json_args.extend(args);
    let report = json_of(&json_args, 1);
    assert_eq!(report["outcome"], "over_ask");
    assert_eq!(report["requested"][0]["status"], "BeyondRegistration");
    assert_eq!(report["counts"]["could_not_judge"], 0);

    // A certificate that registers no jwt_vc_json credential at all.
    let text = stdout_of(
        &[
            "audit",
            "--request",
            &covered,
            "--cert",
            "examples/age-broad-registration.jwt",
            "--purpose",
            "age_gate_18",
        ],
        1,
    );
    assert!(
        text.contains("  [over]  credentialSubject.family_name No registered credential of this format and type in the relying party's registered scope.\n"),
        "{text}"
    );
}

#[test]
fn check_not_evaluated_body_blocks_with_exit_code_3() {
    let jwt_body = body_with(json!([jwt_vc_entry(json!([
        "credentialSubject",
        "family_name"
    ]))]));
    let mdl_body = body_with(json!([{
        "format": "mso_mdoc",
        "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
        "claims": [{ "path": ["org.iso.18013.5.1", "family_name"] }],
    }]));
    let mdl_pid_namespace_body = body_with(json!([{
        "format": "mso_mdoc",
        "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
        "claims": [{ "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"] }],
    }]));
    let membership_body = body_with(json!([{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:example:membership:1"] },
        "claims": [{ "path": ["age_equal_or_over", "18"] }],
    }]));
    let mixed_body = body_with(json!([
        pid_age_entry(),
        jwt_vc_entry(json!(["credentialSubject", "family_name"])),
    ]));
    for body in [
        &jwt_body,
        &mdl_body,
        &mdl_pid_namespace_body,
        &membership_body,
        &mixed_body,
    ] {
        let text = stdout_of(&["check", body], 3);
        assert!(text.starts_with("NOT EVALUATED: "), "{text}");
        assert!(text.contains("  [n/a]  "), "{text}");
        assert!(text.contains(NOT_EVALUATED_LINE), "{text}");
        assert!(!text.contains("OK:"), "{text}");
        assert!(!text.contains("ready to register"), "{text}");
        assert!(!text.contains("OVER-ASK"), "{text}");

        let value = json_of(&["--json", "check", body], 3);
        assert_eq!(value["outcome"], "not_evaluated");
        assert_eq!(value["overAsk"], false);
        assert_eq!(value["blockingFormatError"], false);
        assert_eq!(value["block"], true);
        assert_eq!(value["report"]["outcome"], "not_evaluated");
        assert_eq!(value["report"]["counts"]["could_not_judge"], 1);
        assert_eq!(value["report"]["baseline"]["id"], "age_gate_18");
    }
    // The body is its own registration: the path is covered, the type of a
    // jwt_vc_json credential is not read.
    let text = stdout_of(&["check", &jwt_body], 3);
    assert!(
        text.contains("Not evaluated against the registration: a registered jwt_vc_json credential covers this path"),
        "{text}"
    );
    assert!(!text.contains("No registered credential"), "{text}");

    // A PID over-ask in the same body: exit code 1, the other row is n/a.
    let over_body = body_with(json!([
        {
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            "claims": [{ "path": ["age_equal_or_over", "18"] }, { "path": ["birthdate"] }],
        },
        jwt_vc_entry(json!(["credentialSubject", "family_name"])),
    ]));
    let text = stdout_of(&["check", &over_body], 1);
    assert!(
        text.starts_with(
            "OVER-ASK: Over-ask vs purpose: 1 of 3 requested claims exceed the stated purpose.\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  [over]  birthdate                    Registered, but beyond what the stated purpose needs.\n"),
        "{text}"
    );
    assert!(
        text.contains("  [n/a]  credentialSubject.family_name "),
        "{text}"
    );
    assert!(text.contains("Not evaluated: 1 claim(s).\n"), "{text}");
    let value = json_of(&["--json", "check", &over_body], 1);
    assert_eq!(value["outcome"], "over_ask");
    assert_eq!(value["overAsk"], true);
    assert_eq!(value["block"], true);
}

#[test]
fn check_results_that_stay_carry_the_outcome_field() {
    // OK rows: the PID bodies of 0.4.1.
    let mdoc_body = |namespace: &str| {
        body_with(json!([{
            "format": "mso_mdoc",
            "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
            "claims": [{ "path": [namespace, "age_over_18"] }],
        }]))
    };
    let de = mdoc_body("eu.europa.ec.eudi.pid.de.1");
    let eu = mdoc_body("eu.europa.ec.eudi.pid.1");
    for body in ["examples/min.json", de.as_str(), eu.as_str()] {
        let text = stdout_of(&["check", body], 0);
        assert!(
            text.starts_with("OK: no over-ask, no format errors. "),
            "{text}"
        );
        assert!(text.ends_with(" is ready to register.\n"), "{text}");
        let value = json_of(&["--json", "check", body], 0);
        assert_eq!(value["outcome"], "ok");
        assert_eq!(value["overAsk"], false);
        assert_eq!(value["blockingFormatError"], false);
        assert_eq!(value["block"], false);
        assert_eq!(value["report"]["outcome"], "ok");
        assert_eq!(value["report"]["counts"]["could_not_judge"], 0);
    }

    // Over-ask rows.
    let names = body_with(json!([{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["given_name"] }, { "path": ["family_name"] }, { "path": ["birthdate"] }],
    }]));
    for (body, first_line) in [
        (
            "examples/over.json",
            "OVER-ASK: Over-ask vs purpose: 6 of 6 requested claims exceed the stated purpose.",
        ),
        (
            names.as_str(),
            "OVER-ASK: Over-ask vs purpose: 3 of 3 requested claims exceed the stated purpose.",
        ),
    ] {
        let text = stdout_of(&["check", body], 1);
        assert_eq!(text.lines().next(), Some(first_line));
        let value = json_of(&["--json", "check", body], 1);
        assert_eq!(value["outcome"], "over_ask");
        assert_eq!(value["overAsk"], true);
        assert_eq!(value["block"], true);
    }

    // A blocking format error.
    let text = stdout_of(&["check", "examples/bad-path.json"], 1);
    assert!(text.starts_with("Format findings:\n"), "{text}");
    let value = json_of(&["--json", "check", "examples/bad-path.json"], 1);
    assert_eq!(value["outcome"], "format_error");
    assert_eq!(value["blockingFormatError"], true);
    assert_eq!(value["block"], true);
    assert!(value["report"].is_null());
}

#[test]
fn check_credentials_that_is_not_an_array_is_a_format_error() {
    let object = body_with(json!({
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["birthdate"] }],
    }));
    let string = body_with(json!("x"));
    for body in [&object, &string] {
        let text = stdout_of(&["check", body], 1);
        assert!(
            text.contains("  CHECK-CREDENTIALS-SHAPE [blocking]: credentials must be an array of credential objects.\n    Fix: Wrap the credential object in an array: \"credentials\": [ { ... } ].\n"),
            "{text}"
        );
        assert!(!text.contains("OK"), "{text}");
        assert!(!text.contains("ready to register"), "{text}");

        let value = json_of(&["--json", "check", body], 1);
        assert_eq!(value["outcome"], "format_error");
        assert_eq!(value["blockingFormatError"], true);
        assert_eq!(value["block"], true);
        assert_eq!(value["overAsk"], false);
        assert!(value["report"].is_null());
        assert_eq!(value["findings"][0]["id"], "CHECK-CREDENTIALS-SHAPE");
    }

    // A body that requests no credentials passes, and the line says why.
    let mut without: serde_json::Value = serde_json::from_str(&body_with(json!([]))).expect("json");
    let empty = without.to_string();
    without
        .as_object_mut()
        .expect("object")
        .remove("credentials");
    let missing = without.to_string();
    for body in [&empty, &missing] {
        let text = stdout_of(&["check", body], 0);
        assert!(
            text.starts_with("OK: the body requests no credentials; no format errors. "),
            "{text}"
        );
        assert!(text.ends_with(" is ready to register.\n"), "{text}");
        assert!(!text.contains("no over-ask"), "{text}");
        let value = json_of(&["--json", "check", body], 0);
        assert_eq!(value["outcome"], "ok");
        assert_eq!(value["block"], false);
        assert!(value["report"].is_null());
    }
}

#[test]
fn register_refuses_a_body_that_was_not_evaluated() {
    let jwt_body = body_with(json!([jwt_vc_entry(json!([
        "credentialSubject",
        "family_name"
    ]))]));
    let mdl_body = body_with(json!([{
        "format": "mso_mdoc",
        "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
        "claims": [{ "path": ["org.iso.18013.5.1", "family_name"] }],
    }]));
    let membership_body = body_with(json!([{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:example:membership:1"] },
        "claims": [{ "path": ["age_equal_or_over", "18"] }],
    }]));
    let mixed_body = body_with(json!([
        pid_age_entry(),
        jwt_vc_entry(json!(["credentialSubject", "family_name"])),
    ]));
    // A dry run (no --yes, default target clone) makes no request.
    for body in [&jwt_body, &mdl_body, &membership_body, &mixed_body] {
        let (code, stdout, stderr) = isolated_output(&["register", body], &[]);
        assert_eq!(code, 3, "{stdout}\n{stderr}");
        assert!(stdout.starts_with("NOT EVALUATED: "), "{stdout}");
        assert!(
            stdout.ends_with("Refusing to write: this request could not be evaluated (see above). Re-run with --yes --force to write it anyway.\n"),
            "{stdout}"
        );
        assert!(!stdout.contains("DRY RUN"), "{stdout}");
        assert!(!stdout.contains("ready to register"), "{stdout}");
        assert!(!stdout.contains("Writing to"), "{stdout}");
    }

    // An over-ask is refused with exit code 1, as before.
    let over = fs::read_to_string("examples/over.json").expect("over.json");
    let (code, stdout, _) = isolated_output(&["register", &over], &[]);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.contains("Refusing to write: this request over-asks (see above)."),
        "{stdout}"
    );

    // A body whose credentials member is one object: a format error, nothing
    // is offered for writing.
    let object = body_with(json!({
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["birthdate"] }],
    }));
    let (code, stdout, stderr) = isolated_output(&["register", &object], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("CHECK-CREDENTIALS-SHAPE"), "{stdout}");
    assert!(!stdout.contains("DRY RUN"), "{stdout}");
    assert!(!stdout.contains("OK"), "{stdout}");
    assert!(
        stderr.contains("Refusing to write: fix the blocking format errors above."),
        "{stderr}"
    );

    // A clean PID body still gets its dry run.
    let min = fs::read_to_string("examples/min.json").expect("min.json");
    let (code, stdout, _) = isolated_output(&["register", &min], &[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("DRY RUN: nothing written."), "{stdout}");
}

#[test]
fn baselines_state_the_credential_types_they_model() {
    let line = "credential types: dc+sd-jwt and vc+sd-jwt with vct urn:eudi:pid:de:1 or urn:eudi:pid:1; mso_mdoc with doctype eu.europa.ec.eudi.pid.1\n";
    let text = stdout_of(&["baselines"], 0);
    assert_eq!(text.matches(&format!("    {line}")).count(), 4, "{text}");
    let types = json!([
        { "format": "dc+sd-jwt", "vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:1"] },
        { "format": "vc+sd-jwt", "vct_values": ["urn:eudi:pid:de:1", "urn:eudi:pid:1"] },
        { "format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.pid.1" },
    ]);
    let all = json_of(&["--json", "baselines"], 0);
    assert_eq!(all["baselines"].as_array().expect("baselines").len(), 4);
    for (index, id) in PURPOSE_IDS.iter().enumerate() {
        assert_eq!(all["baselines"][index]["id"], *id);
        assert_eq!(all["baselines"][index]["credential_types"], types, "{id}");

        let text = stdout_of(&["baselines", id], 0);
        assert!(text.contains(&format!("  {line}")), "{id}: {text}");
        let one = json_of(&["--json", "baselines", id], 0);
        assert_eq!(one["credential_types"], types, "{id}");
        // The members of 0.4.1 stay.
        assert!(one["minimal_keys"].is_array(), "{id}");
        assert!(one["note"].is_string(), "{id}");
    }
}

// --- `--baseline FILE`: a loaded baseline file (augenmass-baselines/0.1) ---

const EXAMPLE_BASELINES: &str = "examples/baselines-example.json";
const WINE: &str = "example.wine-shop.age-check.wine";
const SPIRITS: &str = "example.wine-shop.age-check.spirits";
const LOYALTY: &str = "example.wine-shop.loyalty-card";

const WINE_FACTS: &str = "Baseline file: baselines-example.json   entry: example.wine-shop.age-check.wine   version: 0.1   status: draft\n";
const DRAFT_LINE: &str = "draft baseline, no legal review\n";
const WINE_APPLIES: &str = "Applies when (stated by the baseline, not checked by this tool): the order holds wine and no spirits (invented rule: wine is sold from 18)\n";
const ASSESSMENT_LINE: &str =
    "A baseline file is its author's assessment, not law and not legal advice.\n";

/// Exit code, stdout and stderr of one run.
fn run_cli(args: &[&str]) -> (i32, String, String) {
    let out = bin().args(args).output().expect("run augenmass");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf8"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

fn audit_with_example(request: &str, entry: &str) -> (i32, String, String) {
    run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        EXAMPLE_BASELINES,
        "--purpose",
        entry,
    ])
}

/// A baseline file in a fresh directory `<tmp>/<unique>/nested/<name>`.
/// Returns its path.
fn baseline_file_in_temp(name: &str, content: &serde_json::Value) -> String {
    let dir = test_temp_dir("augenmass-cli-baseline").join("nested");
    fs::create_dir_all(&dir).expect("create baseline dir");
    let path = dir.join(name);
    fs::write(&path, content.to_string()).expect("write baseline file");
    path.display().to_string()
}

/// A valid file with one entry and no `applies_when`. Every name is invented.
fn one_entry_baseline() -> serde_json::Value {
    json!({
        "schema": "augenmass-baselines/0.1",
        "entries": [{
            "id": "example.test.age",
            "version": "2.0",
            "status": "draft",
            "reviewer": null,
            "claims": [
                {
                    "format": "dc+sd-jwt",
                    "vct_values": ["urn:eudi:pid:de:1"],
                    "minimal": [{ "path": ["age_equal_or_over", "18"], "one_of": "age-claim" }]
                },
                {
                    "format": "mso_mdoc",
                    "doctype_value": "eu.europa.ec.eudi.pid.1",
                    "minimal": [{ "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"], "one_of": "age-claim" }]
                }
            ],
            "one_of": [{ "id": "age-claim", "reason": "invented rule: one age answer per order" }],
            "legal_sources": [{
                "instrument": "Invented Example Ordinance (not a real law, written for this test)",
                "locator": "section 1 (invented)",
                "quote": "Invented for this test."
            }]
        }]
    })
}

/// The Proof of Age attestation of the EU age verification profile.
fn proof_of_age(paths: &[serde_json::Value]) -> serde_json::Value {
    credential(
        "av",
        "mso_mdoc",
        json!({ "doctype_value": "eu.europa.ec.av.1" }),
        paths,
    )
}

fn pid_mdoc(paths: &[serde_json::Value]) -> serde_json::Value {
    credential(
        "pid-mdoc",
        "mso_mdoc",
        json!({ "doctype_value": "eu.europa.ec.eudi.pid.1" }),
        paths,
    )
}

#[test]
fn baseline_file_minimal_request_is_ok_and_names_the_baseline() {
    let (code, stdout, stderr) =
        audit_with_example("examples/age-minimal-request-sdjwt.json", WINE);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(
        stdout,
        format!(
            "OK: Within the purpose-minimal baseline; registration not evaluated.\n\
             Registration purpose: no registration given   Baseline: Example Wine Shop: age check for an order of wine\n\
             {WINE_FACTS}{DRAFT_LINE}{WINE_APPLIES}\n\
             Requested claims:\n  [ok]  age_equal_or_over.18         Minimal under this baseline entry.\n\n\
             {ASSESSMENT_LINE}"
        )
    );
    // The same request under the entry for the other case asks for a
    // threshold that entry does not hold.
    let (code, stdout, _) = audit_with_example("examples/age-minimal-request-sdjwt.json", SPIRITS);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.starts_with("OVER-ASK: "), "{stdout}");
    assert!(
        stdout.contains(
            "entry: example.wine-shop.age-check.spirits   version: 0.1   status: draft\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("Applies when (stated by the baseline, not checked by this tool): the order holds spirits (invented rule: spirits are sold from 21)\n"),
        "{stdout}"
    );
}

#[test]
fn baseline_file_alternative_is_not_an_over_ask_and_prints_its_reason() {
    let (code, stdout, _) = audit_with_example("examples/age-minimal-request-mdoc.json", WINE);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.starts_with("OK: "), "{stdout}");
    assert!(
        stdout.contains("  [alt]  eu.europa.ec.eudi.pid.1.age_over_18 Acceptable alternative, not an over-ask. Reason stated by the baseline: Invented for this example: the same yes-or-no answer, named in the other namespace of the PID.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(WINE_FACTS) && stdout.contains(DRAFT_LINE),
        "{stdout}"
    );
    assert!(stdout.ends_with(ASSESSMENT_LINE), "{stdout}");

    // The German namespace is the minimal row.
    let request = dcql(&[pid_mdoc(&[json!([
        "eu.europa.ec.eudi.pid.de.1",
        "age_over_18"
    ])])]);
    let (code, stdout, _) = audit_with_example(&request, WINE);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains(
            "  [ok]  eu.europa.ec.eudi.pid.de.1.age_over_18 Minimal under this baseline entry.\n"
        ),
        "{stdout}"
    );
}

#[test]
fn baseline_file_claim_beyond_the_baseline_is_an_over_ask() {
    let (code, stdout, _) = audit_with_example("examples/age-broad-request.json", WINE);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.starts_with(
            "OVER-ASK: Over-ask vs purpose: 5 of 5 requested claims exceed the stated purpose.\n"
        ),
        "{stdout}"
    );
    assert_eq!(stdout.matches("  [over]  ").count(), 5, "{stdout}");
    assert!(
        stdout.contains("Beyond the baseline: not a minimal claim and not an acceptable alternative of entry example.wine-shop.age-check.wine for dc+sd-jwt, urn:eudi:pid:de:1.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(WINE_FACTS) && stdout.contains(DRAFT_LINE) && stdout.contains(WINE_APPLIES),
        "{stdout}"
    );
    // The entry's own rows replace the built-in suggestion.
    assert!(!stdout.contains("Suggested minimal request"), "{stdout}");
    assert!(
        stdout.contains(
            "Minimal claims of this baseline entry (dc+sd-jwt, urn:eudi:pid:de:1):\n  [\"age_equal_or_over\", \"18\"] (group \"age-claim\")\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "Acceptable alternatives of this baseline entry (mso_mdoc, eu.europa.ec.av.1):\n  [\"eu.europa.ec.av.1\", \"age_over_18\"] (group \"age-claim\")\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("One claim per request from each group:\n  \"age-claim\": invented rule: one age answer is enough for one order\n"),
        "{stdout}"
    );
    assert!(stdout.contains("\nLegal basis:\n"), "{stdout}");
    assert!(
        stdout.contains("Sources stated by the baseline: 1 (see --json).\n"),
        "{stdout}"
    );
    assert!(
        stdout.ends_with(&format!("\n{ASSESSMENT_LINE}")),
        "{stdout}"
    );

    // A threshold of the other case next to the right one: 21 has no row
    // under the wine entry.
    let request = dcql(&[pid_sd_jwt(&[
        json!(["age_equal_or_over", "18"]),
        json!(["age_equal_or_over", "21"]),
    ])]);
    let (code, stdout, _) = audit_with_example(&request, WINE);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("  [ok]  age_equal_or_over.18"), "{stdout}");
    assert!(
        stdout.contains("  [over]  age_equal_or_over.21"),
        "{stdout}"
    );
}

#[test]
fn baseline_file_two_rows_of_a_one_of_group_in_one_request() {
    let broken = "Beyond the baseline: entry example.wine-shop.age-check.wine allows one claim of the group \"age-claim\" per request (invented rule: one age answer is enough for one order); this request asks for 2 of them, and 2 of these can each be returned in one response together with another claim of the group.";

    // Both namespaces of the PID mdoc in one credential.
    let both = json!({
        "id": "pid-mdoc", "format": "mso_mdoc",
        "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
        "claims": [
            { "id": "de", "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"] },
            { "id": "eu", "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"] },
        ],
    });
    let (code, stdout, _) = audit_with_example(&dcql(std::slice::from_ref(&both)), WINE);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.starts_with("OVER-ASK: Over-ask vs purpose: 2 of 2 "),
        "{stdout}"
    );
    assert_eq!(stdout.matches(broken).count(), 2, "{stdout}");

    // As separate claim_sets options the wallet returns one of them.
    let mut options = both.clone();
    options["claim_sets"] = json!([["de"], ["eu"]]);
    let (code, stdout, _) = audit_with_example(&dcql(&[options]), WINE);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("  [ok]  ") && stdout.contains("  [alt]  "),
        "{stdout}"
    );

    // An id no claim carries proves nothing.
    let mut misspelt = both;
    misspelt["claim_sets"] = json!([["misspelt"]]);
    let (code, stdout, _) = audit_with_example(&dcql(&[misspelt]), WINE);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.contains("claim_sets names an id the request does not carry, so its claims count as requested together."),
        "{stdout}"
    );

    // The PID and the Proof of Age attestation: required together they are
    // two age answers, as options of one set they are one.
    let pid = pid_sd_jwt(&[json!(["age_equal_or_over", "18"])]);
    let av = proof_of_age(&[json!(["eu.europa.ec.av.1", "age_over_18"])]);
    let (code, stdout, _) = audit_with_example(&dcql(&[pid.clone(), av.clone()]), WINE);
    assert_eq!(code, 1, "{stdout}");
    assert_eq!(stdout.matches(broken).count(), 2, "{stdout}");

    let as_options = json!({
        "credentials": [pid, av],
        "credential_sets": [{ "options": [["pid"], ["av"]] }],
    })
    .to_string();
    let (code, stdout, _) = audit_with_example(&as_options, WINE);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.starts_with("OK: "), "{stdout}");
    assert!(
        stdout.contains("  [alt]  eu.europa.ec.av.1.age_over_18"),
        "{stdout}"
    );
}

#[test]
fn baseline_file_credential_type_the_entry_does_not_model_is_not_evaluated() {
    let (code, stdout, _) = audit_with_example(&mdl_request(), WINE);
    assert_eq!(code, 3, "{stdout}");
    assert!(
        stdout.starts_with("NOT EVALUATED: 3 of 3 requested claims could not be judged.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Not evaluated: entry example.wine-shop.age-check.wine does not model the credential type org.iso.18013.5.1.mDL in format mso_mdoc. It models dc+sd-jwt with vct urn:eudi:pid:de:1, mso_mdoc with doctype eu.europa.ec.eudi.pid.1, and mso_mdoc with doctype eu.europa.ec.av.1.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "Not evaluated: 3 claim(s). No judged claim asks for too much; exit code 3.\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(WINE_FACTS) && stdout.contains(DRAFT_LINE),
        "{stdout}"
    );
    assert!(stdout.ends_with(ASSESSMENT_LINE), "{stdout}");

    // A baseline file is not limited to PID types, and a claim the author
    // leaves open is not evaluated with the stated reason.
    let card = |paths: &[serde_json::Value]| {
        dcql(&[credential(
            "card",
            "dc+sd-jwt",
            json!({ "vct_values": ["urn:example:loyalty:1"] }),
            paths,
        )])
    };
    let (code, stdout, _) = audit_with_example(&card(&[json!(["member_id"])]), LOYALTY);
    assert_eq!(code, 0, "{stdout}");
    // An entry without applies_when prints no "Applies when" line.
    assert!(!stdout.contains("Applies when"), "{stdout}");
    let (code, stdout, _) =
        audit_with_example(&card(&[json!(["member_id"]), json!(["tier"])]), LOYALTY);
    assert_eq!(code, 3, "{stdout}");
    assert!(
        stdout.contains("  [n/a]  tier                         Not evaluated: the baseline leaves this claim open. Reason stated by the baseline: Invented for this example: whether the discount tier is needed at checkout is left open.\n"),
        "{stdout}"
    );
    // The PID is not a type of the loyalty entry.
    let (code, stdout, _) = audit_with_example("examples/age-minimal-request-sdjwt.json", LOYALTY);
    assert_eq!(code, 3, "{stdout}");
    assert!(stdout.starts_with("NOT EVALUATED: "), "{stdout}");
}

#[test]
fn baseline_file_json_carries_the_outcome_and_the_baseline_facts() {
    let run = |request: &str, code: i32| {
        json_of(
            &[
                "--json",
                "audit",
                "--request",
                request,
                "--baseline",
                EXAMPLE_BASELINES,
                "--purpose",
                WINE,
            ],
            code,
        )
    };

    // Minimal.
    let ok = run("examples/age-minimal-request-sdjwt.json", 0);
    assert_eq!(ok["outcome"], "ok");
    assert_eq!(ok["requested"][0]["status"], "MinimalForPurpose");
    assert_eq!(ok["counts"]["minimal"], 1);
    assert_eq!(ok["counts"]["acceptable_alternative"], 0);
    let b = &ok["baseline"];
    assert_eq!(b["source"], "file");
    assert_eq!(b["file"], "baselines-example.json");
    assert_eq!(b["schema"], "augenmass-baselines/0.1");
    assert_eq!(b["entry_id"], WINE);
    assert_eq!(
        b["label"],
        "Example Wine Shop: age check for an order of wine"
    );
    assert_eq!(b["version"], "0.1");
    assert_eq!(b["status"], "draft");
    assert_eq!(b["reviewer"], serde_json::Value::Null);
    assert!(b.get("legal_review").is_none());
    assert_eq!(b["notice"], "draft baseline, no legal review");
    assert_eq!(
        b["applies_when"],
        "the order holds wine and no spirits (invented rule: wine is sold from 18)"
    );
    assert_eq!(
        b["assessment_notice"],
        "A baseline file is its author's assessment, not law and not legal advice."
    );
    assert_eq!(
        b["credential_types"],
        json!([
            { "format": "dc+sd-jwt", "vct_values": ["urn:eudi:pid:de:1"] },
            { "format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.pid.1" },
            { "format": "mso_mdoc", "doctype_value": "eu.europa.ec.av.1" },
        ])
    );
    assert_eq!(
        b["claims"][1]["alternatives"][0]["path"],
        json!(["eu.europa.ec.eudi.pid.1", "age_over_18"])
    );
    assert_eq!(b["one_of"][0]["id"], "age-claim");
    let source = &b["legal_sources"][0];
    assert!(
        source["instrument"]
            .as_str()
            .expect("instrument")
            .contains("Invented")
            && source["instrument"]
                .as_str()
                .expect("instrument")
                .contains("not a real law"),
        "{source}"
    );
    assert!(source.get("url").is_none(), "{source}");
    // The members of 0.4.1 keep name and type; the built-in suggestion
    // members are null under a loaded baseline.
    assert_eq!(
        ok["baseline_label"],
        "Example Wine Shop: age check for an order of wine"
    );
    assert_eq!(
        ok["baseline_note"],
        "draft baseline, no legal review. A baseline file is its author's assessment, not law and not legal advice."
    );
    assert!(ok["suggested_minimal"].is_null() && ok["suggested_minimal_request"].is_null());
    assert_eq!(ok["legal_basis"].as_array().expect("legal_basis").len(), 3);
    assert!(ok["verdict_line"].is_string() && ok["claim_rows"].is_array());
    assert!(ok["registration_certificate"].is_null());

    // Alternative.
    let alt = run("examples/age-minimal-request-mdoc.json", 0);
    assert_eq!(alt["outcome"], "ok");
    assert_eq!(alt["requested"][0]["status"], "AcceptableAlternative");
    assert_eq!(alt["counts"]["acceptable_alternative"], 1);
    assert_eq!(alt["counts"]["minimal"], 0);
    assert_eq!(alt["counts"]["beyond_purpose"], 0);

    // Beyond the baseline.
    let over = run("examples/age-broad-request.json", 1);
    assert_eq!(over["outcome"], "over_ask");
    assert_eq!(over["counts"]["beyond_purpose"], 5);
    assert_eq!(over["requested"][2]["status"], "BeyondPurpose");
    assert_eq!(over["baseline"]["entry_id"], WINE);

    // A credential type the entry does not model.
    let unjudged = run(&mdl_request(), 3);
    assert_eq!(unjudged["outcome"], "not_evaluated");
    assert_eq!(unjudged["counts"]["could_not_judge"], 3);
    assert_eq!(unjudged["requested"][0]["status"], "NotEvaluated");
    assert_eq!(
        unjudged["baseline"]["notice"],
        "draft baseline, no legal review"
    );

    // A built-in run has the new count at 0 and no file facts.
    let built_in = json_of(
        &[
            "--json",
            "audit",
            "--request",
            "examples/age-minimal-request-sdjwt.json",
            "--purpose",
            "age_gate_18",
        ],
        0,
    );
    assert_eq!(built_in["baseline"]["source"], "built-in");
    assert_eq!(built_in["counts"]["acceptable_alternative"], 0);
}

#[test]
fn baseline_file_reviewed_entry_names_the_reviewer_and_has_no_draft_label() {
    let mut file = one_entry_baseline();
    file["entries"][0]["status"] = json!("reviewed");
    file["entries"][0]["reviewer"] = json!("Example Reviewer");
    let path = baseline_file_in_temp("reviewed.json", &file);
    let request = "examples/age-minimal-request-sdjwt.json";

    let (code, stdout, stderr) = run_cli(&["audit", "--request", request, "--baseline", &path]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stdout.contains("Baseline file: reviewed.json   entry: example.test.age   version: 2.0   status: reviewed\nreviewed by Example Reviewer (as stated by the baseline file)\n"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("draft baseline, no legal review"),
        "{stdout}"
    );
    // Without a label the entry id is the baseline label.
    assert!(stdout.contains("Baseline: example.test.age\n"), "{stdout}");

    let json = json_of(
        &["--json", "audit", "--request", request, "--baseline", &path],
        0,
    );
    assert_eq!(json["baseline"]["status"], "reviewed");
    assert_eq!(json["baseline"]["reviewer"], "Example Reviewer");
    assert!(json["baseline"].get("legal_review").is_none());
    assert_eq!(
        json["baseline"]["notice"],
        "reviewed by Example Reviewer (as stated by the baseline file)"
    );
    assert_eq!(json["baseline"]["applies_when"], serde_json::Value::Null);

    // The same file as a draft carries the label.
    let draft = baseline_file_in_temp("draft.json", &one_entry_baseline());
    let (code, stdout, _) = run_cli(&["audit", "--request", request, "--baseline", &draft]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("status: draft\ndraft baseline, no legal review\n"),
        "{stdout}"
    );
}

#[test]
fn baseline_file_is_named_by_its_file_name_only() {
    let path = baseline_file_in_temp("my-baselines.json", &one_entry_baseline());
    assert!(Path::new(&path).is_absolute(), "{path}");
    let dir = Path::new(&path)
        .parent()
        .expect("parent")
        .display()
        .to_string();
    let request = "examples/age-broad-request.json";

    let (code, stdout, stderr) = run_cli(&["audit", "--request", request, "--baseline", &path]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(
        stdout.contains("Baseline file: my-baselines.json   entry: "),
        "{stdout}"
    );
    assert!(
        !stdout.contains(&dir) && !stdout.contains("nested"),
        "{stdout}"
    );

    let (code, stdout, _) =
        run_cli(&["--json", "audit", "--request", request, "--baseline", &path]);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        !stdout.contains(&dir) && !stdout.contains("nested"),
        "{stdout}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(json["baseline"]["file"], "my-baselines.json");

    // Also in the errors: a usage error and a file that does not load.
    let (code, stdout, stderr) = run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        &path,
        "--purpose",
        "no.such.entry",
    ]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("no entry 'no.such.entry' in baseline file my-baselines.json. Entry ids: example.test.age."),
        "{stderr}"
    );
    assert!(
        !stderr.contains(&dir) && !stderr.contains("nested"),
        "{stderr}"
    );

    let missing = format!("{dir}/not-there.json");
    let (code, stdout, stderr) = run_cli(&["audit", "--request", request, "--baseline", &missing]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.starts_with("Error: baseline file not-there.json: cannot be read: "),
        "{stderr}"
    );
    assert!(
        !stderr.contains(&dir) && !stderr.contains("nested"),
        "{stderr}"
    );
}

#[test]
fn baseline_file_entry_selection() {
    let request = "examples/age-minimal-request-sdjwt.json";

    // Several entries: one must be named. Nothing is judged without it.
    for json_flag in [false, true] {
        let mut args = vec![
            "audit",
            "--request",
            request,
            "--baseline",
            EXAMPLE_BASELINES,
        ];
        if json_flag {
            args.insert(0, "--json");
        }
        let (code, stdout, stderr) = run_cli(&args);
        assert_eq!(code, 2, "{stdout}{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(!stderr.contains("OK"), "{stderr}");
        assert!(
            stderr.contains("baseline file baselines-example.json has 3 entries; name the one to judge against with --purpose <entry id>:\n"),
            "{stderr}"
        );
        assert!(
            stderr.contains("  example.wine-shop.age-check.wine  applies when: the order holds wine and no spirits (invented rule: wine is sold from 18)\n"),
            "{stderr}"
        );
        assert!(
            stderr.contains("  example.wine-shop.age-check.spirits  applies when: the order holds spirits (invented rule: spirits are sold from 21)\n"),
            "{stderr}"
        );
        assert!(
            stderr.contains("  example.wine-shop.loyalty-card\n"),
            "{stderr}"
        );
        assert!(stderr.contains("Usage: augenmass audit"), "{stderr}");
    }

    // One entry without applies_when: --purpose is optional, and may name it.
    let one = baseline_file_in_temp("one.json", &one_entry_baseline());
    let (code, stdout, _) = run_cli(&["audit", "--request", request, "--baseline", &one]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("entry: example.test.age   version: 2.0"),
        "{stdout}"
    );
    let (code, _, _) = run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        &one,
        "--purpose",
        "example.test.age",
    ]);
    assert_eq!(code, 0);

    // One entry that states a case: it is never applied without being named.
    let mut case = one_entry_baseline();
    case["entries"][0]["applies_when"] = json!("the order holds wine");
    let case = baseline_file_in_temp("case.json", &case);
    let (code, stdout, stderr) = run_cli(&["audit", "--request", request, "--baseline", &case]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("entry 'example.test.age' applies only when: the order holds wine. Name it with --purpose example.test.age if that is the case you are checking."),
        "{stderr}"
    );
    let (code, stdout, _) = run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        &case,
        "--purpose",
        "example.test.age",
    ]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("Applies when (stated by the baseline, not checked by this tool): the order holds wine\n"),
        "{stdout}"
    );

    // An id the file does not hold.
    let (code, stdout, stderr) = audit_with_example(request, "example.wine-shop.no-such-entry");
    assert_eq!(code, 2);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("no entry 'example.wine-shop.no-such-entry' in baseline file baselines-example.json. Entry ids: example.wine-shop.age-check.wine, example.wine-shop.age-check.spirits, example.wine-shop.loyalty-card."),
        "{stderr}"
    );
    assert!(!stderr.contains("built-in purpose"), "{stderr}");
}

#[test]
fn baseline_file_and_a_built_in_purpose_id_are_not_mixed() {
    let request = "examples/age-minimal-request-sdjwt.json";
    for id in PURPOSE_IDS {
        for file in [
            EXAMPLE_BASELINES.to_string(),
            baseline_file_in_temp("one.json", &one_entry_baseline()),
        ] {
            let (code, stdout, stderr) = run_cli(&[
                "audit",
                "--request",
                request,
                "--baseline",
                &file,
                "--purpose",
                id,
            ]);
            assert_eq!(code, 2, "{id}: {stdout}{stderr}");
            assert!(stdout.is_empty(), "{id}: {stdout}");
            assert!(
                stderr.contains(&format!(
                    "'{id}' is a built-in purpose; it is not used together with --baseline. Drop --baseline to use it."
                )),
                "{id}: {stderr}"
            );
        }
    }
    // A file cannot claim a built-in id for one of its entries either.
    let mut reserved = one_entry_baseline();
    reserved["entries"][0]["id"] = json!("age_gate_18");
    let reserved = baseline_file_in_temp("reserved.json", &reserved);
    let (code, stdout, stderr) = run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        &reserved,
        "--purpose",
        "age_gate_18",
    ]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("Error: baseline file reserved.json: entries[0].id: \"age_gate_18\" is the id of a built-in purpose"),
        "{stderr}"
    );
    // Without --baseline the built-in purposes work as before.
    let (code, stdout, _) = run_cli(&["audit", "--request", request, "--purpose", "age_gate_18"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains("Baseline file"), "{stdout}");
    assert!(!stdout.contains("author's assessment"), "{stdout}");
}

#[test]
fn baseline_file_that_does_not_match_the_format_is_an_error_never_a_pass() {
    type Change = fn(&mut serde_json::Value);
    let cases: [(&str, Change, &str); 9] = [
        (
            "unknown schema id",
            |v| v["schema"] = json!("augenmass-baselines/9.9"),
            "schema: unknown schema id \"augenmass-baselines/9.9\"; this version reads only \"augenmass-baselines/0.1\"",
        ),
        (
            "duplicate entry ids",
            |v| {
                let copy = v["entries"][0].clone();
                v["entries"].as_array_mut().expect("entries").push(copy);
            },
            "entries[1]: duplicate entry id \"example.test.age\"",
        ),
        (
            "entry without claims",
            |v| {
                v["entries"][0].as_object_mut().expect("entry").remove("claims");
            },
            "entries[0] (example.test.age): \"claims\" is missing; an entry without claims judges nothing",
        ),
        (
            "entry with an empty claims list",
            |v| v["entries"][0]["claims"] = json!([]),
            "claims: must be a non-empty list of credential blocks",
        ),
        (
            "malformed path: a dotted string",
            |v| v["entries"][0]["claims"][0]["minimal"][0]["path"] = json!("age_equal_or_over.18"),
            "claims[0].minimal[0].path: must be a non-empty array of strings, nulls and non-negative integers (a claims path pointer)",
        ),
        (
            "malformed path: a negative index",
            |v| v["entries"][0]["claims"][0]["minimal"][0]["path"] = json!(["age_equal_or_over", -1]),
            "claims[0].minimal[0].path: must be a non-empty array",
        ),
        (
            "malformed path: three mdoc segments",
            |v| {
                v["entries"][0]["claims"][1]["minimal"][0]["path"] =
                    json!(["eu.europa.ec.eudi.pid.de.1", "age_over_18", "x"])
            },
            "claims[1].minimal[0].path: an mso_mdoc path is exactly two strings: [namespace, data element]",
        ),
        (
            "misspelt machine field: minimial",
            |v| {
                let block = v["entries"][0]["claims"][0].as_object_mut().expect("block");
                let rows = block.remove("minimal").expect("minimal");
                block.insert("minimial".to_string(), rows);
            },
            "claims[0]: unknown member \"minimial\" (known members: format, vct_values, doctype_value, minimal, alternatives, undecided)",
        ),
        (
            "misspelt machine field: statuss",
            |v| {
                let entry = v["entries"][0].as_object_mut().expect("entry");
                let status = entry.remove("status").expect("status");
                entry.insert("statuss".to_string(), status);
            },
            "entries[0]: unknown member \"statuss\"",
        ),
    ];
    let request = "examples/age-minimal-request-sdjwt.json";
    for (name, change, expected) in cases {
        let mut file = one_entry_baseline();
        change(&mut file);
        let path = baseline_file_in_temp("broken.json", &file);
        for command in ["audit", "check"] {
            for json_flag in [false, true] {
                let mut args = match command {
                    "audit" => vec!["audit", "--request", request, "--baseline", &path],
                    _ => vec!["check", "examples/min.json", "--baseline", &path],
                };
                if json_flag {
                    args.insert(0, "--json");
                }
                let (code, stdout, stderr) = run_cli(&args);
                assert_eq!(code, 1, "{name} ({command}): {stdout}{stderr}");
                assert!(stdout.is_empty(), "{name} ({command}): {stdout}");
                assert!(
                    stderr.starts_with("Error: baseline file broken.json: "),
                    "{name} ({command}): {stderr}"
                );
                assert!(stderr.contains(expected), "{name} ({command}): {stderr}");
                assert!(!stderr.contains("OK"), "{name} ({command}): {stderr}");
            }
        }
    }

    // A member name given twice: the second "status" would otherwise win
    // silently.
    let text = one_entry_baseline().to_string().replace(
        "\"status\":\"draft\"",
        "\"status\":\"draft\",\"status\":\"reviewed\",\"reviewer\":\"Nobody\"",
    );
    let dir = test_temp_dir("augenmass-cli-baseline-dup");
    fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("twice.json");
    fs::write(&path, text).expect("write");
    let (code, stdout, stderr) = run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        &path.display().to_string(),
    ]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("Error: baseline file twice.json: the document: the member \"status\" occurs twice in one object"),
        "{stderr}"
    );

    // Not a baseline file at all: a DCQL request.
    let (code, stdout, stderr) = run_cli(&[
        "audit",
        "--request",
        request,
        "--baseline",
        "examples/age-minimal-request-sdjwt.json",
    ]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.starts_with("Error: baseline file age-minimal-request-sdjwt.json: the document: unknown member \"credentials\""),
        "{stderr}"
    );
}

#[test]
fn check_with_a_baseline_file() {
    let args = |body: &str| {
        vec![
            "check".to_string(),
            body.to_string(),
            "--baseline".to_string(),
            EXAMPLE_BASELINES.to_string(),
            "--purpose".to_string(),
            WINE.to_string(),
        ]
    };
    let run = |body: &str| {
        let owned = args(body);
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        run_cli(&refs)
    };
    let run_json = |body: &str, code: i32| {
        let mut owned = args(body);
        owned.insert(0, "--json".to_string());
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        json_of(&refs, code)
    };

    // A body within the entry passes, and the result names the baseline.
    let (code, stdout, stderr) = run("examples/min.json");
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(
        stdout,
        format!(
            "OK: no over-ask, no format errors. examples/min.json is ready to register.\n{WINE_FACTS}{DRAFT_LINE}{WINE_APPLIES}{ASSESSMENT_LINE}"
        )
    );
    let json = run_json("examples/min.json", 0);
    assert_eq!(json["outcome"], "ok");
    assert_eq!(json["block"], false);
    assert_eq!(json["baseline"]["file"], "baselines-example.json");
    assert_eq!(json["baseline"]["entry_id"], WINE);
    assert_eq!(json["report"]["baseline"]["entry_id"], WINE);
    assert_eq!(
        json["report"]["requested"][0]["status"],
        "MinimalForPurpose"
    );

    // A claim beyond the entry blocks with exit code 1.
    let (code, stdout, _) = run("examples/over.json");
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.starts_with("OVER-ASK: "), "{stdout}");
    assert!(
        stdout.contains(WINE_FACTS) && stdout.contains(DRAFT_LINE),
        "{stdout}"
    );
    assert!(stdout.contains(ASSESSMENT_LINE), "{stdout}");

    // A body is not one request: it lists everything the party may ask. Two
    // rows of a one-of group in it are not evaluated, not an over-ask.
    let two_formats = body_with(json!([
        pid_age_entry(),
        {
            "format": "mso_mdoc",
            "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
            "claims": [{ "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"] }],
        },
    ]));
    let (code, stdout, _) = run(&two_formats);
    assert_eq!(code, 3, "{stdout}");
    assert!(stdout.starts_with("NOT EVALUATED: 2 of 2 "), "{stdout}");
    assert_eq!(
        stdout
            .matches("Not evaluated: entry example.wine-shop.age-check.wine allows one claim of the group \"age-claim\" per request. A registration may list more than one where the intended use needs each; this tool cannot check that.")
            .count(),
        2,
        "{stdout}"
    );
    let json = run_json(&two_formats, 3);
    assert_eq!(json["outcome"], "not_evaluated");
    assert_eq!(json["block"], true);
    assert_eq!(json["overAsk"], false);
    assert_eq!(json["report"]["counts"]["could_not_judge"], 2);

    // A format error names the baseline too, and judges nothing.
    let (code, stdout, _) = run("examples/bad-path.json");
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("CHECK-PATH-STRING"), "{stdout}");
    assert!(!stdout.contains("OK"), "{stdout}");
    assert!(stdout.contains(WINE_FACTS), "{stdout}");
    let json = run_json("examples/bad-path.json", 1);
    assert_eq!(json["outcome"], "format_error");
    assert!(json["report"].is_null());
    assert_eq!(json["baseline"]["entry_id"], WINE);

    // Without --baseline `check` is unchanged and carries no baseline member
    // at the top level.
    let plain = json_of(&["--json", "check", "examples/min.json"], 0);
    assert!(plain.get("baseline").is_none(), "{plain}");
    assert_eq!(plain["report"]["baseline"]["source"], "built-in");
    let text = stdout_of(&["check", "examples/min.json"], 0);
    assert_eq!(
        text,
        "OK: no over-ask, no format errors. examples/min.json is ready to register.\n"
    );
}

#[test]
fn check_entry_selection_and_purpose_without_a_baseline_file() {
    // --purpose belongs to --baseline: `check` has no built-in purpose flag.
    let (code, stdout, stderr) =
        run_cli(&["check", "examples/min.json", "--purpose", "age_gate_18"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("--baseline <FILE>"), "{stderr}");

    // Several entries and no --purpose.
    let (code, stdout, stderr) = run_cli(&[
        "check",
        "examples/min.json",
        "--baseline",
        EXAMPLE_BASELINES,
    ]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("has 3 entries"), "{stderr}");
    assert!(stderr.contains("Usage: augenmass check"), "{stderr}");

    // A built-in id next to --baseline.
    let (code, stdout, stderr) = run_cli(&[
        "check",
        "examples/min.json",
        "--baseline",
        EXAMPLE_BASELINES,
        "--purpose",
        "age_gate_18",
    ]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("is a built-in purpose"), "{stderr}");

    // One entry without applies_when needs no --purpose.
    let one = baseline_file_in_temp("one.json", &one_entry_baseline());
    let (code, stdout, _) = run_cli(&["check", "examples/min.json", "--baseline", &one]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains(
            "Baseline file: one.json   entry: example.test.age   version: 2.0   status: draft\n"
        ),
        "{stdout}"
    );
}

#[test]
fn baseline_flag_is_in_the_help_of_audit_and_check() {
    for command in ["audit", "check"] {
        let text = stdout_of(&[command, "--help"], 0);
        assert!(text.contains("--baseline <FILE>"), "{command}: {text}");
        assert!(
            text.contains("augenmass-baselines/0.1"),
            "{command}: {text}"
        );
    }
    // `register` gets no baseline flag.
    let text = stdout_of(&["register", "--help"], 0);
    assert!(!text.contains("--baseline"), "{text}");
}

#[test]
fn example_baseline_file_marks_its_legal_source_as_invented() {
    let text = fs::read_to_string(EXAMPLE_BASELINES).expect("example file");
    let file: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(file["schema"], "augenmass-baselines/0.1");
    let entries = file["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3);
    for entry in entries {
        assert_eq!(entry["status"], "draft", "{}", entry["id"]);
        let sources = entry["legal_sources"].as_array().expect("legal_sources");
        assert!(!sources.is_empty(), "{}", entry["id"]);
        for source in sources {
            let instrument = source["instrument"].as_str().expect("instrument");
            assert!(instrument.contains("Invented"), "{instrument}");
            assert!(instrument.contains("not a real law"), "{instrument}");
            assert!(
                source["quote"]
                    .as_str()
                    .expect("quote")
                    .starts_with("Invented"),
                "{source}"
            );
            assert!(source.get("url").is_none(), "{source}");
        }
    }
    assert!(file["info"]["note"]
        .as_str()
        .expect("note")
        .contains("invented"));
    // The example is visibly not the German age set: thresholds 18 and 21.
    assert!(
        !text.contains("\"16\"") && !text.contains("age_over_16"),
        "{text}"
    );
}

// --- fix round after the 0.5.0 branch review --------------------------------

/// A baseline with one entry `example.test.rows` for the invented type
/// `urn:example:rows:1`, with the given minimal rows and the group `g`.
fn rows_baseline(minimal: serde_json::Value) -> serde_json::Value {
    json!({
        "schema": "augenmass-baselines/0.1",
        "entries": [{
            "id": "example.test.rows",
            "version": "1",
            "status": "draft",
            "claims": [{
                "format": "dc+sd-jwt",
                "vct_values": ["urn:example:rows:1"],
                "minimal": minimal,
            }],
            "one_of": [{ "id": "g", "reason": "invented rule: only one" }],
            "legal_sources": [],
        }],
    })
}

/// Two rows of which neither covers the other can still cover one path
/// (`["a", null, 0]` and `["a", 0, null]` both cover `["a", 0, 0]`). Such a
/// file is rejected in either row order: before, the first row in file order
/// won, and an ungrouped first row hid the one-of group of the second.
#[test]
fn baseline_file_rows_with_crossed_wildcards_are_rejected() {
    let request = dcql(&[credential(
        "c",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:example:rows:1"] }),
        &[json!(["a", 0, 0]), json!(["b"])],
    )]);
    let ungrouped = json!({ "path": ["a", null, 0] });
    let grouped = json!({ "path": ["a", 0, null], "one_of": "g" });
    let other = json!({ "path": ["b"], "one_of": "g" });
    for rows in [
        json!([ungrouped, grouped, other]),
        json!([grouped, ungrouped, other]),
    ] {
        let file = baseline_file_in_temp("crossed.json", &rows_baseline(rows));
        for command in [
            vec!["audit", "--request", &request, "--baseline", &file],
            vec![
                "--json",
                "audit",
                "--request",
                &request,
                "--baseline",
                &file,
            ],
        ] {
            let (code, stdout, stderr) = run_cli(&command);
            assert_eq!(code, 1, "{stdout}\n{stderr}");
            assert!(stdout.is_empty(), "{stdout}");
            assert!(
                stderr.starts_with("Error: baseline file crossed.json: entries[0] (example.test.rows).claims[0]: the rows "),
                "{stderr}"
            );
            assert!(
                stderr.contains("overlap (both cover the path [\"a\", 0, 0]); a requested claim must match at most one row of a block"),
                "{stderr}"
            );
        }
    }

    // The same rows across two lists (minimal and undecided), in `check`.
    let mut file = rows_baseline(json!([{ "path": ["a", null, "b", 0] }]));
    file["entries"][0]["claims"][0]["undecided"] =
        json!([{ "path": ["a", 0, "b", null], "reason": "invented: left open" }]);
    file["entries"][0]["one_of"] = json!([]);
    let file = baseline_file_in_temp("crossed-lists.json", &file);
    let body = body_with(json!([{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:example:rows:1"] },
        "claims": [{ "path": ["a", 0, "b", 0] }],
    }]));
    let (code, stdout, stderr) = run_cli(&["check", &body, "--baseline", &file]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("the rows [\"a\", null, \"b\", 0] and [\"a\", 0, \"b\", null] overlap (both cover the path [\"a\", 0, \"b\", 0])"),
        "{stderr}"
    );
}

/// `claim_sets` with one option per age claim keeps the two apart within one
/// returned credential. With `multiple: true` the response can hold several
/// credentials of the query, one per option, so both rows of the group can
/// reach the verifier in one response.
#[test]
fn baseline_file_multiple_defeats_separate_claim_sets_options() {
    let mut pid = json!({
        "id": "pid", "format": "mso_mdoc",
        "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
        "claims": [
            { "id": "de", "path": ["eu.europa.ec.eudi.pid.de.1", "age_over_18"] },
            { "id": "eu", "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"] },
        ],
        "claim_sets": [["de"], ["eu"]],
    });
    let (code, stdout, _) = audit_with_example(&dcql(std::slice::from_ref(&pid)), WINE);
    assert_eq!(code, 0, "{stdout}");

    pid["multiple"] = json!(true);
    let request = dcql(&[pid]);
    let (code, stdout, _) = audit_with_example(&request, WINE);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.starts_with("OVER-ASK: Over-ask vs purpose: 2 of 2 "),
        "{stdout}"
    );
    assert_eq!(
        stdout
            .matches("this request asks for 2 of them, and 2 of these can each be returned in one response together with another claim of the group. The credential query sets multiple, so one response can hold several credentials, each answering another claim_sets option.\n")
            .count(),
        2,
        "{stdout}"
    );
    let value = json_of(
        &[
            "--json",
            "audit",
            "--request",
            &request,
            "--baseline",
            EXAMPLE_BASELINES,
            "--purpose",
            WINE,
        ],
        1,
    );
    assert_eq!(value["outcome"], "over_ask");
    for claim in value["requested"].as_array().expect("requested") {
        assert_eq!(claim["status"], "BeyondPurpose", "{claim}");
    }
}

/// The one-of line counts the requested rows of the group and those that one
/// response can hold next to another one. It does not say that one response
/// holds all of them: here no `claim_sets` option names all three.
#[test]
fn baseline_file_one_of_line_does_not_overstate_what_one_response_holds() {
    let file = baseline_file_in_temp(
        "three.json",
        &rows_baseline(json!([
            { "path": ["a"], "one_of": "g" },
            { "path": ["b"], "one_of": "g" },
            { "path": ["c"], "one_of": "g" },
        ])),
    );
    let request = |claim_sets: serde_json::Value| {
        json!({ "credentials": [{
            "id": "c", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:example:rows:1"] },
            "claims": [
                { "id": "a", "path": ["a"] },
                { "id": "b", "path": ["b"] },
                { "id": "c", "path": ["c"] },
            ],
            "claim_sets": claim_sets,
        }] })
        .to_string()
    };

    let (code, stdout, _) = run_cli(&[
        "audit",
        "--request",
        &request(json!([["a", "b"], ["b", "c"]])),
        "--baseline",
        &file,
    ]);
    assert_eq!(code, 1, "{stdout}");
    assert_eq!(
        stdout
            .matches("this request asks for 3 of them, and 3 of these can each be returned in one response together with another claim of the group.\n")
            .count(),
        3,
        "{stdout}"
    );
    assert!(!stdout.contains("hold them together"), "{stdout}");

    let (code, stdout, _) = run_cli(&[
        "audit",
        "--request",
        &request(json!([["a", "b"], ["c"]])),
        "--baseline",
        &file,
    ]);
    assert_eq!(code, 1, "{stdout}");
    assert_eq!(
        stdout
            .matches("this request asks for 3 of them, and 2 of these can each be returned in one response together with another claim of the group.\n")
            .count(),
        2,
        "{stdout}"
    );
    assert!(stdout.contains("  [ok]  c "), "{stdout}");
}

/// `--force` is accepted only together with `--yes`. Before, `register BODY
/// --force` skipped the refusal and ended as a dry run with exit code 0 under
/// the headline NOT EVALUATED or OVER-ASK.
#[test]
fn register_force_without_yes_is_a_usage_error() {
    let not_evaluated = body_with(json!([{
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:example:membership:1"] },
        "claims": [{ "path": ["member_id"] }],
    }]));
    let over = fs::read_to_string("examples/over.json").expect("over.json");
    let min = fs::read_to_string("examples/min.json").expect("min.json");
    for body in [&not_evaluated, &over, &min] {
        for args in [
            vec!["register", body.as_str(), "--force"],
            vec!["register", body.as_str(), "--force", "--target", "sandbox"],
        ] {
            let (code, stdout, stderr) = isolated_output(&args, &[]);
            assert_eq!(code, 2, "{stdout}\n{stderr}");
            assert!(stdout.is_empty(), "{stdout}");
            assert!(stderr.contains("--yes"), "{stderr}");
            assert!(stderr.contains("Usage: augenmass register"), "{stderr}");
        }
    }

    // Without --force the refusals keep their exit codes.
    let (code, stdout, _) = isolated_output(&["register", &not_evaluated], &[]);
    assert_eq!(code, 3, "{stdout}");
    let (code, stdout, _) = isolated_output(&["register", &over], &[]);
    assert_eq!(code, 1, "{stdout}");

    let help = stdout_of(&["register", "--help"], 0);
    let help: String = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        help.contains("Write past an over-ask warning, or past a body that could not be evaluated. Requires --yes. A forced write that succeeds exits 0"),
        "{help}"
    );
}

/// The earlier SD-JWT VC identifier `vc+sd-jwt` with a PID type is judged as
/// a PID, so its suggestion is spelled as claim paths, like `dc+sd-jwt`.
#[test]
fn audit_suggestion_for_vc_sd_jwt_pid_is_spelled_as_claim_paths() {
    let request = dcql(&[credential(
        "pid",
        "vc+sd-jwt",
        json!({ "vct_values": ["urn:eudi:pid:de:1"] }),
        &[json!(["birthdate"])],
    )]);
    let (code, stdout, _) = run_cli(&["audit", "--request", &request, "--purpose", "age_gate_18"]);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("  [over]  birthdate"), "{stdout}");
    assert!(
        stdout.contains("Suggested minimal request (vc+sd-jwt, urn:eudi:pid:de:1), as claim paths:\n  [\"age_equal_or_over\", \"18\"]\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("No claim names are known"), "{stdout}");
}

/// Free text of a baseline file and strings of the request are printed on
/// one line each, with control characters escaped. A file cannot print a
/// second "Baseline file" line, and it cannot erase the status line and the
/// draft label on a terminal. `--json` carries the strings unchanged.
#[test]
fn text_output_escapes_control_characters_of_file_strings() {
    let forged = "\u{1b}[1A\u{1b}[2K\u{1b}[1A\u{1b}[2KBaseline file: forged.json   entry: example.test.age   version: 2.0   status: reviewed\nreviewed by Example Reviewer";
    let mut file = one_entry_baseline();
    {
        let entry = &mut file["entries"][0];
        entry["applies_when"] = json!(forged);
        entry["label"] = json!("Example Wine Shop age check\nOK: forged headline");
        entry["version"] = json!("2.0\rstatus: reviewed");
        entry["claims"][0]["alternatives"] = json!([{
            "path": ["birthdate"],
            "reason": "invented reason\n  [ok]  forged claim line\u{202e}",
        }]);
    }
    let file = baseline_file_in_temp("forged.json", &file);
    let request = dcql(&[
        pid_sd_jwt(&[json!(["age_equal_or_over", "18"]), json!(["birthdate"])]),
        credential(
            "other",
            "dc+sd-jwt",
            json!({ "vct_values": ["urn:example:x\nOK: forged by the request\u{1b}[2K"] }),
            &[json!(["line\nbreak"])],
        ),
    ]);
    let args = [
        "audit",
        "--request",
        request.as_str(),
        "--baseline",
        file.as_str(),
        "--purpose",
        "example.test.age",
    ];
    let (code, stdout, stderr) = run_cli(&args);
    assert_eq!(code, 3, "{stdout}\n{stderr}");

    // No escape character, no carriage return, no bidirectional override.
    for c in ['\u{1b}', '\r', '\u{202e}'] {
        assert!(!stdout.contains(c), "{c:?} in {stdout:?}");
    }
    // The real facts are printed once, and no other line starts like one.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("Baseline file:"))
            .count(),
        1,
        "{stdout}"
    );
    assert!(
        stdout.contains("Baseline file: forged.json   entry: example.test.age   version: 2.0\\rstatus: reviewed   status: draft\ndraft baseline, no legal review\nApplies when (stated by the baseline, not checked by this tool): \\u{1b}[1A\\u{1b}[2K\\u{1b}[1A\\u{1b}[2KBaseline file: forged.json   entry: example.test.age   version: 2.0   status: reviewed\\nreviewed by Example Reviewer\n"),
        "{stdout}"
    );
    for line in &lines {
        assert!(!line.starts_with("reviewed by"), "{stdout}");
        assert!(!line.starts_with("OK:"), "{stdout}");
        assert!(!line.starts_with("  [ok]  forged"), "{stdout}");
    }
    assert!(
        stdout.contains("Baseline: Example Wine Shop age check\\nOK: forged headline\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("invented reason\\n  [ok]  forged claim line\\u{202e}"),
        "{stdout}"
    );
    assert!(
        stdout.contains("urn:example:x\\nOK: forged by the request\\u{1b}[2K"),
        "{stdout}"
    );
    assert!(stdout.contains("  [n/a]  line\\nbreak"), "{stdout}");

    // --json is not changed: the strings are the file's, encoded by JSON.
    let mut json_args = vec!["--json"];
    json_args.extend(args);
    let value = json_of(&json_args, 3);
    assert_eq!(value["baseline"]["applies_when"], forged);
    assert_eq!(value["baseline"]["status"], "draft");
    assert!(value["baseline"].get("legal_review").is_none());

    // An error that quotes the file is printed on one line as well.
    let mut bad = one_entry_baseline();
    bad["entries"][0]["nosuch\nOK: forged\u{1b}[2K"] = json!(1);
    let bad = baseline_file_in_temp("bad.json", &bad);
    let (code, stdout, stderr) = run_cli(&["audit", "--request", "minimal", "--baseline", &bad]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(
        stderr.contains("unknown member \"nosuch\\nOK: forged\\u{1b}[2K\""),
        "{stderr}"
    );
}

/// A path of a baseline file is printed as a JSON array that stays valid
/// JSON: a character that the text output may not print raw (here a
/// bidirectional override, a line separator, two control characters) is
/// written as the JSON escape `\uXXXX`, never as `\u{...}`, so the array can
/// be pasted into a DCQL `path` and parses back to the path of the file.
#[test]
fn baseline_file_path_suggestions_stay_valid_json() {
    let minimal = json!(["a\u{202e}"]);
    let alternative = json!(["list\u{2028}\u{85}", null, 0, "x\u{7f}"]);
    let file = json!({
        "schema": "augenmass-baselines/0.1",
        "entries": [{
            "id": "example.test",
            "version": "1",
            "status": "draft",
            "claims": [{
                "format": "dc+sd-jwt",
                "vct_values": ["urn:example:test"],
                "minimal": [{ "path": minimal }],
                "alternatives": [{ "path": alternative, "reason": "invented reason" }]
            }],
            "legal_sources": []
        }]
    });
    let file = baseline_file_in_temp("paths.json", &file);
    let request = dcql(&[credential(
        "c",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:example:test"] }),
        &[json!(["b"])],
    )]);
    let args = [
        "audit",
        "--request",
        request.as_str(),
        "--baseline",
        file.as_str(),
    ];
    let (code, stdout, stderr) = run_cli(&args);
    assert_eq!(code, 1, "{stdout}\n{stderr}");

    // Nothing that acts on a terminal or reorders the line is printed raw.
    for c in ['\u{202e}', '\u{2028}', '\u{85}', '\u{7f}'] {
        assert!(!stdout.contains(c), "{c:?} in {stdout:?}");
    }
    assert!(
        stdout.contains(
            "Minimal claims of this baseline entry (dc+sd-jwt, urn:example:test):\n  [\"a\\u202e\"]\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "Acceptable alternatives of this baseline entry (dc+sd-jwt, urn:example:test):\n  [\"list\\u2028\\u0085\", null, 0, \"x\\u007f\"]\n"
        ),
        "{stdout}"
    );

    // Each printed array parses as JSON and is the path of the file.
    let lines: Vec<&str> = stdout.lines().collect();
    let line_after = |heading: &str| {
        let at = lines
            .iter()
            .position(|line| line.starts_with(heading))
            .unwrap_or_else(|| panic!("no line {heading:?} in {stdout}"));
        lines[at + 1].trim()
    };
    for (heading, path) in [
        ("Minimal claims of this baseline entry", &minimal),
        (
            "Acceptable alternatives of this baseline entry",
            &alternative,
        ),
    ] {
        let printed = line_after(heading);
        let parsed: serde_json::Value = serde_json::from_str(printed)
            .unwrap_or_else(|e| panic!("{printed:?} is not JSON: {e}"));
        assert_eq!(&parsed, path, "{printed}");
    }

    // --json carries the paths as the file has them.
    let mut json_args = vec!["--json"];
    json_args.extend(args);
    let value = json_of(&json_args, 1);
    assert_eq!(
        value["baseline"]["claims"][0]["minimal"][0]["path"],
        minimal
    );
    assert_eq!(
        value["baseline"]["claims"][0]["alternatives"][0]["path"],
        alternative
    );
}

// --- closed output streams ---------------------------------------------------
//
// The exit code carries the verdict. A reader that closes standard output or
// standard error early must not turn it into a panic with exit code 101: the
// command writes nothing more to that stream and exits with the code it
// computes with an open reader.

/// Which of the two output streams have a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readers {
    Open,
    StdoutClosed,
    StderrClosed,
    BothClosed,
}

/// The write end of a pipe whose read end is already closed. No race: the
/// reader is gone before the child starts.
fn pipe_without_reader() -> std::process::Stdio {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    writer.into()
}

/// Exit code, standard output and standard error of one run. A stream
/// without a reader gives an empty string.
fn run_with_readers(mut cmd: std::process::Command, readers: Readers) -> (i32, String, String) {
    use std::process::Stdio;
    let closed_out = matches!(readers, Readers::StdoutClosed | Readers::BothClosed);
    let closed_err = matches!(readers, Readers::StderrClosed | Readers::BothClosed);
    cmd.stdin(Stdio::null());
    cmd.stdout(if closed_out {
        pipe_without_reader()
    } else {
        Stdio::piped()
    });
    cmd.stderr(if closed_err {
        pipe_without_reader()
    } else {
        Stdio::piped()
    });
    let out = cmd.output().expect("run binary");
    (
        out.status.code().expect("exit code, not a signal"),
        String::from_utf8(out.stdout).expect("utf8"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

/// The binary in the repository root (the fixtures are named relative to it).
fn augenmass(args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_augenmass"));
    cmd.args(args);
    cmd
}

/// Runs `args` with open readers and with each stream closed before the
/// start. The exit code is `code` every time, no run panics, and the stream
/// that still has a reader holds exactly what it holds in the open run
/// (nothing further is printed, also no "Broken pipe" line).
fn assert_exit_code_survives_closed_streams(label: &str, args: &[&str], code: i32) {
    let (open_code, open_out, open_err) = run_with_readers(augenmass(args), Readers::Open);
    assert_eq!(
        open_code, code,
        "{label}: open readers\n{open_out}{open_err}"
    );
    assert!(!open_err.contains("panicked"), "{label}: {open_err}");

    let (c, out, err) = run_with_readers(augenmass(args), Readers::StdoutClosed);
    assert_eq!(c, code, "{label}: stdout closed\n{err}");
    assert!(out.is_empty(), "{label}");
    assert!(!err.contains("panicked"), "{label}: {err}");
    assert_eq!(err, open_err, "{label}: stderr with stdout closed");

    let (c, out, err) = run_with_readers(augenmass(args), Readers::StderrClosed);
    assert_eq!(c, code, "{label}: stderr closed\n{out}");
    assert!(err.is_empty(), "{label}");
    assert_eq!(out, open_out, "{label}: stdout with stderr closed");

    let (c, _, _) = run_with_readers(augenmass(args), Readers::BothClosed);
    assert_eq!(c, code, "{label}: both closed");
}

/// A request whose second credential type the built-in baseline does not
/// model: NOT EVALUATED, exit code 3.
fn not_evaluated_request() -> String {
    dcql(&[
        pid_sd_jwt(&[json!(["age_equal_or_over", "18"])]),
        credential(
            "card",
            "dc+sd-jwt",
            json!({ "vct_values": ["urn:example:member-card:1"] }),
            &[json!(["member_number"])],
        ),
    ])
}

#[test]
fn closed_output_streams_keep_the_exit_code_of_a_verdict() {
    let not_evaluated = not_evaluated_request();
    let not_evaluated_body = body_with(json!([jwt_vc_entry(json!([
        "credentialSubject",
        "family_name"
    ]))]));
    let minimal = "examples/age-minimal-request-sdjwt.json";
    let cases: Vec<(&str, Vec<&str>, i32)> = vec![
        (
            "audit, OVER-ASK",
            vec!["audit", "--request", "overask", "--purpose", "age_gate_18"],
            1,
        ),
        (
            "audit, OK",
            vec!["audit", "--request", minimal, "--purpose", "age_gate_18"],
            0,
        ),
        (
            "audit, NOT EVALUATED",
            vec![
                "audit",
                "--request",
                &not_evaluated,
                "--purpose",
                "age_gate_18",
            ],
            3,
        ),
        (
            "audit, NOT EVALUATED for an ignored member",
            vec![
                "audit",
                "--request",
                "examples/age-request-ignored-member.json",
                "--purpose",
                "age_gate_18",
            ],
            3,
        ),
        (
            "audit --json, OVER-ASK",
            vec![
                "audit",
                "--request",
                "overask",
                "--purpose",
                "age_gate_18",
                "--json",
            ],
            1,
        ),
        (
            "audit --json, NOT EVALUATED",
            vec![
                "--json",
                "audit",
                "--request",
                &not_evaluated,
                "--purpose",
                "age_gate_18",
            ],
            3,
        ),
        ("check, over-ask", vec!["check", "examples/over.json"], 1),
        ("check, ok", vec!["check", "examples/min.json"], 0),
        (
            "check, not evaluated",
            vec!["check", &not_evaluated_body],
            3,
        ),
        (
            "check, format error",
            vec!["check", "examples/bad-path.json"],
            1,
        ),
        (
            "check --json, over-ask",
            vec!["check", "examples/over.json", "--json"],
            1,
        ),
        (
            "register dry run, ok",
            vec!["register", "examples/min.json"],
            0,
        ),
        (
            "register dry run, refused over-ask",
            vec!["register", "examples/over.json"],
            1,
        ),
        (
            "register dry run, refused not evaluated",
            vec!["register", &not_evaluated_body],
            3,
        ),
        (
            "register dry run, format error",
            vec!["register", "examples/bad-path.json"],
            1,
        ),
    ];
    for (label, args, code) in &cases {
        assert_exit_code_survives_closed_streams(label, args, *code);
    }
}

#[test]
fn closed_output_streams_never_panic_any_command() {
    let source = evidence_source_session();
    let bundle_dir = test_temp_dir("augenmass-cli-closed-evidence");
    let bundle = bundle_dir.join("bundle.json");
    let bundle = bundle.to_str().expect("utf8 path").to_string();
    bin()
        .args([
            "evidence",
            "export",
            source.to_str().unwrap(),
            "--out",
            &bundle,
        ])
        .assert()
        .success();

    let erica = "fixtures/presentations/erica-vp-VALID.sdjwt";
    let wrong_nonce = "fixtures/presentations/erica-vp-WRONG_NONCE.sdjwt";
    let registration = "examples/age-broad-registration.jwt";
    let cases: Vec<(&str, Vec<&str>, i32)> = vec![
        (
            "validate dcql, valid",
            vec!["validate", "dcql", "examples/age-broad-request.json"],
            0,
        ),
        (
            "validate dcql, valid with a warning",
            vec![
                "validate",
                "dcql",
                "examples/age-request-ignored-member.json",
            ],
            0,
        ),
        (
            "validate dcql, invalid",
            vec!["validate", "dcql", r#"{"credentials":[]}"#],
            1,
        ),
        (
            "inspect",
            vec!["inspect", "examples/age-broad-request.json"],
            0,
        ),
        ("inspect --json", vec!["inspect", erica, "--json"], 0),
        ("decode jwt", vec!["decode", "jwt", registration], 0),
        ("decode sd-jwt", vec!["decode", "sd-jwt", erica], 0),
        ("decode regcert", vec!["decode", "regcert", registration], 0),
        (
            "decode request",
            vec!["decode", "request", "fixtures/requests/eudiplo-request.jwt"],
            0,
        ),
        (
            "decode offer",
            vec!["decode", "offer", "fixtures/offers/eudiplo-offer-uri.txt"],
            0,
        ),
        (
            "decode status-list",
            vec![
                "decode",
                "status-list",
                "fixtures/status/status-list-CLEAR.jwt",
            ],
            0,
        ),
        (
            "decode mdoc",
            vec!["decode", "mdoc", "fixtures/mdoc/issuer-signed.hex"],
            0,
        ),
        ("baselines", vec!["baselines"], 0),
        ("baselines age_gate_18", vec!["baselines", "age_gate_18"], 0),
        ("baselines --json", vec!["baselines", "--json"], 0),
        (
            "doctor with findings",
            vec!["doctor", "examples/bad-request.json"],
            1,
        ),
        (
            "x509-hash",
            vec!["x509-hash", "fixtures/certs/access-leaf.pem"],
            0,
        ),
        (
            "x509-hash, mismatch",
            vec![
                "x509-hash",
                "fixtures/certs/access-leaf.pem",
                "--client-id",
                "x509_hash:not-the-hash",
            ],
            1,
        ),
        (
            "verify presentation, verified",
            vec![
                "verify",
                "presentation",
                erica,
                "--nonce",
                NONCE,
                "--aud",
                AUD,
                "--now",
                NOW,
            ],
            0,
        ),
        (
            "verify presentation, not verified",
            vec![
                "verify",
                "presentation",
                wrong_nonce,
                "--nonce",
                NONCE,
                "--aud",
                AUD,
                "--now",
                NOW,
            ],
            1,
        ),
        ("generate regbody", vec!["generate", "regbody"], 0),
        (
            "generate dcql",
            vec!["generate", "dcql", "--claim", "age_equal_or_over.18"],
            0,
        ),
        ("evidence verify", vec!["evidence", "verify", &bundle], 0),
        ("--help", vec!["--help"], 0),
        ("--version", vec!["--version"], 0),
        (
            "usage error",
            vec![
                "audit",
                "--request",
                "overask",
                "--purpose",
                "no_such_purpose",
            ],
            2,
        ),
        (
            "unreadable input",
            vec![
                "audit",
                "--request",
                "no-such-file",
                "--purpose",
                "age_gate_18",
            ],
            1,
        ),
    ];
    for (label, args, code) in &cases {
        assert_exit_code_survives_closed_streams(label, args, *code);
    }

    let _ = fs::remove_dir_all(source);
    let _ = fs::remove_dir_all(bundle_dir);
}

/// One run with a reader of standard output that stops early: it reads
/// `take` bytes (or up to the first line break for `None`) and closes.
/// Returns the exit code and standard error.
fn run_with_a_reader_that_stops(args: &[&str], take: Option<usize>) -> (i32, String) {
    use std::io::{BufRead, Read};
    use std::process::Stdio;
    let mut child = augenmass(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binary");
    let stdout = child.stdout.take().expect("stdout");
    match take {
        None => {
            let mut reader = std::io::BufReader::with_capacity(64, stdout);
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).expect("first line");
            assert!(line.ends_with(b"\n"), "a first line");
        }
        Some(count) => {
            let mut read = vec![0u8; count];
            let mut stdout = stdout;
            stdout
                .read_exact(&mut read)
                .expect("the bytes before the stop");
        }
    }
    // The reader is dropped here: the pipe has no reader from now on.
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().expect("exit code, not a signal"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

/// A DCQL query with 3000 invented claim paths of a credential type that no
/// built-in baseline models, as a file. Its `audit` output is larger than a
/// pipe buffer, so the write is still in progress when a reader goes away:
/// the failed write is certain, not a race. With `over_ask`, a second
/// credential query asks a PID for `given_name`, which `age_gate_18` judges
/// as too much.
fn large_request_file(dir: &Path, over_ask: bool) -> String {
    let paths: Vec<serde_json::Value> = (0..3000)
        .map(|i| json!([format!("invented_claim_{i:04}")]))
        .collect();
    let mut credentials = vec![credential(
        "card",
        "dc+sd-jwt",
        json!({ "vct_values": ["urn:example:member-card:1"] }),
        &paths,
    )];
    if over_ask {
        credentials.push(pid_sd_jwt(&[json!(["given_name"])]));
    }
    let name = if over_ask {
        "large-over.json"
    } else {
        "large.json"
    };
    let file = dir.join(name);
    fs::write(&file, dcql(&credentials)).expect("write large request");
    file.to_str().expect("utf8 path").to_string()
}

#[test]
fn closed_stdout_during_a_large_output_keeps_the_exit_code() {
    let dir = test_temp_dir("augenmass-cli-large");
    fs::create_dir_all(&dir).expect("create dir");
    let not_evaluated = large_request_file(&dir, false);
    let over_ask = large_request_file(&dir, true);
    let large_json = dir.join("large-document.json");
    let strings: Vec<String> = (0..20000).map(|i| format!("invented string {i}")).collect();
    fs::write(&large_json, json!(strings).to_string()).expect("write large document");
    let large_json = large_json.to_str().expect("utf8 path").to_string();

    let cases: Vec<(&str, Vec<&str>, i32, &str)> = vec![
        (
            "NOT EVALUATED, text",
            vec![
                "audit",
                "--request",
                &not_evaluated,
                "--purpose",
                "age_gate_18",
            ],
            3,
            "NOT EVALUATED: ",
        ),
        (
            "NOT EVALUATED, --json",
            vec![
                "audit",
                "--request",
                &not_evaluated,
                "--purpose",
                "age_gate_18",
                "--json",
            ],
            3,
            "{",
        ),
        (
            "OVER-ASK, text",
            vec!["audit", "--request", &over_ask, "--purpose", "age_gate_18"],
            1,
            "OVER-ASK: ",
        ),
        (
            "OVER-ASK, --json",
            vec![
                "audit",
                "--request",
                &over_ask,
                "--purpose",
                "age_gate_18",
                "--json",
            ],
            1,
            "{",
        ),
        (
            "inspect of a large document",
            vec!["inspect", &large_json],
            0,
            "[",
        ),
    ];
    for (label, args, code, start) in &cases {
        // The open run first: the expected result is really there, and the
        // output is larger than any pipe buffer.
        let (open_code, open_out, open_err) = run_with_readers(augenmass(args), Readers::Open);
        assert_eq!(open_code, *code, "{label}: open reader\n{open_err}");
        assert!(open_out.starts_with(start), "{label}");
        assert!(
            open_out.len() > 400_000,
            "{label}: {} bytes",
            open_out.len()
        );
        if *start == "{" {
            let value: serde_json::Value = serde_json::from_str(&open_out).expect("json");
            let outcome = if *code == 1 {
                "over_ask"
            } else {
                "not_evaluated"
            };
            assert_eq!(value["outcome"], outcome, "{label}");
        }

        // Where the reader stops: after the first line; after 20 bytes
        // (inside the first line of a text result); after 300000 bytes,
        // moved by one if that is a line end, so that the stop is inside a
        // line; and before the last ten bytes. In the last case the child
        // has usually finished its write, so it shows the exit code and the
        // absence of a panic, not a failed last write (the unit tests of
        // `output` pin that).
        let bytes = open_out.as_bytes();
        let mut middle = 300_000;
        if bytes[middle - 1] == b'\n' {
            middle += 1;
        }
        if start.ends_with(": ") {
            assert!(!bytes[..20].contains(&b'\n'), "{label}: a long first line");
        }
        for (stop, take) in [
            ("after the first line", None),
            ("after 20 bytes", Some(20)),
            ("inside a line", Some(middle)),
            ("before the last bytes", Some(bytes.len() - 10)),
        ] {
            let (stopped_code, stderr) = run_with_a_reader_that_stops(args, take);
            assert_eq!(
                stopped_code, *code,
                "{label}, reader stops {stop}\n{stderr}"
            );
            assert!(!stderr.contains("panicked"), "{label}, {stop}: {stderr}");
            assert_eq!(stderr, open_err, "{label}, {stop}");
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// A write error that is not a closed reader is reported as an error, with
/// exit code 1 and not the code of the verdict, and without a panic.
/// `/dev/full` accepts no byte ("No space left on device"); macOS has no
/// such device.
#[cfg(target_os = "linux")]
#[test]
fn full_disk_on_stdout_is_an_error_not_a_panic() {
    for args in [
        vec!["baselines", "age_gate_18"],
        vec!["audit", "--request", "minimal", "--purpose", "age_gate_18"],
        vec!["register", "examples/min.json"],
    ] {
        let full = fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full");
        let out = augenmass(&args)
            .stdin(std::process::Stdio::null())
            .stdout(full)
            .output()
            .expect("run binary");
        let stderr = String::from_utf8(out.stderr).expect("utf8");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.starts_with("Error: write standard output"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
    }
}

/// This pins a stated limit, not a wish. The Rust standard library reports a
/// write to a standard stream that is not open for writing (the error EBADF)
/// as done, so the binary cannot see it: nothing is written, nothing is
/// reported, and the exit code is the one the command computed, as with a
/// closed reader. A later change of that handle shows up here.
#[cfg(unix)]
#[test]
fn stdout_not_open_for_writing_keeps_the_exit_code() {
    let dir = test_temp_dir("augenmass-cli-read-only-stream");
    fs::create_dir_all(&dir).expect("create dir");
    let file = dir.join("opened-for-reading.txt");
    let content = "a file opened for reading only\n";
    fs::write(&file, content).expect("write file");
    let read_only = || fs::File::open(&file).expect("open for reading");
    let not_evaluated = not_evaluated_request();

    for (args, code) in [
        (vec!["baselines", "age_gate_18"], 0),
        (
            vec!["audit", "--request", "overask", "--purpose", "age_gate_18"],
            1,
        ),
        (
            vec![
                "audit",
                "--request",
                &not_evaluated,
                "--purpose",
                "age_gate_18",
            ],
            3,
        ),
    ] {
        let (open_code, _, _) = run_with_readers(augenmass(&args), Readers::Open);
        assert_eq!(open_code, code, "{args:?}");
        let out = augenmass(&args)
            .stdin(std::process::Stdio::null())
            .stdout(read_only())
            .output()
            .expect("run binary");
        let stderr = String::from_utf8(out.stderr).expect("utf8");
        assert_eq!(out.status.code(), Some(code), "{args:?}: {stderr}");
        assert!(stderr.is_empty(), "{args:?}: {stderr}");
        assert_eq!(fs::read_to_string(&file).expect("read"), content);
    }

    // The same for standard error: the result of `inspect` is on standard
    // output, its "Detected:" line would go to standard error.
    let out = augenmass(&["inspect", "examples/age-minimal-request-sdjwt.json"])
        .stdin(std::process::Stdio::null())
        .stderr(read_only())
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.starts_with("DCQL query\n"), "{stdout}");
    assert_eq!(fs::read_to_string(&file).expect("read"), content);
    let _ = fs::remove_dir_all(dir);
}

/// Answers every connection with one JSON document until the listener is
/// dropped with the test process. Read path only: it never stores anything.
fn serve_json_once_per_connection(body: String) -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

/// `list` prints outside the shared result function. A local listener
/// stands in for the clone; `list` only reads.
#[test]
fn list_survives_a_closed_stdout() {
    let entry = fs::read_to_string("fixtures/regcert/rc-by-id.json").expect("fixture");
    for (body, expected) in [
        (
            format!("[{entry}]"),
            "1 registration(s) for RP rp-example on clone:\n",
        ),
        (
            "[]".to_string(),
            "No registrations for RP rp-example on clone.\n",
        ),
    ] {
        let port = serve_json_once_per_connection(body);
        let base = format!("http://127.0.0.1:{port}/api");
        let command = || {
            let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_augenmass"));
            cmd.env_clear()
                .current_dir(isolated_dir())
                .env("AUGENMASS_CLONE_API_BASE", &base)
                .args(["list", "--target", "clone", "--rp", "rp-example"]);
            cmd
        };
        let (code, stdout, stderr) = run_with_readers(command(), Readers::Open);
        assert_eq!(code, 0, "{stdout}{stderr}");
        assert!(stdout.starts_with(expected), "{stdout}");
        for readers in [Readers::StdoutClosed, Readers::BothClosed] {
            let (code, _, stderr) = run_with_readers(command(), readers);
            assert_eq!(code, 0, "{readers:?}: {stderr}");
            assert!(!stderr.contains("panicked"), "{stderr}");
        }
    }
}

/// Sends `GET <path>` to a local port and returns the status line, or `None`
/// while nothing answers there.
fn http_status_line(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.lines().next().map(str::to_string)
}

/// A server process that is stopped when the test ends, also when it fails.
struct Server(std::process::Child);

impl Server {
    /// True once `GET <path>` answers 200; false when the process exited or
    /// nothing answered in time.
    fn answers(&mut self, port: u16, path: &str) -> bool {
        for _ in 0..300 {
            if self.0.try_wait().expect("try_wait").is_some() {
                return false;
            }
            if http_status_line(port, path).is_some_and(|line| line.contains(" 200")) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    fn still_runs(&mut self) -> bool {
        self.0.try_wait().expect("try_wait").is_none()
    }

    /// Stops the process and returns what it wrote to the streams that were
    /// piped.
    fn stop(mut self) -> (String, String) {
        use std::io::Read;
        let _ = self.0.kill();
        let _ = self.0.wait();
        let mut stdout = String::new();
        if let Some(mut pipe) = self.0.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = self.0.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        (stdout, stderr)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_with_readers(mut cmd: std::process::Command, readers: Readers) -> Server {
    use std::process::Stdio;
    let closed_out = matches!(readers, Readers::StdoutClosed | Readers::BothClosed);
    let closed_err = matches!(readers, Readers::StderrClosed | Readers::BothClosed);
    cmd.stdin(Stdio::null());
    cmd.stdout(if closed_out {
        pipe_without_reader()
    } else {
        Stdio::piped()
    });
    cmd.stderr(if closed_err {
        pipe_without_reader()
    } else {
        Stdio::piped()
    });
    Server(cmd.spawn().expect("spawn server"))
}

/// `serve` writes its start lines to standard error and its log lines to
/// standard output through a log layer of a dependency. That layer reports a
/// failed write with a print macro of its own: with standard output closed
/// it printed "[tracing-subscriber] Unable to write an event ..." for every
/// log line, and with both streams closed that print panicked. The server
/// runs with an empty environment in an empty directory and without a
/// relay, so no connection leaves the machine.
#[test]
fn serve_survives_closed_streams() {
    for readers in [Readers::Open, Readers::StdoutClosed, Readers::BothClosed] {
        let port = closed_local_port();
        let port_text = port.to_string();
        let public_url = format!("http://127.0.0.1:{port}/");
        let cmd = isolated_command(
            &[
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &port_text,
                "--public-url",
                &public_url,
            ],
            &[],
        );
        let mut server = spawn_with_readers(cmd, readers);
        let healthy = server.answers(port, "/health");
        let running = server.still_runs();
        let (stdout, stderr) = server.stop();
        assert!(healthy, "{readers:?}: /health did not answer\n{stderr}");
        assert!(running, "{readers:?}: the server exited\n{stderr}");
        assert!(!stderr.contains("panicked"), "{readers:?}: {stderr}");
        assert!(
            !stderr.contains("[tracing-subscriber]"),
            "{readers:?}: {stderr}"
        );
        match readers {
            // The log line is written: the next two runs reach that write.
            Readers::Open => {
                assert!(stdout.contains("listening on"), "{stdout}");
                assert!(stderr.contains("augenmass serve: "), "{stderr}");
            }
            Readers::StdoutClosed => assert!(stderr.contains("augenmass serve: "), "{stderr}"),
            _ => {}
        }
    }
}

// --- member names that resemble a defined one --------------------------------
//
// A credential query that says `claim` for `claims` is a valid DCQL query: a
// wallet ignores a member it does not know. It is very likely not what its
// author meant. `validate dcql`, `inspect` and `audit` warn about it, and
// `audit` never gives it a bare OK.

const IGNORED_MEMBER_EXAMPLE: &str = "examples/age-request-ignored-member.json";

/// The warning line for a member at a place of the query.
fn near_miss_line(place: &str, member: &str, level: &str, resembles: &str) -> String {
    format!(
        "{place}: member \"{member}\" is not defined by OpenID4VP 1.0 for a {level} and resembles \"{resembles}\". A wallet ignores a member it does not know (OpenID4VP 1.0, section 6: \"Implementations MUST ignore any unknown properties.\"), so \"{member}\" has no effect on the request unless the wallet implements an extension that defines it."
    )
}

fn claim_for_claims_line() -> String {
    near_miss_line("credentials[0]", "claim", "Credential Query", "claims")
}

const NEAR_MISS_FIX_LINE: &str = "    Fix: rename the member to the defined name if that was meant. If it belongs to an extension that the wallet implements, keep it; this warning then does not apply.\n";

/// A PID credential query that asks for the age attribute, with further
/// members next to `claims`.
fn pid_age_query_with(extra: serde_json::Value) -> serde_json::Value {
    let mut query = json!({
        "id": "pid",
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "id": "age", "path": ["age_equal_or_over", "18"] }],
    });
    for (key, value) in extra.as_object().expect("object") {
        query[key] = value.clone();
    }
    query
}

fn audit_age_gate(request: &str) -> (i32, String, String) {
    run_cli(&["audit", "--request", request, "--purpose", "age_gate_18"])
}

#[test]
fn validate_dcql_warns_on_a_near_miss_and_stays_valid() {
    let (code, stdout, stderr) = run_cli(&["validate", "dcql", IGNORED_MEMBER_EXAMPLE]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(
        stdout,
        format!(
            "DCQL findings:\n  DCQL-MEMBER-NEAR-MISS [warning]: {}\n{NEAR_MISS_FIX_LINE}\nDCQL OK (warnings only).\n",
            claim_for_claims_line()
        )
    );

    let value = json_of(&["validate", "dcql", IGNORED_MEMBER_EXAMPLE, "--json"], 0);
    assert_eq!(value["valid"], true);
    assert_eq!(value["findingCount"], 1);
    assert_eq!(value["findings"][0]["id"], "DCQL-MEMBER-NEAR-MISS");
    assert_eq!(value["findings"][0]["severity"], "warning");
    assert_eq!(value["findings"][0]["message"], claim_for_claims_line());
    assert_eq!(
        value["warnings"],
        json!([{
            "id": "DCQL-MEMBER-NEAR-MISS",
            "place": "credentials[0]",
            "level": "credential_query",
            "member": "claim",
            "resembles": "claims",
            "message": claim_for_claims_line(),
        }])
    );

    // A query without such a member: the result of before, and an empty list.
    let clean = "examples/age-broad-request.json";
    let (code, stdout, _) = run_cli(&["validate", "dcql", clean]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "DCQL VALID: no structural or reference issues found.\n"
    );
    let value = json_of(&["validate", "dcql", clean, "--json"], 0);
    assert_eq!(value["warnings"], json!([]));
    assert_eq!(value["findingCount"], 0);

    // A warning does not turn an invalid query valid, and a blocking error
    // does not hide the warning. `option` for `options`: the set has no
    // options. `credential` for `credentials`: the query has no credentials.
    let no_options = json!({
        "credentials": [pid_age_query_with(json!({}))],
        "credential_sets": [{ "option": [["pid"]] }],
    })
    .to_string();
    let value = json_of(&["validate", "dcql", &no_options, "--json"], 1);
    assert_eq!(value["valid"], false);
    assert_eq!(value["warnings"][0]["place"], "credential_sets[0]");
    assert_eq!(value["warnings"][0]["level"], "credential_set_query");
    assert_eq!(value["warnings"][0]["resembles"], "options");
    let ids: Vec<&str> = value["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| f["id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids[0], "DCQL-MEMBER-NEAR-MISS", "{ids:?}");
    assert!(ids.contains(&"DCQL-SET-OPTIONS-MISSING"), "{ids:?}");

    let no_credentials = json!({ "credential": [pid_age_query_with(json!({}))] }).to_string();
    let (code, stdout, _) = run_cli(&["validate", "dcql", &no_credentials]);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.contains(&near_miss_line(
            "query",
            "credential",
            "DCQL query",
            "credentials"
        )),
        "{stdout}"
    );
    assert!(stdout.contains("DCQL-CREDENTIALS-MISSING"), "{stdout}");
    assert!(stdout.ends_with("DCQL INVALID: at least one blocking error above.\n"));

    // `paths` for `path` in a claims query, and a wrapped query.
    let paths = json!({ "dcql_query": { "credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["age_equal_or_over", "18"] }, { "paths": ["birthdate"] }],
    }] } })
    .to_string();
    let (code, stdout, _) = run_cli(&["validate", "dcql", &paths]);
    assert_eq!(code, 1, "{stdout}");
    assert!(
        stdout.contains(&near_miss_line(
            "credentials[0].claims[1]",
            "paths",
            "Claims Query",
            "path"
        )),
        "{stdout}"
    );
    // The claims query that says `paths` has no `path`: a blocking finding,
    // like `option` for `options` above.
    assert!(
        stdout.contains(
            "  DCQL-PATH-MISSING [blocking]: credentials[0].claims[1] has no member path\n"
        ),
        "{stdout}"
    );
    assert!(stdout.ends_with("DCQL INVALID: at least one blocking error above.\n"));
}

/// `validate dcql` and `audit` agree on a claims query without the required
/// member `path` and on an empty `path` (OpenID4VP 1.0, section 6.3):
/// `validate dcql` lists a blocking finding and exits 1, `audit` stops with
/// the parse error and exits 1. A query whose claims queries all have a
/// non-empty path stays valid in both.
#[test]
fn validate_dcql_blocks_a_claims_query_without_a_path_like_audit() {
    let query = |claims: serde_json::Value| {
        json!({ "credentials": [{
            "id": "pid", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            "claims": claims,
        }] })
        .to_string()
    };
    for (claims, id, message) in [
        (
            json!([{ "id": "a" }]),
            "DCQL-PATH-MISSING",
            "credentials[0].claims[0] has no member path",
        ),
        (
            json!([{ "path": ["age_equal_or_over", "18"] }, {}]),
            "DCQL-PATH-MISSING",
            "credentials[0].claims[1] has no member path",
        ),
        (
            json!([{ "path": [] }]),
            "DCQL-PATH-EMPTY",
            "credentials[0].claims[0].path is an empty array",
        ),
    ] {
        let request = query(claims);
        let (code, stdout, stderr) = run_cli(&["validate", "dcql", &request]);
        assert_eq!(code, 1, "{request}: {stdout}{stderr}");
        assert!(
            stdout.contains(&format!("  {id} [blocking]: {message}\n")),
            "{request}: {stdout}"
        );
        assert!(
            stdout.ends_with("DCQL INVALID: at least one blocking error above.\n"),
            "{request}: {stdout}"
        );
        let value = json_of(&["validate", "dcql", &request, "--json"], 1);
        assert_eq!(value["valid"], false, "{request}");
        assert_eq!(value["findings"][0]["id"], id, "{request}");
        assert_eq!(value["findings"][0]["severity"], "blocking", "{request}");

        let (code, stdout, stderr) = audit_age_gate(&request);
        assert_eq!(code, 1, "{request}: {stdout}{stderr}");
        assert_eq!(stdout, "", "{request}");
        assert!(stderr.contains("parse DCQL query"), "{request}: {stderr}");
    }

    let valid = query(json!([{ "path": ["age_equal_or_over", "18"] }]));
    let (code, stdout, _) = run_cli(&["validate", "dcql", &valid]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(
        stdout,
        "DCQL VALID: no structural or reference issues found.\n"
    );
    let (code, _, _) = audit_age_gate(&valid);
    assert_eq!(code, 0);
}

#[test]
fn inspect_prints_the_authoring_warning_for_a_dcql_query() {
    let (code, stdout, stderr) = run_cli(&["inspect", IGNORED_MEMBER_EXAMPLE]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "Detected: DCQL query\n");
    assert_eq!(
        stdout,
        format!(
            "DCQL query\n  requested claims: 0\n  authoring warnings: 1\n    {}\n",
            claim_for_claims_line()
        )
    );
    let value = json_of(&["inspect", IGNORED_MEMBER_EXAMPLE, "--json"], 0);
    assert_eq!(value["artifact"], "dcql-query");
    assert_eq!(value["requestedKeys"], json!([]));
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
    assert_eq!(value["warnings"][0]["member"], "claim");
    assert_eq!(value["warnings"][0]["resembles"], "claims");

    // A query without such a member has no warning lines and an empty list.
    let clean = "examples/age-minimal-request-sdjwt.json";
    let (code, stdout, _) = run_cli(&["inspect", clean]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "DCQL query\n  requested claims: 1\n    age_equal_or_over.18\n"
    );
    let value = json_of(&["inspect", clean, "--json"], 0);
    assert_eq!(value["warnings"], json!([]));

    // `value` for `values`: the claim is still requested, the warning names
    // the claims query.
    let value_query = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["age_equal_or_over", "18"], "value": [true] }],
    }] })
    .to_string();
    let (code, stdout, _) = run_cli(&["inspect", &value_query]);
    assert_eq!(code, 0);
    assert!(stdout.contains("  requested claims: 1\n"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "  authoring warnings: 1\n    {}\n",
            near_miss_line(
                "credentials[0].claims[0]",
                "value",
                "Claims Query",
                "values"
            )
        )),
        "{stdout}"
    );

    // A query the typed parse rejects stays an error; the error names the
    // member that is the likely cause.
    let paths = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "paths": ["birthdate"] }],
    }] })
    .to_string();
    let (code, stdout, stderr) = run_cli(&["inspect", &paths]);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.starts_with(
            "Detected: DCQL query\nError: the query has 1 member(s) that a wallet ignores unless it knows them from an extension: credentials[0].claims[0]: member \"paths\" is not defined by OpenID4VP 1.0 for a Claims Query and resembles \"path\"."
        ),
        "{stderr}"
    );
    assert!(
        stderr.ends_with("Caused by:\n    0: parse DCQL query\n    1: missing field `path`\n"),
        "{stderr}"
    );

    // A document whose only DCQL-like member is `credential` is not detected
    // as a DCQL query, so `inspect` has no warning for it.
    let no_credentials = json!({ "credential": [pid_age_query_with(json!({}))] }).to_string();
    let (code, stdout, stderr) = run_cli(&["inspect", &no_credentials]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr, "Detected: JSON document\n");
    assert!(!stdout.contains("authoring warnings"), "{stdout}");
}

#[test]
fn audit_never_prints_ok_for_a_query_with_an_ignored_member() {
    let (code, stdout, stderr) = audit_age_gate(IGNORED_MEMBER_EXAMPLE);
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert_eq!(
        stdout,
        format!(
            "NOT EVALUATED: 1 member(s) of the query resemble a defined member and are ignored by a wallet that does not know them.\n\
             Registration purpose: no registration given   Baseline: Age gate (over 18)\n\
             \n\
             Requested claims:\n\
             \n\
             Authoring warnings:\n  {}\n\
             \n\
             Not evaluated: 1 member(s) of the query that a wallet ignores unless it knows them from an extension. No judged claim asks for too much; exit code 3.\n\
             \n\
             Suggested minimal request (dc+sd-jwt, urn:eudi:pid:de:1), as claim paths:\n  [\"age_equal_or_over\", \"18\"]\n",
            claim_for_claims_line()
        )
    );
    for line in stdout.lines() {
        assert!(!line.starts_with("OK"), "{stdout}");
    }

    let value = json_of(
        &[
            "audit",
            "--request",
            IGNORED_MEMBER_EXAMPLE,
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        3,
    );
    assert_eq!(value["outcome"], "not_evaluated");
    assert_eq!(
        value["verdict_line"],
        "1 member(s) of the query resemble a defined member and are ignored by a wallet that does not know them."
    );
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
    assert_eq!(value["warnings"][0]["id"], "DCQL-MEMBER-NEAR-MISS");
    assert_eq!(value["warnings"][0]["place"], "credentials[0]");
    assert_eq!(value["warnings"][0]["member"], "claim");
    assert_eq!(value["warnings"][0]["message"], claim_for_claims_line());
    // The counts are about claims: no claim was requested, none was unjudged.
    assert_eq!(value["counts"]["requested"], 0);
    assert_eq!(value["counts"]["could_not_judge"], 0);

    // Under the default purpose as well (no --purpose).
    let (code, stdout, _) = run_cli(&["audit", "--request", IGNORED_MEMBER_EXAMPLE]);
    assert_eq!(code, 3, "{stdout}");
    assert!(stdout.starts_with("NOT EVALUATED: "), "{stdout}");

    // The correctly spelled query asks for the same three claims and two
    // more: OVER-ASK, as before, with an empty list of warnings.
    let (code, stdout, _) = audit_age_gate("examples/age-broad-request.json");
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.starts_with("OVER-ASK: "), "{stdout}");
    assert!(!stdout.contains("Authoring warnings"), "{stdout}");
    let value = json_of(
        &[
            "audit",
            "--request",
            "examples/age-broad-request.json",
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        1,
    );
    assert_eq!(value["warnings"], json!([]));

    // A request that is OK has the empty list too, and the two built-in
    // requests never have a warning.
    let value = json_of(
        &[
            "audit",
            "--request",
            "examples/age-minimal-request-sdjwt.json",
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        0,
    );
    assert_eq!(value["outcome"], "ok");
    assert_eq!(value["warnings"], json!([]));
    let value = json_of(&["audit", "--request", "minimal", "--json"], 0);
    assert_eq!(value["warnings"], json!([]));
}

#[test]
fn audit_over_ask_wins_over_an_ignored_member() {
    let request = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["age_equal_or_over", "18"] }, { "path": ["address"] }],
        "claim": [{ "path": ["given_name"] }],
    }] })
    .to_string();
    let (code, stdout, stderr) = audit_age_gate(&request);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(
        stdout.starts_with(
            "OVER-ASK: Over-ask vs purpose: 1 of 2 requested claims exceed the stated purpose.\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\nAuthoring warnings:\n  {}\n\nOver-asking 1 claim(s) beyond the stated purpose.\nIgnored by a wallet that does not know them: 1 member(s) of the query.\n",
            claim_for_claims_line()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("\nLegal basis:\n"), "{stdout}");
    let value = json_of(
        &[
            "audit",
            "--request",
            &request,
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        1,
    );
    assert_eq!(value["outcome"], "over_ask");
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
    assert_eq!(
        value["verdict_line"],
        "Over-ask vs purpose: 1 of 2 requested claims exceed the stated purpose."
    );

    // With a claim that could not be judged: the result was NOT EVALUATED
    // already, and the reason line names the claim and the member.
    let request = json!({
        "credentials": [
            pid_age_query_with(json!({})),
            { "id": "card", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:example:member-card:1"] },
              "claims": [{ "path": ["member_number"] }] },
        ],
        "credential_set": [{ "options": [["pid"], ["card"]] }],
    })
    .to_string();
    let (code, stdout, _) = audit_age_gate(&request);
    assert_eq!(code, 3, "{stdout}");
    assert!(
        stdout.starts_with("NOT EVALUATED: 1 of 2 requested claims could not be judged.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\nAuthoring warnings:\n  {}\n",
            near_miss_line("query", "credential_set", "DCQL query", "credential_sets")
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("\nNot evaluated: 1 claim(s), and 1 member(s) of the query that a wallet ignores unless it knows them from an extension. No judged claim asks for too much; exit code 3.\n"),
        "{stdout}"
    );
}

#[test]
fn audit_ignored_member_under_a_baseline_file() {
    let (code, stdout, stderr) = audit_with_example(IGNORED_MEMBER_EXAMPLE, WINE);
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert!(
        stdout.starts_with(&format!(
            "NOT EVALUATED: 1 member(s) of the query resemble a defined member and are ignored by a wallet that does not know them.\n\
             Registration purpose: no registration given   Baseline: Example Wine Shop: age check for an order of wine\n\
             {WINE_FACTS}{DRAFT_LINE}{WINE_APPLIES}\n\
             Requested claims:\n\
             \n\
             Authoring warnings:\n  {}\n\
             \n\
             Not evaluated: 1 member(s) of the query that a wallet ignores unless it knows them from an extension. No judged claim asks for too much; exit code 3.\n\
             \n\
             Minimal claims of this baseline entry (dc+sd-jwt, urn:eudi:pid:de:1):\n",
            claim_for_claims_line()
        )),
        "{stdout}"
    );
    assert!(
        stdout.ends_with(&format!("\n{ASSESSMENT_LINE}")),
        "{stdout}"
    );
    let value = json_of(
        &[
            "audit",
            "--request",
            IGNORED_MEMBER_EXAMPLE,
            "--baseline",
            EXAMPLE_BASELINES,
            "--purpose",
            WINE,
            "--json",
        ],
        3,
    );
    assert_eq!(value["outcome"], "not_evaluated");
    assert_eq!(value["baseline"]["source"], "file");
    assert_eq!(value["warnings"][0]["member"], "claim");

    // The correctly spelled minimal request stays OK under the same entry.
    let (code, _, _) = audit_with_example("examples/age-minimal-request-sdjwt.json", WINE);
    assert_eq!(code, 0);
}

/// Extensions are allowed: an unknown member that resembles no defined one
/// gets no warning and changes nothing.
#[test]
fn audit_unknown_member_that_is_no_near_miss_stays_ok() {
    let plain = json!({ "credentials": [pid_age_query_with(json!({}))] }).to_string();
    let mut credential = pid_age_query_with(json!({ "x_example_profile": "invented" }));
    credential["claims"][0]["x_example_note"] = json!("invented extension member");
    let extended = json!({
        "credentials": [credential],
        "x_example_extension": { "enabled": true },
    })
    .to_string();

    let (plain_code, plain_text, _) = audit_age_gate(&plain);
    let (code, text, stderr) = audit_age_gate(&extended);
    assert_eq!(plain_code, 0, "{plain_text}");
    assert_eq!(code, 0, "{text}{stderr}");
    assert!(text.starts_with("OK: "), "{text}");
    assert_eq!(text, plain_text);
    let value = json_of(
        &[
            "audit",
            "--request",
            &extended,
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        0,
    );
    assert_eq!(value["outcome"], "ok");
    assert_eq!(value["warnings"], json!([]));

    let (code, stdout, _) = run_cli(&["validate", "dcql", &extended]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "DCQL VALID: no structural or reference issues found.\n"
    );
    let (code, stdout, _) = run_cli(&["inspect", &extended]);
    assert_eq!(code, 0);
    assert!(!stdout.contains("authoring warnings"), "{stdout}");
}

/// One run per near-miss name: the member is named with its place and the
/// defined name, and no run ends with OK.
#[test]
fn audit_each_listed_near_miss() {
    let pid = |extra: serde_json::Value| pid_age_query_with(extra);
    let claims_with = |claim: serde_json::Value| {
        json!({ "id": "pid", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] }, "claims": [claim] })
    };
    // (query, place, member, level, defined name, exit code)
    let cases = [
        (
            fs::read_to_string(IGNORED_MEMBER_EXAMPLE).expect("example"),
            "credentials[0]",
            "claim",
            "Credential Query",
            "claims",
            3,
        ),
        (
            json!({ "credentials": [pid(json!({ "claims_set": [["age"]] }))] }).to_string(),
            "credentials[0]",
            "claims_set",
            "Credential Query",
            "claim_sets",
            3,
        ),
        (
            json!({ "credentials": [pid(json!({ "claim_set": [["age"]] }))] }).to_string(),
            "credentials[0]",
            "claim_set",
            "Credential Query",
            "claim_sets",
            3,
        ),
        (
            json!({ "credentials": [pid(json!({}))],
                "credential_set": [{ "options": [["pid"]] }] })
            .to_string(),
            "query",
            "credential_set",
            "DCQL query",
            "credential_sets",
            3,
        ),
        (
            json!({ "credential": [pid(json!({}))] }).to_string(),
            "query",
            "credential",
            "DCQL query",
            "credentials",
            1,
        ),
        (
            json!({ "credentials": [pid(json!({}))],
                "credential_sets": [{ "option": [["pid"]] }] })
            .to_string(),
            "credential_sets[0]",
            "option",
            "Credential Set Query",
            "options",
            1,
        ),
        (
            json!({ "credentials": [claims_with(json!({ "paths": ["age_equal_or_over", "18"] }))] })
                .to_string(),
            "credentials[0].claims[0]",
            "paths",
            "Claims Query",
            "path",
            1,
        ),
        (
            json!({ "credentials": [claims_with(
                json!({ "path": ["age_equal_or_over", "18"], "value": [true] })
            )] })
            .to_string(),
            "credentials[0].claims[0]",
            "value",
            "Claims Query",
            "values",
            3,
        ),
    ];
    for (query, place, member, level, defined, expected) in &cases {
        let line = near_miss_line(place, member, level, defined);
        let (code, stdout, stderr) = audit_age_gate(query);
        assert_eq!(code, *expected, "{member}: {stdout}{stderr}");
        assert!(!stdout.starts_with("OK"), "{member}: {stdout}");
        if *expected == 3 {
            assert!(stdout.starts_with("NOT EVALUATED: "), "{member}: {stdout}");
            assert!(
                stdout.contains(&format!("\nAuthoring warnings:\n  {line}\n")),
                "{member}: {stdout}"
            );
        } else {
            // The typed parse rejects the query: an error as before, with
            // one more cause line that names the member.
            assert!(stdout.is_empty(), "{member}: {stdout}");
            assert!(
                stderr.starts_with(
                    "Error: --request must be 'minimal', 'overask', or a DCQL JSON value ("
                ),
                "{member}: {stderr}"
            );
            assert!(
                stderr.contains(&format!(
                    "\nCaused by:\n    0: the query has 1 member(s) that a wallet ignores unless it knows them from an extension: {line}\n    1: parse DCQL query\n    2: missing field `"
                )),
                "{member}: {stderr}"
            );
        }
    }
}

/// An unsigned registration certificate (only the payload is read) with the
/// given payload, as a file. Returns its path.
fn unsigned_certificate(name: &str, payload: &serde_json::Value) -> String {
    let b64 = |v: &str| BASE64_URL_SAFE_NO_PAD.encode(v.as_bytes());
    let header = json!({ "alg": "ES256", "typ": "rc-wrp+jwt" }).to_string();
    let dir = test_temp_dir("augenmass-cli-cert");
    fs::create_dir_all(&dir).expect("create cert dir");
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            "{}.{}.{}",
            b64(&header),
            b64(&payload.to_string()),
            b64("not-a-signature")
        ),
    )
    .expect("write certificate");
    path.display().to_string()
}

/// The rule is for DCQL queries only. In a registration body and in a
/// registration certificate `claim` is a defined name.
#[test]
fn registration_bodies_and_certificates_get_no_warning() {
    let body = json!({
        "rpId": "rp-example",
        "purpose": [{ "lang": "en", "content": "age check" }],
        "privacy_policy": "https://shop.example/privacy",
        "support_uri": "support@shop.example",
        "credentials": [{
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            "claim": [{ "path": ["age_equal_or_over", "18"] }],
        }],
    })
    .to_string();
    let (code, stdout, stderr) = run_cli(&["check", &body]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stdout.starts_with("OK: no over-ask, no format errors. "),
        "{stdout}"
    );
    assert!(!stdout.contains("warning"), "{stdout}");
    let value = json_of(&["check", &body, "--json"], 0);
    assert_eq!(value["outcome"], "ok");
    assert!(value.get("warnings").is_none());
    assert!(value["report"].get("warnings").is_none());
    let (code, stdout, _) = isolated_output(&["register", &body], &[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains("warning"), "{stdout}");
    // `inspect` detects a registration body and runs the same check.
    let (code, stdout, stderr) = run_cli(&["inspect", &body]);
    assert_eq!(code, 0);
    assert_eq!(stderr, "Detected: registrar registration body\n");
    assert!(!stdout.contains("warning"), "{stdout}");

    // A registration certificate whose credential uses `claim`.
    let certificate = unsigned_certificate(
        "cert-claim.jwt",
        &json!({
            "name": "Example Wine Shop",
            "purpose": [{ "lang": "en", "content": "Example Wine Shop: confirm the buyer is over 18" }],
            "privacy_policy": "https://wine.example.org/privacy",
            "support_uri": "support@wine.example.org",
            "credentials": [{
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                "claim": [{ "path": ["age_equal_or_over", "18"] }],
            }],
        }),
    );
    for args in [
        vec!["decode", "regcert", certificate.as_str()],
        vec!["inspect", certificate.as_str()],
        vec!["decode", "regcert", "examples/age-broad-registration.jwt"],
    ] {
        let (code, stdout, stderr) = run_cli(&args);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert!(stdout.contains("      claim "), "{args:?}: {stdout}");
        assert!(
            !stdout.to_lowercase().contains("warning"),
            "{args:?}: {stdout}"
        );
        assert!(
            !stdout.contains("DCQL-MEMBER-NEAR-MISS"),
            "{args:?}: {stdout}"
        );
    }
    let args = [
        "audit",
        "--request",
        "examples/age-minimal-request-sdjwt.json",
        "--purpose",
        "age_gate_18",
        "--cert",
        certificate.as_str(),
    ];
    let (code, stdout, stderr) = run_cli(&args);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.starts_with("OK: "), "{stdout}");
    assert!(!stdout.contains("Authoring warnings"), "{stdout}");
    let mut json_args = vec!["--json"];
    json_args.extend(args);
    let value = json_of(&json_args, 0);
    assert_eq!(value["warnings"], json!([]));
    assert_eq!(value["counts"]["registration_evaluated"], true);
}

/// This pins a stated limit of the rule, not a claim that the member is a
/// mistake. OpenID4VP 1.0 lets an extension define further members, and an
/// extension may choose a name that differs from a defined one only by
/// upper and lower case. The tool cannot know which extensions a wallet
/// implements: it reports the member with that condition, and the result is
/// NOT EVALUATED, never OVER-ASK and never an error.
#[test]
fn near_miss_that_an_extension_could_define_is_reported_with_the_condition() {
    let request = json!({ "credentials": [pid_age_query_with(
        json!({ "ID": "x-example-correlation" })
    )] })
    .to_string();
    let (code, stdout, stderr) = audit_age_gate(&request);
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert!(stdout.starts_with("NOT EVALUATED: "), "{stdout}");
    let line = near_miss_line("credentials[0]", "ID", "Credential Query", "id");
    assert!(
        stdout.contains(&format!("\nAuthoring warnings:\n  {line}\n")),
        "{stdout}"
    );
    assert!(
        line.ends_with("unless the wallet implements an extension that defines it."),
        "{line}"
    );
    let (code, stdout, _) = run_cli(&["validate", "dcql", &request]);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains(&line), "{stdout}");
    assert!(
        stdout.contains("If it belongs to an extension that the wallet implements, keep it; this warning then does not apply."),
        "{stdout}"
    );
}

/// No output says without a condition that a member has no effect or that a
/// wallet ignores it: a wallet that implements an extension which defines
/// the member does not ignore it. This keeps a later rewording from
/// dropping the condition.
#[test]
fn no_output_says_unconditionally_that_a_member_has_no_effect() {
    let over_ask = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "claims": [{ "path": ["address"] }],
        "claim": [{ "path": ["given_name"] }],
    }] })
    .to_string();
    let with_unjudged = json!({
        "credentials": [
            pid_age_query_with(json!({ "ID": "x-example-correlation" })),
            { "id": "card", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:example:member-card:1"] },
              "claims": [{ "path": ["member_number"] }] },
        ],
    })
    .to_string();
    let rejected = json!({ "credential": [pid_age_query_with(json!({}))] }).to_string();
    let runs: Vec<Vec<&str>> = vec![
        vec!["validate", "dcql", IGNORED_MEMBER_EXAMPLE],
        vec!["inspect", IGNORED_MEMBER_EXAMPLE],
        vec![
            "audit",
            "--request",
            IGNORED_MEMBER_EXAMPLE,
            "--purpose",
            "age_gate_18",
        ],
        vec!["audit", "--request", &over_ask, "--purpose", "age_gate_18"],
        vec![
            "audit",
            "--request",
            &with_unjudged,
            "--purpose",
            "age_gate_18",
        ],
        vec![
            "audit",
            "--request",
            IGNORED_MEMBER_EXAMPLE,
            "--baseline",
            EXAMPLE_BASELINES,
            "--purpose",
            WINE,
        ],
        vec!["audit", "--request", &rejected, "--purpose", "age_gate_18"],
        vec!["validate", "dcql", &rejected],
    ];
    let mut checked = 0;
    for args in &runs {
        let (_, stdout, stderr) = run_cli(args);
        for line in stdout.lines().chain(stderr.lines()) {
            let lower = line.to_lowercase();
            if lower.contains("has no effect") {
                assert!(lower.contains("unless"), "{args:?}: {line}");
                checked += 1;
            }
            if lower.contains("ignores") || lower.contains("ignored by") {
                assert!(
                    lower.contains("does not know") || lower.contains("unless"),
                    "{args:?}: {line}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 2 * runs.len(), "{checked} lines checked");
    assert!(!IGNORED_MEMBER_EXAMPLE.contains("ignores"));
    assert!(!IGNORED_MEMBER_EXAMPLE.contains("no effect"));
}

/// A PID credential query whose three claims sit under `member`.
fn three_claims_under(member: &str) -> serde_json::Value {
    let mut credential = json!({
        "id": "pid",
        "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
    });
    credential[member] = json!([
        { "path": ["given_name"] },
        { "path": ["birthdate"] },
        { "path": ["address"] },
    ]);
    credential
}

/// One query through the three commands: `audit` gives NOT EVALUATED with
/// exit code 3 and never a bare OK, `validate dcql` stays valid with the
/// warning, `inspect` prints it. All three name the member and the defined
/// name. `line` is a part of the warning line.
fn assert_warned_by_all_three_commands(query: &str, member: &str, resembles: &str, line: &str) {
    let (code, stdout, stderr) = audit_age_gate(query);
    assert_eq!(code, 3, "{member:?}: {stdout}{stderr}");
    assert!(
        stdout.starts_with(
            "NOT EVALUATED: 1 member(s) of the query resemble a defined member and are ignored by a wallet that does not know them.\n"
        ),
        "{member:?}: {stdout}"
    );
    assert!(
        stdout.contains("\nAuthoring warnings:\n  ") && stdout.contains(line),
        "{member:?}: {stdout}"
    );
    let value = json_of(
        &[
            "audit",
            "--request",
            query,
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        3,
    );
    assert_eq!(value["outcome"], "not_evaluated", "{member:?}");
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
    assert_eq!(value["warnings"][0]["id"], "DCQL-MEMBER-NEAR-MISS");
    assert_eq!(value["warnings"][0]["member"], member);
    assert_eq!(value["warnings"][0]["resembles"], resembles);

    let (code, stdout, stderr) = run_cli(&["validate", "dcql", query]);
    assert_eq!(code, 0, "{member:?}: {stdout}{stderr}");
    assert!(
        stdout.starts_with("DCQL findings:\n  DCQL-MEMBER-NEAR-MISS [warning]: "),
        "{member:?}: {stdout}"
    );
    assert!(stdout.contains(line), "{member:?}: {stdout}");
    assert!(
        stdout.ends_with("DCQL OK (warnings only).\n"),
        "{member:?}: {stdout}"
    );
    let value = json_of(&["validate", "dcql", query, "--json"], 0);
    assert_eq!(value["valid"], true);
    assert_eq!(value["warnings"][0]["member"], member);

    let (code, stdout, stderr) = run_cli(&["inspect", query]);
    assert_eq!(code, 0, "{member:?}: {stdout}{stderr}");
    assert!(
        stdout.contains("  authoring warnings: 1\n    ") && stdout.contains(line),
        "{member:?}: {stdout}"
    );
    let value = json_of(&["inspect", query, "--json"], 0);
    assert_eq!(value["warnings"][0]["member"], member);
    assert_eq!(value["warnings"][0]["resembles"], resembles);
}

/// A member name that differs from a defined one only by upper and lower
/// case is reported wherever the upper-case letter is. `claimS` and the
/// other names that end in an upper-case S got a bare OK before.
#[test]
fn near_miss_by_case_only_is_warned_by_all_three_commands() {
    for member in [
        "claimS", "cLaImS", "CLAIMS", "Claims", "ClaimS", "claiM", "CLAIM",
    ] {
        let query = json!({ "credentials": [three_claims_under(member)] }).to_string();
        let line = near_miss_line("credentials[0]", member, "Credential Query", "claims");
        assert_warned_by_all_three_commands(&query, member, "claims", &line);
    }
    // The same at the other levels: the query object, a claims query, and
    // `claim_sets` next to `claims`.
    let pid = pid_age_query_with(json!({}));
    for member in ["credential_setS", "cReDeNtIaL_sEtS", "credentialSetS"] {
        let mut query = json!({ "credentials": [pid] });
        query[member] = json!([{ "options": [["pid"]] }]);
        let line = near_miss_line("query", member, "DCQL query", "credential_sets");
        assert_warned_by_all_three_commands(&query.to_string(), member, "credential_sets", &line);
    }
    for member in ["valueS", "vAlUeS"] {
        let mut credential = pid_age_query_with(json!({}));
        credential["claims"][0][member] = json!([true]);
        let query = json!({ "credentials": [credential] }).to_string();
        let line = near_miss_line("credentials[0].claims[0]", member, "Claims Query", "values");
        assert_warned_by_all_three_commands(&query, member, "values", &line);
    }
    for member in ["claim_setS", "cLaIm_sEtS", "claimSetS"] {
        let mut credential = pid_age_query_with(json!({}));
        credential[member] = json!([["age"]]);
        let query = json!({ "credentials": [credential] }).to_string();
        let line = near_miss_line("credentials[0]", member, "Credential Query", "claim_sets");
        assert_warned_by_all_three_commands(&query, member, "claim_sets", &line);
    }
}

/// A member name that differs from a defined one only by characters that
/// are not letters (a space or a tab before or after it, a digit, a dot, a
/// character without width) or by a letter written twice is reported. Each
/// of these got a bare OK before.
#[test]
fn near_miss_by_characters_that_are_not_letters_is_warned_by_all_three_commands() {
    for member in [
        "claims ", "claim ", " claim", " claims", "claims1", "claim1", "claims.", "claimss",
    ] {
        let query = json!({ "credentials": [three_claims_under(member)] }).to_string();
        let line = near_miss_line("credentials[0]", member, "Credential Query", "claims");
        assert_warned_by_all_three_commands(&query, member, "claims", &line);
    }
    // A tab and a character without width are printed as their escape in
    // the warning line, so the name does not read like the defined one;
    // `--json` carries the name as written in `member`.
    for (member, printed) in [
        ("claims\t", "claims\\t"),
        ("claims\u{200b}", "claims\\u{200b}"),
    ] {
        let query = json!({ "credentials": [three_claims_under(member)] }).to_string();
        let line = near_miss_line("credentials[0]", printed, "Credential Query", "claims");
        assert_warned_by_all_three_commands(&query, member, "claims", &line);
    }

    // The other levels.
    for (member, resembles) in [
        ("values ", "values"),
        ("value ", "values"),
        ("valuess", "values"),
    ] {
        let mut credential = pid_age_query_with(json!({}));
        credential["claims"][0][member] = json!([true]);
        let query = json!({ "credentials": [credential] }).to_string();
        let line = near_miss_line(
            "credentials[0].claims[0]",
            member,
            "Claims Query",
            resembles,
        );
        assert_warned_by_all_three_commands(&query, member, resembles, &line);
    }
    for member in ["credential_sets ", "credential_sets1"] {
        let mut query = json!({ "credentials": [pid_age_query_with(json!({}))] });
        query[member] = json!([{ "options": [["pid"]] }]);
        let line = near_miss_line("query", member, "DCQL query", "credential_sets");
        assert_warned_by_all_three_commands(&query.to_string(), member, "credential_sets", &line);
    }
    for member in ["claim_sets ", "claim_setss"] {
        let mut credential = pid_age_query_with(json!({}));
        credential[member] = json!([["age"]]);
        let query = json!({ "credentials": [credential] }).to_string();
        let line = near_miss_line("credentials[0]", member, "Credential Query", "claim_sets");
        assert_warned_by_all_three_commands(&query, member, "claim_sets", &line);
    }
}

/// The claims of a credential query under a name that is no near miss of
/// `claims` by its spelling (another letter, a look-alike letter outside
/// ASCII): the member is reported by the form of its value, because the
/// credential query has no `claims` member. Each of these got a bare OK
/// before. With `claims` present the same member is an extension member
/// and changes nothing.
#[test]
fn claims_under_another_name_never_get_a_bare_ok() {
    // (member, the member as the warning line prints it)
    for (member, printed) in [
        ("claimz", "claimz"),
        ("klaims", "klaims"),
        ("cla\u{456}ms", "cla\\u{456}ms"),
        ("requested_claims", "requested_claims"),
    ] {
        let query = json!({ "credentials": [three_claims_under(member)] }).to_string();
        let line = format!(
            "credentials[0]: member \"{printed}\" is not defined by OpenID4VP 1.0 for a Credential Query, its value has the form of a \"claims\" value (an array of objects with a \"path\" member), and the Credential Query has no \"claims\" member. A wallet ignores a member it does not know (OpenID4VP 1.0, section 6: \"Implementations MUST ignore any unknown properties.\"), so \"{printed}\" has no effect on the request unless the wallet implements an extension that defines it."
        );
        assert_warned_by_all_three_commands(&query, member, "claims", &line);
    }

    // `claims` is there: the other member is an extension member.
    let plain = json!({ "credentials": [pid_age_query_with(json!({}))] }).to_string();
    let extended = json!({ "credentials": [pid_age_query_with(json!({
        "klaims": [{ "path": ["given_name"] }, { "path": ["address"] }],
    }))] })
    .to_string();
    let (plain_code, plain_text, _) = audit_age_gate(&plain);
    let (code, text, stderr) = audit_age_gate(&extended);
    assert_eq!((plain_code, code), (0, 0), "{text}{stderr}");
    assert_eq!(text, plain_text);
    let (code, stdout, _) = run_cli(&["validate", "dcql", &extended]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "DCQL VALID: no structural or reference issues found.\n"
    );

    // A credential query without claims and without such a member stays OK.
    let no_claims = json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
        "x_example_labels": [{ "lang": "en", "text": "invented" }],
    }] })
    .to_string();
    let (code, stdout, stderr) = audit_age_gate(&no_claims);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.starts_with("OK: No claims requested.\n"), "{stdout}");
}

/// A request object given as JSON (not a signed JAR) is read by `inspect`
/// and `decode request`, and `inspect` prints the authoring warnings of its
/// `dcql_query`, as `audit` and `validate dcql` do for the same file. Before,
/// `inspect` tried to decode the JSON as a compact JWT and ended with an
/// error and exit code 1.
#[test]
fn inspect_reads_a_plain_request_object_and_agrees_with_audit_and_validate() {
    let request = json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_id": "x509_hash:example-not-a-real-hash",
        "nonce": "n-0S6_WzA2Mj",
        "state": "invented-state",
        "dcql_query": { "credentials": [three_claims_under("claim")] },
    })
    .to_string();
    let line = claim_for_claims_line();

    let (code, stdout, stderr) = audit_age_gate(&request);
    assert_eq!(code, 3, "{stdout}{stderr}");
    assert!(stdout.contains(&line), "{stdout}");
    let (code, stdout, _) = run_cli(&["validate", "dcql", &request]);
    assert_eq!(code, 0);
    assert!(stdout.contains(&line), "{stdout}");

    let expected = format!(
        "OpenID4VP authorization request object (plain JSON, not a signed JAR)\n  client_id: x509_hash:example-not-a-real-hash\n  client_id scheme: x509_hash\n  response_type: vp_token\n  response_mode: direct_post\n  nonce: n-0S6_WzA2Mj\n  state: invented-state\n  query: dcql_query present\n  authoring warnings: 1\n    {line}\n"
    );
    let (code, stdout, stderr) = run_cli(&["inspect", &request]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(
        stderr,
        "Detected: OpenID4VP authorization request object (plain JSON, not a signed JAR)\n"
    );
    assert_eq!(stdout, expected);
    let (code, stdout, stderr) = run_cli(&["decode", "request", &request]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(stdout, expected);

    let value = json_of(&["inspect", &request, "--json"], 0);
    assert_eq!(value["artifact"], "authorization-request");
    assert_eq!(value["header"], serde_json::Value::Null);
    assert_eq!(value["x5cPresent"], false);
    assert_eq!(value["clientIdScheme"], "x509_hash");
    assert_eq!(value["warnings"].as_array().expect("warnings").len(), 1);
    assert_eq!(value["warnings"][0]["member"], "claim");
    assert_eq!(value["warnings"][0]["place"], "credentials[0]");
    assert_eq!(
        value["payload"],
        serde_json::from_str::<serde_json::Value>(&request).expect("json")
    );

    // The request object without a `client_id` is detected by `response_type`.
    let mut without_client: serde_json::Value = serde_json::from_str(&request).expect("json");
    without_client
        .as_object_mut()
        .expect("object")
        .remove("client_id");
    let (code, stdout, stderr) = run_cli(&["inspect", &without_client.to_string()]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("  authoring warnings: 1\n"), "{stdout}");

    // The payload of a decoded JAR is such a request object: it goes back
    // into `inspect` and `decode request`. The JAR has no warning.
    let jar = json_of(&["decode", "request", JAR_FIXTURE, "--json"], 0);
    assert_eq!(jar["warnings"], json!([]));
    assert!(jar["header"].is_object());
    let payload = jar["payload"].to_string();
    for args in [
        vec!["inspect", payload.as_str()],
        vec!["decode", "request", payload.as_str()],
    ] {
        let (code, stdout, stderr) = run_cli(&args);
        assert_eq!(code, 0, "{args:?}: {stdout}{stderr}");
        assert!(
            stdout.starts_with(
                "OpenID4VP authorization request object (plain JSON, not a signed JAR)\n"
            ),
            "{stdout}"
        );
        assert!(stdout.contains("  query: dcql_query present\n"), "{stdout}");
        assert!(!stdout.contains("authoring warnings"), "{stdout}");
    }
    let again = json_of(&["inspect", &payload, "--json"], 0);
    assert_eq!(again["payload"], jar["payload"]);
    assert_eq!(again["nonce"], jar["nonce"]);

    // The text output of the JAR itself is the one of before.
    let (code, stdout, _) = run_cli(&["decode", "request", JAR_FIXTURE]);
    assert_eq!(code, 0);
    assert!(
        stdout
            .starts_with("OpenID4VP authorization request / JAR (no signature verified)\n  typ: "),
        "{stdout}"
    );
    assert!(!stdout.contains("authoring warnings"), "{stdout}");

    // Input that is neither a JSON object nor a compact JWT stays an error.
    let (code, stdout, stderr) = run_cli(&["decode", "request", "[1, 2]"]);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.starts_with("Error: decode authorization request JAR\n"),
        "{stderr}"
    );
}

/// The `Detected:` line of `inspect` names the form of an authorization
/// request and never contradicts the first line of the result: a plain
/// request object is not called a JAR, a compact JWT is. Before, the line
/// read `Detected: OpenID4VP authorization request (JAR)` for both, above a
/// result that said "not a signed JAR".
#[test]
fn inspect_detected_line_names_the_form_of_an_authorization_request() {
    const OBJECT: &str =
        "Detected: OpenID4VP authorization request object (plain JSON, not a signed JAR)\n";
    const JAR: &str = "Detected: OpenID4VP authorization request (JAR)\n";

    // The three shapes that are read as a plain request object.
    for request in [
        json!({ "response_type": "vp_token" }),
        json!({ "client_metadata": {} }),
        json!({
            "client_id": "x509_hash:example-not-a-real-hash",
            "dcql_query": { "credentials": [three_claims_under("claims")] },
        }),
    ] {
        let request = request.to_string();
        for json_flag in [false, true] {
            let mut args = vec!["inspect", request.as_str()];
            if json_flag {
                args.push("--json");
            }
            let (code, stdout, stderr) = run_cli(&args);
            assert_eq!(code, 0, "{request}: {stdout}{stderr}");
            assert_eq!(stderr, OBJECT, "{request}");
            if json_flag {
                let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
                assert_eq!(value["artifact"], "authorization-request", "{request}");
                assert_eq!(value["header"], serde_json::Value::Null, "{request}");
            } else {
                assert_eq!(
                    stdout.lines().next(),
                    Some("OpenID4VP authorization request object (plain JSON, not a signed JAR)"),
                    "{request}"
                );
            }
        }
    }

    // A signed JAR keeps the line and the first result line of before.
    let (code, stdout, stderr) = run_cli(&["inspect", JAR_FIXTURE]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(stderr, JAR);
    assert_eq!(
        stdout.lines().next(),
        Some("OpenID4VP authorization request / JAR (no signature verified)")
    );

    // So does a compact JWT that is recognised by its payload, not its `typ`.
    let b64 = |v: &str| BASE64_URL_SAFE_NO_PAD.encode(v.as_bytes());
    let jwt = format!(
        "{}.{}.{}",
        b64(&json!({ "alg": "ES256" }).to_string()),
        b64(&json!({ "response_type": "vp_token" }).to_string()),
        b64("not-a-signature")
    );
    let (code, stdout, stderr) = run_cli(&["inspect", &jwt]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(stderr, JAR);
}

/// A signed JAR whose `dcql_query` has a near-miss member: `inspect` and
/// `decode request` print the warning for it as well.
#[test]
fn inspect_prints_the_authoring_warning_for_a_jar() {
    let b64 = |v: &str| BASE64_URL_SAFE_NO_PAD.encode(v.as_bytes());
    let header = json!({ "alg": "ES256", "typ": "oauth-authz-req+jwt" }).to_string();
    let payload = json!({
        "response_type": "vp_token",
        "client_id": "x509_hash:example-not-a-real-hash",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": { "credentials": [three_claims_under("claim")] },
    })
    .to_string();
    let jar = format!(
        "{}.{}.{}",
        b64(&header),
        b64(&payload),
        b64("not-a-signature")
    );
    for args in [
        vec!["inspect", jar.as_str()],
        vec!["decode", "request", jar.as_str()],
    ] {
        let (code, stdout, stderr) = run_cli(&args);
        assert_eq!(code, 0, "{args:?}: {stdout}{stderr}");
        assert!(
            stdout.starts_with(
                "OpenID4VP authorization request / JAR (no signature verified)\n  typ: oauth-authz-req+jwt\n  alg: ES256\n  x5c present: false\n"
            ),
            "{stdout}"
        );
        assert!(
            stdout.ends_with(&format!(
                "  query: dcql_query present\n  authoring warnings: 1\n    {}\n",
                claim_for_claims_line()
            )),
            "{stdout}"
        );
    }
    let value = json_of(&["inspect", &jar, "--json"], 0);
    assert_eq!(value["warnings"][0]["member"], "claim");
    assert_eq!(value["header"]["typ"], "oauth-authz-req+jwt");
}

// --- wording, the baseline file reader, register --json ----------------------

/// The first value of the line under the headline is the purpose text of
/// the registration, not the purpose id of `--purpose`. The line says so,
/// and says why it has no text. No `--json` member changes with it.
#[test]
fn registration_purpose_line_says_what_is_and_is_not_stated() {
    // No registration given, with and without --purpose.
    let (_, stdout, _) = run_cli(&["audit", "--request", "minimal"]);
    assert_eq!(
        stdout.lines().nth(1),
        Some("Registration purpose: no registration given   Baseline: Event check-in")
    );
    let (_, stdout, _) = audit_age_gate("minimal");
    assert_eq!(
        stdout.lines().nth(1),
        Some("Registration purpose: no registration given   Baseline: Age gate (over 18)")
    );
    let value = json_of(
        &[
            "audit",
            "--request",
            "minimal",
            "--purpose",
            "age_gate_18",
            "--json",
        ],
        1,
    );
    assert_eq!(value["purpose"], serde_json::Value::Null);
    assert_eq!(value["baseline_label"], "Age gate (over 18)");

    // A registration certificate with a purpose text.
    let cert = "examples/age-broad-registration.jwt";
    let (_, stdout, _) = run_cli(&[
        "audit",
        "--request",
        "minimal",
        "--purpose",
        "age_gate_18",
        "--cert",
        cert,
    ]);
    assert_eq!(
        stdout.lines().nth(2),
        Some("Registration purpose: Example Wine Shop: confirm the buyer is over 18   Baseline: Age gate (over 18)")
    );
    let value = json_of(
        &[
            "audit",
            "--request",
            "minimal",
            "--purpose",
            "age_gate_18",
            "--cert",
            cert,
            "--json",
        ],
        1,
    );
    assert_eq!(
        value["purpose"],
        "Example Wine Shop: confirm the buyer is over 18"
    );

    // A registration certificate that states no purpose.
    let no_purpose = unsigned_certificate(
        "cert-no-purpose.jwt",
        &json!({
            "name": "Example Wine Shop",
            "privacy_policy": "https://wine.example.org/privacy",
            "support_uri": "support@wine.example.org",
            "credentials": [{
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                "claims": [{ "path": ["age_equal_or_over", "18"] }],
            }],
        }),
    );
    let args = [
        "audit",
        "--request",
        "examples/age-minimal-request-sdjwt.json",
        "--purpose",
        "age_gate_18",
        "--cert",
        no_purpose.as_str(),
    ];
    let (code, stdout, stderr) = run_cli(&args);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(
        stdout.lines().nth(2),
        Some("Registration purpose: not stated in the registration   Baseline: Age gate (over 18)")
    );
    let mut json_args = vec!["--json"];
    json_args.extend(args);
    assert_eq!(json_of(&json_args, 0)["purpose"], serde_json::Value::Null);

    // `check`: the body is the registration.
    let (code, stdout, _) = run_cli(&["check", "examples/over.json"]);
    assert_eq!(code, 1);
    assert_eq!(
        stdout.lines().nth(1),
        Some("Registration purpose: Age verification   Baseline: Age gate (over 18)")
    );

    // The old label is gone from every one of these outputs.
    for args in [
        vec!["audit", "--request", "minimal"],
        vec!["audit", "--request", "overask", "--cert", cert],
        vec!["check", "examples/over.json"],
    ] {
        let (_, stdout, _) = run_cli(&args);
        for line in stdout.lines() {
            assert!(!line.starts_with("Purpose: "), "{args:?}: {line}");
        }
    }
}

/// A registration whose purpose text shows nothing (empty, white space, a
/// character without width) states no purpose: the line says so instead of
/// printing an empty value. `--json` carries the text unchanged.
#[test]
fn blank_registration_purpose_reads_as_not_stated() {
    let dir = test_temp_dir("augenmass-cli-blank-purpose");
    fs::create_dir_all(&dir).expect("create dir");
    let body: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("examples/over.json").expect("example"))
            .expect("json");
    for (name, content) in [
        ("empty.json", ""),
        ("space.json", "   "),
        ("tab-newline.json", "\t\n"),
        ("no-width.json", "\u{200b}"),
    ] {
        let mut blank = body.clone();
        blank["purpose"] = json!([{ "lang": "en", "content": content }]);
        let path = dir.join(name);
        fs::write(&path, blank.to_string()).expect("write body");
        let path = path.to_str().expect("utf8 path");

        let (code, stdout, stderr) = run_cli(&["check", path]);
        assert_eq!(code, 1, "{name}: {stdout}{stderr}");
        assert_eq!(
            stdout.lines().nth(1),
            Some("Registration purpose: not stated in the registration   Baseline: Age gate (over 18)"),
            "{name}"
        );
        let args = [
            "check",
            path,
            "--baseline",
            EXAMPLE_BASELINES,
            "--purpose",
            WINE,
        ];
        let (code, stdout, stderr) = run_cli(&args);
        assert_eq!(code, 1, "{name}: {stdout}{stderr}");
        assert_eq!(
            stdout.lines().nth(1),
            Some("Registration purpose: not stated in the registration   Baseline: Example Wine Shop: age check for an order of wine"),
            "{name}"
        );
        // No member of `--json` changes: the text is there as written.
        let mut json_args = vec!["--json"];
        json_args.extend(args);
        assert_eq!(
            json_of(&json_args, 1)["report"]["purpose"],
            content,
            "{name}"
        );
    }

    // A registration certificate with a blank purpose text, for `audit`.
    let blank_cert = unsigned_certificate(
        "cert-blank-purpose.jwt",
        &json!({
            "name": "Example Wine Shop",
            "purpose": [{ "lang": "en", "content": "  " }],
            "privacy_policy": "https://wine.example.org/privacy",
            "support_uri": "support@wine.example.org",
            "credentials": [{
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                "claims": [{ "path": ["age_equal_or_over", "18"] }],
            }],
        }),
    );
    let (code, stdout, stderr) = run_cli(&[
        "audit",
        "--request",
        "examples/age-minimal-request-sdjwt.json",
        "--purpose",
        "age_gate_18",
        "--cert",
        blank_cert.as_str(),
    ]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(
        stdout.lines().nth(2),
        Some("Registration purpose: not stated in the registration   Baseline: Age gate (over 18)")
    );

    // A purpose text with a visible character is printed as before.
    let mut stated = body.clone();
    stated["purpose"] = json!([{ "lang": "en", "content": " Example purpose " }]);
    let path = dir.join("stated.json");
    fs::write(&path, stated.to_string()).expect("write body");
    let (_, stdout, _) = run_cli(&["check", path.to_str().expect("utf8 path")]);
    assert_eq!(
        stdout.lines().nth(1),
        Some("Registration purpose:  Example purpose    Baseline: Age gate (over 18)")
    );
}

/// A purpose text made only of characters that a display shows as nothing
/// (the combining grapheme joiner U+034F, the variation selector U+FE0F and
/// the other code points Unicode lists as default ignorable, and the blank
/// Braille pattern) states no purpose either. Before, only five of these
/// characters were treated so, and `Registration purpose:` was followed by a
/// value that looked empty. `--json` carries the text unchanged.
#[test]
fn registration_purpose_of_characters_that_show_nothing_reads_as_not_stated() {
    let body: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("examples/over.json").expect("example"))
            .expect("json");
    let check = |content: &str| {
        let mut changed = body.clone();
        changed["purpose"] = json!([{ "lang": "en", "content": content }]);
        let changed = changed.to_string();
        let (code, stdout, stderr) = run_cli(&["check", &changed]);
        assert_eq!(code, 1, "{content:?}: {stdout}{stderr}");
        let line = stdout.lines().nth(1).expect("purpose line").to_string();
        let report = json_of(&["--json", "check", &changed], 1);
        assert_eq!(report["report"]["purpose"], content, "{content:?}");
        line
    };

    for content in [
        "\u{34f}",
        "\u{fe0f}",
        "\u{ad}",
        "\u{180e}",
        "\u{2064}",
        "\u{2800}",
        "\u{3164}",
        "\u{e0020}",
        " \u{34f}\u{fe0f}\u{200b} ",
    ] {
        assert_eq!(
            check(content),
            "Registration purpose: not stated in the registration   Baseline: Age gate (over 18)",
            "{content:?}"
        );
    }

    // A bidirectional formatting character is printed as its escape, which a
    // reader sees, and a visible character next to an ignorable one is text.
    assert_eq!(
        check("\u{202e}"),
        "Registration purpose: \\u{202e}   Baseline: Age gate (over 18)"
    );
    assert_eq!(
        check("Example\u{fe0f}"),
        "Registration purpose: Example\u{fe0f}   Baseline: Age gate (over 18)"
    );
}

/// `legal_review` would be true only because the file says `reviewed`. The
/// status and the reviewer are in the output; the member is not.
#[test]
fn baseline_json_has_no_legal_review_member() {
    let minimal = "examples/age-minimal-request-sdjwt.json";
    let (code, audit_json, _) = run_cli(&[
        "audit",
        "--request",
        minimal,
        "--baseline",
        EXAMPLE_BASELINES,
        "--purpose",
        WINE,
        "--json",
    ]);
    assert_eq!(code, 0);
    let (code, check_json, _) = run_cli(&[
        "check",
        "examples/min.json",
        "--baseline",
        EXAMPLE_BASELINES,
        "--purpose",
        WINE,
        "--json",
    ]);
    assert_eq!(code, 0);
    for text in [&audit_json, &check_json] {
        assert!(!text.contains("legal_review"), "{text}");
    }
    let audit: serde_json::Value = serde_json::from_str(&audit_json).expect("json");
    let check: serde_json::Value = serde_json::from_str(&check_json).expect("json");
    for baseline in [
        &audit["baseline"],
        &check["baseline"],
        &check["report"]["baseline"],
    ] {
        assert_eq!(baseline["status"], "draft", "{baseline}");
        assert_eq!(baseline["reviewer"], serde_json::Value::Null);
        assert_eq!(baseline["notice"], "draft baseline, no legal review");
    }
    // The text output keeps its wording.
    let (_, text, _) = audit_with_example(minimal, WINE);
    assert!(text.contains(DRAFT_LINE), "{text}");
}

/// A baseline file that starts with a UTF-8 byte order mark is rejected, and
/// the error names the mark.
#[test]
fn baseline_file_with_a_byte_order_mark_names_the_cause() {
    let dir = test_temp_dir("augenmass-cli-bom");
    fs::create_dir_all(&dir).expect("create dir");
    let file = dir.join("baselines-bom.json");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend(fs::read(EXAMPLE_BASELINES).expect("example"));
    fs::write(&file, bytes).expect("write file");
    let file = file.to_str().expect("utf8 path");
    for args in [
        vec![
            "audit",
            "--request",
            "minimal",
            "--baseline",
            file,
            "--purpose",
            WINE,
        ],
        vec![
            "check",
            "examples/min.json",
            "--baseline",
            file,
            "--purpose",
            WINE,
        ],
        vec!["audit", "--request", "minimal", "--baseline", file],
    ] {
        let (code, stdout, stderr) = run_cli(&args);
        assert_eq!(code, 1, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert_eq!(
            stderr,
            "Error: baseline file baselines-bom.json: the document: starts with a UTF-8 byte order mark (the bytes EF BB BF); save the file as UTF-8 without a byte order mark\n",
            "{args:?}"
        );
        assert!(!stderr.contains('\u{feff}'), "{args:?}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// The overlap error quotes its paths as JSON arrays, as the other baseline
/// output does: a character that is never printed raw is the JSON escape
/// (six ASCII characters), not the raw character and not the Rust escape.
#[test]
fn baseline_overlap_error_quotes_paths_as_json() {
    let path = "a\u{202e}b\u{2028}c";
    let mut file = one_entry_baseline();
    file["entries"][0]["claims"] = json!([{
        "format": "dc+sd-jwt",
        "vct_values": ["urn:example:test"],
        "minimal": [{ "path": [path] }, { "path": [path] }],
    }]);
    file["entries"][0]["one_of"] = json!([]);
    let file = baseline_file_in_temp("overlap.json", &file);
    let (code, stdout, stderr) = run_cli(&["audit", "--request", "minimal", "--baseline", &file]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");

    let quoted = r#"["a\u202eb\u2028c"]"#;
    assert_eq!(
        stderr,
        format!(
            "Error: baseline file overlap.json: entries[0] (example.test.age).claims[0]: the rows {quoted} and {quoted} overlap (both cover the path {quoted}); a requested claim must match at most one row of a block\n"
        )
    );
    // These two are what a comparison of decoded values cannot give: an
    // output with the raw characters decodes to the same path.
    assert!(!stderr.contains('\u{202e}'), "{stderr:?}");
    assert!(!stderr.contains('\u{2028}'), "{stderr:?}");
    assert!(!stderr.contains("\\u{"), "{stderr}");
    // And each quoted array is JSON with the path of the file.
    let mut arrays = 0;
    let mut rest = stderr.as_str();
    while let Some(start) = rest.find("[\"") {
        let end = start + rest[start..].find("\"]").expect("end of array") + 2;
        let parsed: Vec<String> = serde_json::from_str(&rest[start..end]).expect("valid JSON");
        assert_eq!(parsed, [path]);
        arrays += 1;
        rest = &rest[end..];
    }
    assert_eq!(arrays, 3, "{stderr}");
}

/// `--json` is a global flag and is accepted on `register`, where it has no
/// effect: the command prints its text output. The result as JSON is in
/// `check --json`.
#[test]
fn register_prints_text_with_and_without_json() {
    for body in ["examples/min.json", "examples/over.json"] {
        let body = repo_path(body);
        let plain = isolated_output(&["register", &body], &[]);
        assert!(!plain.1.trim_start().starts_with('{'), "{}", plain.1);
        assert_eq!(isolated_output(&["register", &body, "--json"], &[]), plain);
        assert_eq!(isolated_output(&["--json", "register", &body], &[]), plain);
    }
    let (code, stdout, _) = isolated_output(&["register", &repo_path("examples/min.json")], &[]);
    assert_eq!(code, 0);
    assert!(
        stdout.ends_with("DRY RUN: nothing written. Re-run with --yes to write to clone.\n"),
        "{stdout}"
    );
    // The outcome member is where the documents point to.
    let value = json_of(&["check", "examples/min.json", "--json"], 0);
    assert_eq!(value["outcome"], "ok");
}
