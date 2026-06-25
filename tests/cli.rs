//! End-to-end CLI tests against the committed offline fixtures. These pin the
//! observable behavior of every read-only command (detection, decoding,
//! verification, over-ask, exit codes) so refactors cannot silently regress it.
//! The registrar write path (register/list/clone) needs a live local server and
//! is exercised by `just verify` and the `clone_server` unit test, not here.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
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
            "response=not-a-real-jwe&state=abc",
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

fn status_evidence_source_session() -> PathBuf {
    let dir = test_temp_dir("augenmass-cli-status-evidence-source");
    fs::create_dir_all(&dir).expect("create status evidence source dir");
    let request_jwt =
        fs::read_to_string("fixtures/requests/eudiplo-request.jwt").expect("read request fixture");
    let presentation = fs::read_to_string("fixtures/presentations/synthetic-pid-with-status.sdjwt")
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
            "response=not-a-real-jwe&state=abc",
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
        .stdout(contains("age_equal_or_over.18"));
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
