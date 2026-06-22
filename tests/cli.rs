//! End-to-end CLI tests against the committed offline fixtures. These pin the
//! observable behavior of every read-only command (detection, decoding,
//! verification, over-ask, exit codes) so refactors cannot silently regress it.
//! The registrar write path (register/list/clone) needs a live local server and
//! is exercised by `just verify` and the `clone_server` unit test, not here.

use assert_cmd::Command;
use predicates::str::contains;

// Shared binding values for the ERICA / synthetic fixtures (see fixtures MANIFEST).
const NONCE: &str = "b4ba2623-76a2-486b-a1f6-f1656025d07b";
const AUD: &str = "https://self-issued.me/v2";
const NOW: &str = "1780435200";
const STATUS_KEY: &str = "fixtures/status/status-list-verify-key.pub.pem";

fn bin() -> Command {
    Command::cargo_bin("augenmass").expect("binary builds")
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
