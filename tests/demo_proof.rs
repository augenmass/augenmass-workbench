//! Presentation-proof smoke tests.
//!
//! These tests pin the short, agent-first demo path: identify an artifact,
//! prove the over-ask guard, show a wallet/JAR diagnostic, and prove the
//! offline crypto checks. They intentionally use committed fixtures only, so
//! the presentation can be rehearsed without the sandbox or secrets.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

const NONCE: &str = "b4ba2623-76a2-486b-a1f6-f1656025d07b";
const AUD: &str = "https://self-issued.me/v2";
const NOW: &str = "1780435200";
const GOOD_CLIENT_ID: &str = "x509_hash:VE3qp3vLVkU8JyVmXkjL7CSDVxVoTFdTv5fAEwmjKOI";

fn bin() -> Command {
    Command::cargo_bin("augenmass").expect("binary builds")
}

#[test]
fn agent_front_door_identifies_real_eudi_artifacts() {
    bin()
        .args(["inspect", "fixtures/presentations/erica-vp-VALID.sdjwt"])
        .assert()
        .success()
        .stderr(contains("SD-JWT VC presentation"))
        .stdout(contains("urn:eudi:pid:de:1"))
        .stdout(contains("given_name"));

    bin()
        .args(["inspect", "fixtures/requests/eudiplo-request.jwt"])
        .assert()
        .success()
        .stdout(contains("x509_hash"))
        .stdout(contains("direct_post.jwt"));

    bin()
        .args(["inspect", "fixtures/mdoc/issuer-signed.hex"])
        .assert()
        .success()
        .stderr(contains("ISO 18013-5 mdoc"))
        .stdout(contains("family_name"));
}

#[test]
fn overask_guardrail_demo_is_stable_and_cites_the_basis() {
    bin()
        .args(["check", "examples/min.json"])
        .assert()
        .success()
        .stdout(contains("OK: no over-ask"));

    bin()
        .args(["check", "examples/over.json"])
        .assert()
        .failure()
        .stdout(contains("OVER-ASK"))
        .stdout(contains("Suggested minimal request"))
        .stdout(contains("eIDAS Regulation (EU) 2024/1183"))
        .stdout(contains("GDPR (EU) 2016/679"));

    bin()
        .args(["audit", "--request", "overask", "--purpose", "age_gate_18"])
        .assert()
        .failure()
        .stdout(contains("OVER-ASK"))
        .stdout(contains("age_equal_or_over.18"));
}

#[test]
fn developer_repair_story_catches_jar_and_registration_mistakes() {
    bin()
        .args(["doctor", "examples/bad-request.json"])
        .assert()
        .failure()
        .stdout(contains("DOCTOR-X5C-STRING"))
        .stdout(contains("DOCTOR-CLIENT-ID-X509HASH"))
        .stdout(contains("Compute it with `augenmass x509-hash`"));

    bin()
        .args([
            "x509-hash",
            "fixtures/certs/access-leaf.pem",
            "--client-id",
            GOOD_CLIENT_ID,
        ])
        .assert()
        .success()
        .stdout(contains("MATCH"));

    bin()
        .args(["check", "examples/bad-path.json"])
        .assert()
        .failure()
        .stdout(contains("CHECK-PATH-STRING"));
}

#[test]
fn offline_crypto_story_accepts_good_and_rejects_hostile_fixtures() {
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

    bin()
        .args([
            "verify",
            "status-list",
            "--token",
            "fixtures/status/status-list-REVOKED.jwt",
            "--key",
            "fixtures/status/status-list-verify-key.pub.pem",
            "--index",
            "42",
        ])
        .assert()
        .failure()
        .stdout(contains("REVOKED"));
}

#[test]
fn demo_targets_are_safe_without_live_credentials() {
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

    bin()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(contains("unsafe-debug-artifacts"))
        .stdout(contains("live-status"));

    bin()
        .args(["cache", "serve", "--help"])
        .assert()
        .success()
        .stdout(contains("--upstream"))
        .stdout(contains("--ttl-secs"));
}
