//! Integration test for the wallet-interaction debugger (`augenmass serve`).
//!
//! Spins the real axum router on an ephemeral port and drives the request side
//! of the OpenID4VP flow (the part that does not need a live wallet): a session
//! is created, the signed request object is served with the HAIP content-type,
//! and the trace captures each step and serializes at the JSON endpoints. The
//! response/verify path (which needs a wallet to encrypt to the run's ephemeral
//! key) is covered by the unit test in `src/serve/handlers.rs`.

use std::sync::Arc;

use augenmass_workbench::serve::handlers::router;
use augenmass_workbench::serve::state::{AppState, CertSource};
use base64::prelude::*;

async fn spawn_server() -> (String, reqwest::Client) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let public_url: url::Url = base.parse().unwrap();
    let state = Arc::new(
        AppState::new(
            public_url.clone(),
            public_url,
            CertSource::Ephemeral,
            "event_checkin",
            None,
            false,
            None,
            None,
            false,
        )
        .await
        .expect("build app state"),
    );
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        base.trim_end_matches('/').to_string(),
        reqwest::Client::new(),
    )
}

#[tokio::test]
async fn request_side_and_trace_flow() {
    let (base, client) = spawn_server().await;

    // Health.
    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert!(health.status().is_success());

    // Loading the landing page mints a fresh session.
    let landing = client.get(format!("{base}/")).send().await.unwrap();
    assert!(landing.status().is_success());
    let html = landing.text().await.unwrap();
    assert!(html.contains("Present your German PID"));
    assert!(html.contains("client_id"));

    // The session shows up in the listing.
    let sessions: serde_json::Value = client
        .get(format!("{base}/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sid = sessions["sessions"]
        .as_array()
        .unwrap()
        .last()
        .expect("at least one session")["session"]
        .as_str()
        .unwrap()
        .to_string();

    // The wallet fetches the signed request object: correct HAIP content-type.
    let req = client
        .get(format!("{base}/request/{sid}"))
        .send()
        .await
        .unwrap();
    assert!(req.status().is_success());
    assert_eq!(
        req.headers().get("content-type").unwrap(),
        "application/oauth-authz-req+jwt"
    );
    let jar = req.text().await.unwrap();
    assert_eq!(jar.split('.').count(), 3, "JAR is a compact JWS");
    let payload = decode_jws_payload(&jar);
    assert!(
        payload["verifier_info"].is_array(),
        "Android sandbox wallet expects verifier_info as an array"
    );
    assert_eq!(
        payload["verifier_info"][0]["format"], "registration_cert",
        "German sandbox wallet expects the registration certificate in verifier_info"
    );
    assert!(payload["verifier_info"][0]["data"].is_string());
    assert!(
        payload["verifier_attestations"].is_array(),
        "newer stacks consume verifier_attestations"
    );
    assert_eq!(payload["verifier_attestations"][0]["format"], "jwt");
    assert!(payload["verifier_attestations"][0]["data"].is_string());
    assert_eq!(payload["request_uri_method"], "get");
    assert_eq!(payload["state"], sid);
    assert!(payload["iat"].is_i64());
    assert!(payload["exp"].is_i64());
    assert!(payload["exp"].as_i64().unwrap() > payload["iat"].as_i64().unwrap());

    // The trace captured the request-side steps in order.
    let trace: serde_json::Value = client
        .get(format!("{base}/api/trace/{sid}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let codes: Vec<&str> = trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"SESSION_CREATED"), "codes: {codes:?}");
    assert!(codes.contains(&"REQUEST_BUILT"), "codes: {codes:?}");
    assert!(
        codes.contains(&"REQUEST_OBJECT_FETCHED"),
        "codes: {codes:?}"
    );

    // The HTML timeline renders.
    let timeline = client
        .get(format!("{base}/trace/{sid}"))
        .send()
        .await
        .unwrap();
    assert!(timeline.status().is_success());
    assert!(timeline
        .text()
        .await
        .unwrap()
        .contains("Wallet-interaction trace"));

    // An unknown session has no trace.
    let unknown = client
        .get(format!("{base}/api/trace/{}", uuid::Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
}

fn decode_jws_payload(jar: &str) -> serde_json::Value {
    let payload = jar.split('.').nth(1).expect("compact JWS payload segment");
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("payload json")
}
