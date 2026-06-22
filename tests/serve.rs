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

async fn spawn_server() -> (String, reqwest::Client) {
    let state = Arc::new(
        AppState::new(
            "http://127.0.0.1:0/".parse().unwrap(),
            CertSource::Ephemeral,
            "event_checkin",
            None,
            false,
            None,
            false,
        )
        .await
        .expect("build app state"),
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), reqwest::Client::new())
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
