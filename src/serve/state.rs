//! Verifier wiring: build the `openid4vp` [`Verifier`] for the German PID
//! profile (x509_hash client_id, `direct_post.jwt` JWE response), using either
//! the real registrar-issued leaf and key (so the `client_id` matches the one we
//! registered) or a throwaway CA for zero-config local runs.
//!
//! Adapted from the in-tree HAIP blueprint and the sibling `verifier-service`,
//! with the per-session wallet-interaction [`TraceStore`] added so the exchange
//! is observable end to end.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::prelude::*;
use openid4vp::core::authorization_request::parameters::{
    ClientIdScheme, ClientMetadata, ResponseMode, ResponseType, VerifierInfo,
};
use openid4vp::core::credential_format::{
    ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload,
};
use openid4vp::core::metadata::parameters::verifier::{EncryptedResponseEncValuesSupported, JWKs};
use openid4vp::core::metadata::parameters::wallet::{
    AuthorizationEndpoint, ClientIdPrefixesSupported, VpFormatsSupported,
};
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::core::object::UntypedObject;
use openid4vp::verifier::client::{Client, X509HashClient};
use openid4vp::verifier::request_signer::P256Signer;
use openid4vp::verifier::session::MemoryStore;
use openid4vp::verifier::Verifier;
use p256::ecdsa::SigningKey;
use p256::SecretKey;
use ssi::jwk::JWK;
use tokio::sync::Mutex;
use url::Url;
use x509_cert::{der::Decode, Certificate};

use augenmass_core::inspector::{self, PurposeBaseline};
use augenmass_core::regcert::{self, RegisteredScope};
use augenmass_core::trust::TrustAnchors;
use augenmass_core::VerifiedPid;

use crate::serve::trace::TraceStore;

/// The real registration certificate we created, bundled so the inspector has a
/// registered scope with no network.
const BUNDLED_RC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/regcert/rc-by-id.json"
));

/// Where the verifier's signing identity comes from.
pub enum CertSource {
    /// The real registrar-issued leaf (PEM) and its EC private key (PEM).
    Files { key_pem: String, leaf_pem: String },
    /// A throwaway self-signed CA and leaf, generated for a zero-config run.
    Ephemeral,
}

pub struct AppState {
    pub verifier: Verifier,
    pub wallet_metadata: WalletMetadata,
    pub public_url: Url,
    pub client_id: String,
    pub encryption_key_jwk: JWK,
    pub registered_scope: Option<RegisteredScope>,
    pub baseline: Option<PurposeBaseline>,
    /// Verification outcomes, keyed by session id, for the inspector view.
    pub(crate) results: Mutex<HashMap<uuid::Uuid, SessionResult>>,
    /// True when running on a throwaway cert (the client_id is not the real one).
    pub ephemeral: bool,
    /// PID issuer trust anchors. When present, the response path rejects issuers
    /// that do not chain to one of them.
    pub trust_anchors: Option<TrustAnchors>,
    /// When true, the response path resolves the credential's token-status-list
    /// over the network and rejects a revoked/suspended PID. Off by default so
    /// the service stays offline-friendly.
    pub live_status: bool,
    /// The trust-anchor PEM the service loaded, kept so the live-status resolver
    /// can derive the trusted status-signer key from the anchor certificate (the
    /// sandbox same-entity stand-in).
    pub anchor_pem: Option<String>,
    /// The per-session wallet-interaction trace (the debugger's event log).
    pub trace: TraceStore,
    pub(crate) status_fetcher: StatusFetcher,
}

pub(crate) enum StatusFetcher {
    Http,
    #[cfg(test)]
    Recording(std::sync::Arc<std::sync::atomic::AtomicUsize>),
}

pub(crate) enum SessionResult {
    Verified(Box<VerifiedPid>),
    Rejected(String),
}

impl StatusFetcher {
    pub(crate) async fn fetch(&self, uri: &str) -> Result<String> {
        match self {
            Self::Http => {
                let url =
                    Url::parse(uri).with_context(|| format!("parse status-list uri {uri}"))?;
                if url.scheme() != "https" {
                    anyhow::bail!(
                        "status-list uri must be https, got scheme {} ({uri})",
                        url.scheme()
                    );
                }
                // SSRF guard: the status-list uri comes from the credential, so it
                // is attacker-influenced. Resolve the host and refuse to fetch from
                // loopback, private, link-local, or otherwise non-public addresses,
                // and disable redirects so a public host cannot bounce us inward.
                let host = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("status-list uri has no host ({uri})"))?;
                let port = url.port_or_known_default().unwrap_or(443);
                let addrs: Vec<std::net::SocketAddr> = (host, port)
                    .to_socket_addrs()
                    .with_context(|| format!("resolve status-list host {host}"))?
                    .collect();
                if addrs.is_empty() {
                    anyhow::bail!("status-list host {host} did not resolve ({uri})");
                }
                if let Some(addr) = addrs.iter().find(|a| is_non_public_ip(&a.ip())) {
                    anyhow::bail!(
                        "refusing to fetch status-list from non-public address {} ({uri})",
                        addr.ip()
                    );
                }
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(10))
                    .build()
                    .context("build status-list http client")?;
                let jws = client
                    .get(url)
                    .send()
                    .await
                    .with_context(|| format!("fetch status-list token from {uri}"))?
                    .error_for_status()
                    .with_context(|| format!("status-list token request to {uri} failed"))?
                    .text()
                    .await
                    .with_context(|| format!("read status-list token body from {uri}"))?;
                Ok(jws)
            }
            #[cfg(test)]
            Self::Recording(counter) => {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/fixtures/status/status-list-CLEAR.jwt"
                ))
                .trim()
                .to_string())
            }
        }
    }
}

/// Is this address one we must not fetch from (the SSRF deny list): loopback,
/// private, link-local, unspecified, or multicast?
fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique-local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        public_url: Url,
        source: CertSource,
        purpose: &str,
        trust_anchors: Option<TrustAnchors>,
        live_status: bool,
        anchor_pem: Option<String>,
        console_trace: bool,
    ) -> Result<Self> {
        let ephemeral = matches!(source, CertSource::Ephemeral);
        let (signing_key, leaf) = match source {
            CertSource::Files { key_pem, leaf_pem } => {
                (parse_signing_key(&key_pem)?, parse_leaf(&leaf_pem)?)
            }
            CertSource::Ephemeral => {
                let host = public_url.host_str().unwrap_or("localhost");
                generate_cert(host)?
            }
        };

        let signer = Arc::new(P256Signer::new(signing_key)?);
        let client = Arc::new(X509HashClient::new(vec![leaf], signer)?);
        let client_id = client.id().0.clone();

        let session_store = Arc::new(MemoryStore::default());
        let submission_endpoint = public_url.join("response")?;
        let request_uri_base = public_url.join("request")?;

        let (encryption_key_jwk, public_jwk) = generate_encryption_key()?;
        let client_metadata = build_client_metadata(&public_jwk);

        let mut builder = Verifier::builder()
            .with_client(client)
            .with_session_store(session_store)
            .with_submission_endpoint(submission_endpoint)
            .by_reference(request_uri_base)
            .with_default_request_parameter(ResponseType::VpToken)
            .with_default_request_parameter(ResponseMode::DirectPostJwt)
            .with_default_request_parameter(client_metadata);

        // Embed our registration certificate as `verifier_info` in every emitted
        // request object: a German PID presentation requires it, and its absence
        // is the one warning ERICA raises against this verifier.
        if let Some(rc_jwt) = bundled_rc_jwt() {
            builder =
                builder.with_default_request_parameter(VerifierInfo(vec![serde_json::json!({
                    "format": "jwt",
                    "data": rc_jwt,
                })]));
        }

        let verifier = builder.build().await?;

        let wallet_metadata = create_wallet_metadata("openid4vp://".parse()?)?;

        let registered_scope = decode_bundled_scope();
        let baseline = inspector::baseline(purpose);

        Ok(Self {
            verifier,
            wallet_metadata,
            public_url,
            client_id,
            encryption_key_jwk,
            registered_scope,
            baseline,
            results: Mutex::new(HashMap::new()),
            ephemeral,
            trust_anchors,
            live_status,
            anchor_pem,
            trace: TraceStore::new(console_trace),
            status_fetcher: StatusFetcher::Http,
        })
    }
}

/// The RC JWT string from the bundled registration certificate.
fn bundled_rc_jwt() -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(BUNDLED_RC).ok()?;
    Some(v.get("jwt")?.as_str()?.to_string())
}

/// Derive the trusted status-signer JWK from the trust-anchor PEM (the sandbox
/// same-entity stand-in for live status checks).
///
/// Supports a SINGLE issuing entity only. Live status binds the status-list
/// signature to one anchor key, so a multi-certificate anchor PEM is ambiguous
/// (which issuer signs the status list?). Rather than silently pick the first
/// certificate, fail closed when the PEM carries more than one, so the
/// constraint is loud instead of latent.
pub(crate) fn status_signer_from_anchor(anchor_pem: &str) -> Result<JWK> {
    let cert_count = anchor_pem.matches("BEGIN CERTIFICATE").count();
    if cert_count > 1 {
        anyhow::bail!(
            "live status supports a single issuer trust anchor, but the anchor PEM \
             contains {cert_count} certificates; multi-issuer status signing is not \
             yet wired (set LIVE_STATUS=false or supply a single-issuer anchor)"
        );
    }
    let body: String = anchor_pem
        .lines()
        .skip_while(|l| !l.contains("BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.contains("END CERTIFICATE"))
        .map(|l| l.trim())
        .collect();
    let der = BASE64_STANDARD
        .decode(body.trim())
        .context("decode trust-anchor PEM body")?;
    augenmass_core::crypto::public_key_from_cert_der(&der)
        .context("derive status-signer key from trust anchor")
}

fn decode_bundled_scope() -> Option<RegisteredScope> {
    let v: serde_json::Value = serde_json::from_str(BUNDLED_RC).ok()?;
    let jwt = v.get("jwt")?.as_str()?;
    regcert::decode_registration_jwt(jwt).ok()
}

/// Parse an EC P-256 private key from PEM (PKCS#8 or SEC1).
fn parse_signing_key(pem: &str) -> Result<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(sk) = SecretKey::from_pkcs8_pem(pem) {
        return Ok(SigningKey::from_bytes(&sk.to_bytes())?);
    }
    let sk = SecretKey::from_sec1_pem(pem).context("parse EC private key (PKCS#8 or SEC1 PEM)")?;
    Ok(SigningKey::from_bytes(&sk.to_bytes())?)
}

fn parse_leaf(pem: &str) -> Result<Certificate> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = BASE64_STANDARD
        .decode(body.trim())
        .context("decode leaf PEM body")?;
    Certificate::from_der(&der).context("parse leaf certificate DER")
}

/// Generate a throwaway CA-signed leaf for a zero-config local run.
fn generate_cert(domain: &str) -> Result<(SigningKey, Certificate)> {
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "augenmass dev CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "augenmass dev verifier");
    leaf_params.subject_alt_names = vec![SanType::DnsName(domain.to_string().try_into()?)];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;

    let leaf = Certificate::from_der(leaf_cert.der())?;
    let signing_key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der())?;
    Ok((signing_key, leaf))
}

/// Generate an ECDH-ES encryption key pair for the `direct_post.jwt` response.
fn generate_encryption_key() -> Result<(JWK, serde_json::Map<String, serde_json::Value>)> {
    use rand::rngs::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    let mut private_jwk: JWK =
        serde_json::from_str(&secret_key.to_jwk_string()).context("private enc JWK")?;
    private_jwk.public_key_use = Some("enc".into());
    private_jwk.key_id = Some("enc-key-1".into());

    let mut public_jwk: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&public_key.to_jwk_string()).context("public enc JWK")?;
    public_jwk.insert("use".to_string(), serde_json::json!("enc"));
    public_jwk.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    public_jwk.insert("kid".to_string(), serde_json::json!("enc-key-1"));

    Ok((private_jwk, public_jwk))
}

fn build_client_metadata(
    encryption_public_jwk: &serde_json::Map<String, serde_json::Value>,
) -> ClientMetadata {
    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::Other("dc+sd-jwt".to_string()),
        ClaimFormatPayload::Other(serde_json::json!({})),
    );

    let mut inner = UntypedObject::default();
    inner.insert(VpFormatsSupported(vp_formats));
    inner.insert(JWKs {
        keys: vec![encryption_public_jwk.clone()],
    });
    // HAIP Section 5: list both A128GCM and A256GCM.
    inner.insert(EncryptedResponseEncValuesSupported(vec![
        "A128GCM".to_string(),
        "A256GCM".to_string(),
    ]));

    ClientMetadata(inner)
}

fn create_wallet_metadata(authorization_endpoint: Url) -> Result<WalletMetadata> {
    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::Other("dc+sd-jwt".to_string()),
        ClaimFormatPayload::Other(serde_json::json!({})),
    );

    let mut metadata = WalletMetadata::new(
        AuthorizationEndpoint(authorization_endpoint),
        VpFormatsSupported(vp_formats),
        None,
    );
    metadata.insert(ClientIdPrefixesSupported(vec![ClientIdScheme(
        ClientIdScheme::X509_HASH.to_string(),
    )]));
    Ok(metadata)
}
