//! Verifier wiring: build the `openid4vp` [`Verifier`] for the German PID
//! profile (x509_hash client_id, `direct_post.jwt` JWE response), using either
//! the real registrar-issued leaf and key (so the `client_id` matches the one we
//! registered) or a throwaway CA for zero-config local runs.
//!
//! Adapted from the in-tree HAIP blueprint and the sibling `verifier-service`,
//! with the per-session wallet-interaction [`TraceStore`] added so the exchange
//! is observable end to end.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
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
use url::{Host, Url};
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
pub(crate) const MAX_STATUS_LIST_BYTES: usize = 2_000_000;

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
    pub operator_url: Url,
    pub client_id: String,
    pub(crate) encryption_keys: Mutex<HashMap<uuid::Uuid, JWK>>,
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
    /// Explicit opt-in path for private replay artifacts. Never served over the
    /// trace API; used only for local end-to-end debugging.
    pub(crate) unsafe_debug_artifacts: Option<PathBuf>,
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
                    .host()
                    .ok_or_else(|| anyhow::anyhow!("status-list uri has no host ({uri})"))?;
                let port = url.port_or_known_default().unwrap_or(443);
                let (addrs, pin_domain) = match host {
                    Host::Domain(domain) => (resolve_status_addrs(domain, port)?, Some(domain)),
                    Host::Ipv4(ip) => (vec![SocketAddr::new(IpAddr::V4(ip), port)], None),
                    Host::Ipv6(ip) => (vec![SocketAddr::new(IpAddr::V6(ip), port)], None),
                };
                let vetted = vet_resolved_status_addrs(uri, addrs)?;
                let mut builder = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(10));
                if let Some(domain) = pin_domain {
                    builder = builder.resolve_to_addrs(domain, &vetted);
                }
                let client = builder.build().context("build status-list http client")?;
                let response = client
                    .get(url)
                    .send()
                    .await
                    .with_context(|| format!("fetch status-list token from {uri}"))?
                    .error_for_status()
                    .with_context(|| format!("status-list token request to {uri} failed"))?;
                let jws = read_status_body_limited(response)
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

pub(crate) fn resolve_status_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve status-list host {host}"))
        .map(|iter| iter.collect())
}

pub(crate) fn vet_resolved_status_addrs(
    uri: &str,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>> {
    if addrs.is_empty() {
        anyhow::bail!("status-list host did not resolve ({uri})");
    }
    if let Some(addr) = addrs.iter().find(|a| is_non_public_ip(&a.ip())) {
        anyhow::bail!(
            "refusing to fetch status-list from non-public address {} ({uri})",
            addr.ip()
        );
    }
    Ok(addrs)
}

async fn read_status_body_limited(mut response: reqwest::Response) -> Result<String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_status_chunk(&mut bytes, &chunk)?;
    }
    String::from_utf8(bytes).context("status-list token body is not UTF-8")
}

pub(crate) fn append_status_chunk(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    if buffer.len().saturating_add(chunk.len()) > MAX_STATUS_LIST_BYTES {
        anyhow::bail!(
            "status-list token body is too large: more than {MAX_STATUS_LIST_BYTES} bytes"
        );
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

/// Is this address one we must not fetch from (the SSRF deny list): loopback,
/// private, link-local, unspecified, or multicast?
pub(crate) fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public_ip(&IpAddr::V4(v4));
            }
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
        operator_url: Url,
        source: CertSource,
        purpose: &str,
        trust_anchors: Option<TrustAnchors>,
        live_status: bool,
        anchor_pem: Option<String>,
        unsafe_debug_artifacts: Option<PathBuf>,
        console_trace: bool,
    ) -> Result<Self> {
        if let Some(root) = unsafe_debug_artifacts.as_ref() {
            crate::serve::artifacts::prepare_root(root)?;
        }
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

        let mut builder = Verifier::builder()
            .with_client(client)
            .with_session_store(session_store)
            .with_submission_endpoint(submission_endpoint)
            .by_reference(request_uri_base)
            .with_default_request_parameter(ResponseType::VpToken)
            .with_default_request_parameter(ResponseMode::DirectPostJwt);

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
            operator_url,
            client_id,
            encryption_keys: Mutex::new(HashMap::new()),
            registered_scope,
            baseline,
            results: Mutex::new(HashMap::new()),
            ephemeral,
            trust_anchors,
            live_status,
            anchor_pem,
            trace: TraceStore::new(console_trace),
            status_fetcher: StatusFetcher::Http,
            unsafe_debug_artifacts,
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
pub(crate) fn generate_encryption_key(
    kid: &str,
) -> Result<(JWK, serde_json::Map<String, serde_json::Value>)> {
    use rand::rngs::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    let mut private_jwk: JWK =
        serde_json::from_str(&secret_key.to_jwk_string()).context("private enc JWK")?;
    private_jwk.public_key_use = Some("enc".into());
    private_jwk.key_id = Some(kid.into());

    let mut public_jwk: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&public_key.to_jwk_string()).context("public enc JWK")?;
    public_jwk.insert("use".to_string(), serde_json::json!("enc"));
    public_jwk.insert("alg".to_string(), serde_json::json!("ECDH-ES"));
    public_jwk.insert("kid".to_string(), serde_json::json!(kid));

    Ok((private_jwk, public_jwk))
}

pub(crate) fn build_client_metadata(
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;

    #[test]
    fn deny_list_covers_mapped_ipv6_and_cgnat() {
        for ip in [
            IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("::ffff:169.254.169.254".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        ] {
            assert!(is_non_public_ip(&ip), "{ip} should be denied");
        }
        assert!(!is_non_public_ip(&IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34
        ))));
        assert!(!is_non_public_ip(&IpAddr::V6(
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<Ipv6Addr>()
                .unwrap()
        )));
    }

    #[test]
    fn pure_status_addr_vetter_returns_only_vetted_public_addrs() {
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let vetted = vet_resolved_status_addrs("https://example.com/status", vec![public])
            .expect("public address passes");
        assert_eq!(vetted, vec![public]);

        for ip in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        ] {
            let err = vet_resolved_status_addrs(
                "https://example.com/status",
                vec![SocketAddr::new(ip, 443)],
            )
            .expect_err("non-public address rejected");
            assert!(
                err.to_string().contains("non-public"),
                "unexpected error: {err}"
            );
        }
    }

    #[tokio::test]
    async fn http_status_fetcher_rejects_literal_non_public_hosts_before_network() {
        for uri in [
            "https://127.0.0.1/",
            "https://169.254.169.254/",
            "https://[::ffff:127.0.0.1]/",
        ] {
            let err = StatusFetcher::Http
                .fetch(uri)
                .await
                .expect_err("literal non-public host rejected");
            assert!(
                err.to_string().contains("non-public"),
                "unexpected error for {uri}: {err}"
            );
        }
    }

    #[test]
    fn status_body_cap_rejects_above_limit() {
        let mut buffer = Vec::new();
        append_status_chunk(&mut buffer, &vec![b'a'; MAX_STATUS_LIST_BYTES])
            .expect("exact limit allowed");
        assert_eq!(buffer.len(), MAX_STATUS_LIST_BYTES);
        let err = append_status_chunk(&mut buffer, b"x").expect_err("above limit rejected");
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );
    }
}
