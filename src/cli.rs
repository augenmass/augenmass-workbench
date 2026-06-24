//! The `augenmass` command tree. Groups: inspect/decode (understand any
//! artifact), check/audit/baselines (over-ask proportionality), verify/x509-hash
//! (cryptographic checks), generate (produce artifacts), doctor (diagnose JAR
//! gotchas), register/list/clone/cache (guard-railed registrar writes and
//! sandbox mirrors).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::cache_server::{
    DEFAULT_CACHE_DB, DEFAULT_CACHE_HOST, DEFAULT_CACHE_MAX_ENTRIES, DEFAULT_CACHE_PORT,
    DEFAULT_CACHE_TIMEOUT_SECS, DEFAULT_CACHE_TTL_SECS,
};
use crate::commands::decode::Decoded;
use crate::commands::{
    audit, baselines, cache, check, clone, decode, doctor, evidence, generate, inspect, register,
    validate, verify, x509hash,
};
use crate::config::{DEFAULT_API_BASE, DEFAULT_CACHE_API_BASE, DEFAULT_HTTP_TIMEOUT_SECS};
use crate::generator::GenerateOptions;
use crate::http_target::Target;
use crate::mdoc;
use crate::output::{emit, OutputFormat};
use crate::serve::{self, ServeArgs};
use crate::{DEFAULT_PRIVACY_POLICY, DEFAULT_PURPOSE, DEFAULT_RP_ID, DEFAULT_SUPPORT_URI};

#[derive(Parser)]
#[command(
    name = "augenmass",
    version,
    about = "Agent-ready Rust tooling for EUDI Wallet artifacts, over-ask guardrails, verifier debugging, and evidence replay.",
    long_about = "Augenmass Workbench is a developer and auditor toolkit for the EUDI \
Wallet ecosystem. It decodes and inspects every common artifact (SD-JWT VC, \
mdoc, registration certificate, authorization request/JAR, credential offer, \
status list, and DCQL), audits requests for over-asking against curated purpose \
baselines and the legal basis, verifies presentations cryptographically, writes \
registrations under guardrails, live-debugs wallet interactions, and replays \
local evidence bundles. Offline commands stay deterministic; live features are \
explicit targets such as sandbox, cached-sandbox, clone, cache, and serve."
)]
struct Cli {
    /// Emit machine-readable JSON instead of a text rendering on commands that render structured output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Auto-detect an artifact and decode it ("what is this?").
    Inspect {
        /// A file path, an inline value, or `-` for stdin.
        input: String,
    },
    /// Decode a specific artifact type (no signature verification).
    Decode {
        #[command(subcommand)]
        what: DecodeCmd,
    },
    /// Gate a registrar registration body before a write (over-ask + format).
    Check {
        /// Registration body: a file path, inline JSON, or `-` for stdin.
        body: String,
    },
    /// Audit an OpenID4VP request for over-asking against a purpose baseline.
    Audit(AuditCommand),
    /// List the curated purpose baselines and legal basis, or show one.
    Baselines {
        /// A baseline id to show in detail (omit to list all).
        id: Option<String>,
    },
    /// Cryptographically verify a presentation, trust, or revocation status.
    Verify {
        #[command(subcommand)]
        what: VerifyCmd,
    },
    /// Compute (and optionally check) the x509_hash client_id binding.
    #[command(name = "x509-hash")]
    X509Hash {
        /// A JAR (its x5c leaf), a PEM certificate, or base64 DER; file/inline/`-`.
        input: String,
        /// A claimed client_id to compare against the computed binding.
        #[arg(long)]
        client_id: Option<String>,
    },
    /// Produce a proportionate registration body or a DCQL query.
    Generate {
        #[command(subcommand)]
        what: GenerateCmd,
    },
    /// Diagnose verifier signed-request / JAR gotchas (x5c, client_id).
    Doctor {
        /// Request JSON or a compact JWT: a file path, inline value, or `-`.
        request: String,
    },
    /// Validate an artifact's structure and cross-references (CI-gateable).
    Validate {
        #[command(subcommand)]
        what: ValidateCmd,
    },
    /// Export, verify, and replay local evidence captured by serve.
    Evidence {
        #[command(subcommand)]
        what: EvidenceCmd,
    },
    /// Write a registration under guardrails (dry-run by default).
    Register(RegisterCommand),
    /// Read registrations back for one relying party, decoded.
    List(ListCommand),
    /// Run the registrar-compatible local clone store.
    Clone {
        #[command(subcommand)]
        command: CloneCmd,
    },
    /// Run a server-side read-through cache for public sandbox reads.
    Cache {
        #[command(subcommand)]
        command: CacheCmd,
    },
    /// Serve a live wallet-interaction debugger (verifier-in-a-box + trace).
    Serve(ServeArgs),
}

#[derive(Subcommand)]
enum DecodeCmd {
    /// Decode a JWT/JWS (header + payload).
    Jwt { input: String },
    /// Decode an SD-JWT VC (issuer claims, disclosures, KB-JWT, resolved view).
    #[command(name = "sd-jwt")]
    SdJwt { input: String },
    /// Decode a WRPRC registration certificate (payload-only).
    Regcert { input: String },
    /// Decode an OpenID4VP authorization request / JAR.
    Request { input: String },
    /// Decode an OpenID4VCI credential offer (URI or JSON).
    Offer { input: String },
    /// Decode a token status list token.
    #[command(name = "status-list")]
    StatusList { input: String },
    /// Decode an ISO 18013-5 mdoc (DeviceResponse / IssuerSigned / MSO; CBOR, hex, or base64).
    Mdoc { input: String },
}

#[derive(Subcommand)]
enum ValidateCmd {
    /// Validate a DCQL query (unique ids, credential_sets references, per-format claim paths).
    Dcql {
        /// DCQL JSON (bare or wrapped under `dcql_query`): file path, inline, or `-`.
        input: String,
    },
}

#[derive(Subcommand)]
enum VerifyCmd {
    /// Verify an SD-JWT VC presentation (issuer sig, KB-JWT, nonce/aud, vct).
    Presentation(VerifyPresentationArgs),
    /// Check whether a presentation's issuer chains to a trust anchor.
    Trust {
        /// Presentation: file path, inline value, or `-`.
        input: String,
        /// Trust anchor PEM (one or more certificates): file path or inline.
        #[arg(long)]
        anchor: String,
        /// Verification clock (Unix seconds); omit to use the system clock.
        #[arg(long)]
        now: Option<i64>,
    },
    /// Check a presentation's revocation status against a status-list token.
    Status {
        /// Presentation: file path, inline value, or `-`.
        input: String,
        /// The status-list token (statuslist+jwt): file path or inline.
        #[arg(long)]
        token: String,
        /// The status-signer public key (SPKI or certificate PEM).
        #[arg(long)]
        key: String,
    },
    /// Verify a status-list token and read a specific index.
    #[command(name = "status-list")]
    StatusList {
        /// The status-list token (statuslist+jwt): file path or inline.
        #[arg(long)]
        token: String,
        /// The status-signer public key (SPKI or certificate PEM).
        #[arg(long)]
        key: String,
        /// The status index to read.
        #[arg(long)]
        index: usize,
    },
}

#[derive(Subcommand)]
enum EvidenceCmd {
    /// Export one serve unsafe-debug session directory into a portable bundle.
    Export {
        /// A session directory containing debug-manifest.json.
        session_dir: PathBuf,
        /// Output bundle path.
        #[arg(long)]
        out: PathBuf,
        /// Optional P-256 PKCS#8 private key PEM for signing the bundle.
        #[arg(long)]
        signing_key: Option<PathBuf>,
    },
    /// Verify bundle hashes, replay determinism, and optional signature.
    Verify {
        /// Evidence bundle JSON.
        bundle: PathBuf,
        /// Optional P-256 public key PEM for signature verification.
        #[arg(long)]
        verify_key: Option<PathBuf>,
    },
    /// Render the bundle's projector-safe replay timeline.
    Replay {
        /// Evidence bundle JSON.
        bundle: PathBuf,
        /// Optional P-256 public key PEM for signature verification.
        #[arg(long)]
        verify_key: Option<PathBuf>,
    },
}

#[derive(Args)]
struct VerifyPresentationArgs {
    /// Presentation (SD-JWT VC ~ ... ~ KB-JWT): file path, inline, or `-`.
    input: String,
    /// The Authorization Request nonce the KB-JWT must echo.
    #[arg(long)]
    nonce: String,
    /// The audience the KB-JWT must bind to (the verifier client_id).
    #[arg(long)]
    aud: String,
    /// The expected credential vct (defaults to the German PID).
    #[arg(long)]
    vct: Option<String>,
    /// KB-JWT freshness window in seconds.
    #[arg(long, default_value_t = 300)]
    max_age: i64,
    /// Verification clock (Unix seconds); omit to use the system clock.
    #[arg(long)]
    now: Option<i64>,
    /// Trust anchor PEM to anchor the issuer (optional; otherwise the leaf key).
    #[arg(long)]
    trust_anchor: Option<String>,
    /// A status-list token to check revocation against (needs --status-key).
    #[arg(long)]
    status_token: Option<String>,
    /// The status-signer public key PEM (needs --status-token).
    #[arg(long)]
    status_key: Option<String>,
}

#[derive(Subcommand)]
enum GenerateCmd {
    /// A registrar registration body (the proportionate age check by default).
    Regbody(GenerateRegbodyArgs),
    /// A DCQL query built from claim paths.
    Dcql {
        /// A claim path (dotted or slashed), repeatable. E.g. --claim age_equal_or_over.18
        #[arg(long = "claim", required = true)]
        claims: Vec<String>,
    },
}

#[derive(Args)]
struct GenerateRegbodyArgs {
    #[arg(long, value_enum, default_value_t = UseCase::AgeCheck)]
    use_case: UseCase,
    #[arg(long)]
    over_broad: bool,
    #[arg(long, default_value = DEFAULT_RP_ID)]
    rp: String,
    #[arg(long, default_value = DEFAULT_SUPPORT_URI)]
    support_uri: String,
    #[arg(long, default_value = DEFAULT_PRIVACY_POLICY)]
    privacy_policy: String,
    #[arg(long, default_value = DEFAULT_PURPOSE)]
    purpose: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum UseCase {
    AgeCheck,
}

#[derive(Args)]
struct AuditCommand {
    /// "minimal", "overask", or a path to a DCQL JSON file.
    #[arg(long, default_value = "minimal")]
    request: String,
    /// Purpose baseline id (age_gate_18, event_checkin, car_rental, bank_kyc).
    #[arg(long, default_value = "event_checkin")]
    purpose: String,
    /// Path to a registration certificate (compact JWT, entity JSON, or array).
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Override the expected vct (defaults to the German PID).
    #[arg(long)]
    vct: Option<String>,
}

#[derive(Args)]
struct RegisterCommand {
    /// Registration body: a file path, inline JSON, or `-` for stdin.
    body: String,
    #[arg(long, value_enum, default_value_t = Target::Clone)]
    target: Target,
    /// Confirm a write. Without this flag the command is a dry-run.
    #[arg(long)]
    yes: bool,
    /// Write past an over-ask warning. Requires --yes.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ListCommand {
    #[arg(long, value_enum, default_value_t = Target::Clone)]
    target: Target,
    #[arg(long, default_value = DEFAULT_RP_ID)]
    rp: String,
}

#[derive(Subcommand)]
enum CloneCmd {
    /// Serve the registrar-compatible local demo target.
    Serve {
        #[arg(long, default_value = "./augenmass-clone.sqlite")]
        db: String,
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum CacheCmd {
    /// Serve a cached-sandbox target for public sandbox GET routes.
    Serve {
        /// SQLite database path (env AUGENMASS_CACHE_DB).
        #[arg(long, env = "AUGENMASS_CACHE_DB", default_value = DEFAULT_CACHE_DB)]
        db: String,
        /// Bind host (env AUGENMASS_CACHE_HOST). Use 0.0.0.0 for deploys.
        #[arg(long, env = "AUGENMASS_CACHE_HOST", default_value = DEFAULT_CACHE_HOST)]
        host: String,
        /// Listen port. Env AUGENMASS_CACHE_PORT wins, then PORT, then 8081.
        #[arg(long, env = "AUGENMASS_CACHE_PORT")]
        port: Option<u16>,
        /// Upstream sandbox API base (env AUGENMASS_CACHE_UPSTREAM).
        #[arg(long, env = "AUGENMASS_CACHE_UPSTREAM", default_value_t = DEFAULT_API_BASE.to_string())]
        upstream: String,
        /// Freshness window for cached responses (env AUGENMASS_CACHE_TTL_SECS).
        #[arg(long, env = "AUGENMASS_CACHE_TTL_SECS", default_value_t = DEFAULT_CACHE_TTL_SECS)]
        ttl_secs: u64,
        /// Upstream request timeout in seconds (env AUGENMASS_CACHE_TIMEOUT_SECS).
        #[arg(long, env = "AUGENMASS_CACHE_TIMEOUT_SECS", default_value_t = DEFAULT_CACHE_TIMEOUT_SECS)]
        timeout_secs: u64,
        /// Maximum stored cache entries before oldest rows are evicted (env AUGENMASS_CACHE_MAX_ENTRIES).
        #[arg(long, env = "AUGENMASS_CACHE_MAX_ENTRIES", default_value_t = DEFAULT_CACHE_MAX_ENTRIES)]
        max_entries: usize,
        /// Protect /api/cache/status and /api/cache/refresh (env AUGENMASS_CACHE_ADMIN_TOKEN).
        #[arg(long, env = "AUGENMASS_CACHE_ADMIN_TOKEN")]
        admin_token: Option<String>,
        /// Restrict registration-certificate read-through to these RP ids. Repeatable, or comma-separated via env AUGENMASS_CACHE_ALLOWED_RPS.
        #[arg(
            long = "allowed-rp",
            env = "AUGENMASS_CACHE_ALLOWED_RPS",
            value_delimiter = ',',
            default_value = DEFAULT_RP_ID
        )]
        allowed_rps: Vec<String>,
        /// Explicitly allow registration-certificate read-through for any syntactically valid RP. Unsafe for shared deployments.
        #[arg(long, env = "AUGENMASS_CACHE_ALLOW_ANY_RP", default_value_t = false)]
        allow_any_rp: bool,
        /// Permit non-HTTPS or private cache upstreams on public binds. Unsafe; use only in isolated development.
        #[arg(long, env = "AUGENMASS_CACHE_UNSAFE_UPSTREAM", default_value_t = false)]
        unsafe_upstream: bool,
    },
    /// Force-refresh the cache server's demo-critical public sandbox routes.
    Warm {
        /// Cache API base (env AUGENMASS_CACHE_API_BASE).
        #[arg(long, env = "AUGENMASS_CACHE_API_BASE", default_value = DEFAULT_CACHE_API_BASE)]
        api_base: String,
        /// Admin token for protected refresh endpoints (env AUGENMASS_CACHE_ADMIN_TOKEN).
        #[arg(long, env = "AUGENMASS_CACHE_ADMIN_TOKEN")]
        admin_token: Option<String>,
        /// Relying party id whose registration list should be warmed.
        #[arg(long, default_value = DEFAULT_RP_ID)]
        rp: String,
        /// HTTP request timeout in seconds (env AUGENMASS_HTTP_TIMEOUT_SECS).
        #[arg(long, env = "AUGENMASS_HTTP_TIMEOUT_SECS", default_value_t = DEFAULT_HTTP_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
    /// Show cache entries and deployment settings from a cache server.
    Status {
        /// Cache API base (env AUGENMASS_CACHE_API_BASE).
        #[arg(long, env = "AUGENMASS_CACHE_API_BASE", default_value = DEFAULT_CACHE_API_BASE)]
        api_base: String,
        /// Admin token for protected status endpoint (env AUGENMASS_CACHE_ADMIN_TOKEN).
        #[arg(long, env = "AUGENMASS_CACHE_ADMIN_TOKEN")]
        admin_token: Option<String>,
        /// HTTP request timeout in seconds (env AUGENMASS_HTTP_TIMEOUT_SECS).
        #[arg(long, env = "AUGENMASS_HTTP_TIMEOUT_SECS", default_value_t = DEFAULT_HTTP_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let fmt = OutputFormat::from_json_flag(cli.json);

    match cli.command {
        Command::Inspect { input } => {
            inspect::run(&read_input(&input)?, fmt)?;
        }
        Command::Decode { what } => run_decode(what, fmt)?,
        Command::Check { body } => {
            let block = check::run(&body, &read_input(&body)?, fmt)?;
            exit_if(block);
        }
        Command::Audit(cmd) => {
            let ok = audit::run(
                audit::AuditArgs {
                    request: cmd.request,
                    purpose: cmd.purpose,
                    cert: cmd.cert,
                    vct: cmd.vct,
                },
                fmt,
            )?;
            exit_if(!ok);
        }
        Command::Baselines { id } => baselines::run(id.as_deref(), fmt)?,
        Command::Verify { what } => {
            let ok = run_verify(what, fmt)?;
            exit_if(!ok);
        }
        Command::X509Hash { input, client_id } => {
            let ok = x509hash::run(&read_input(&input)?, client_id.as_deref(), fmt)?;
            exit_if(!ok);
        }
        Command::Generate { what } => match what {
            GenerateCmd::Regbody(args) => generate::regbody(&GenerateOptions {
                over_broad: args.over_broad,
                rp_id: args.rp,
                support_uri: args.support_uri,
                privacy_policy: args.privacy_policy,
                purpose: args.purpose,
            })?,
            GenerateCmd::Dcql { claims } => generate::dcql_query(&claims)?,
        },
        Command::Doctor { request } => {
            let found = doctor::run(&read_input(&request)?, fmt)?;
            exit_if(found);
        }
        Command::Validate { what } => {
            let bad = match what {
                ValidateCmd::Dcql { input } => validate::dcql(&read_input(&input)?, fmt)?,
            };
            exit_if(bad);
        }
        Command::Evidence { what } => {
            let ok = run_evidence(what, fmt)?;
            exit_if(!ok);
        }
        Command::Register(cmd) => {
            let content = read_input(&cmd.body)?;
            register::register(
                &cmd.body,
                &content,
                register::RegisterArgs {
                    target: cmd.target,
                    yes: cmd.yes,
                    force: cmd.force,
                },
            )
            .await?;
        }
        Command::List(cmd) => register::list(cmd.target, &cmd.rp).await?,
        Command::Clone { command } => match command {
            CloneCmd::Serve { db, port } => clone::serve(&db, port).await?,
        },
        Command::Cache { command } => match command {
            CacheCmd::Serve {
                db,
                host,
                port,
                upstream,
                ttl_secs,
                timeout_secs,
                max_entries,
                admin_token,
                allowed_rps,
                allow_any_rp,
                unsafe_upstream,
            } => {
                cache::serve(cache::ServeArgs {
                    db,
                    host,
                    port: resolve_cache_port(port),
                    upstream,
                    ttl_secs,
                    timeout_secs,
                    max_entries,
                    admin_token,
                    allowed_rps,
                    allow_any_rp,
                    unsafe_upstream,
                })
                .await?
            }
            CacheCmd::Warm {
                api_base,
                admin_token,
                rp,
                timeout_secs,
            } => {
                cache::warm(
                    cache::WarmArgs {
                        api_base,
                        admin_token,
                        rp,
                        timeout_secs,
                    },
                    fmt,
                )
                .await?
            }
            CacheCmd::Status {
                api_base,
                admin_token,
                timeout_secs,
            } => {
                cache::status(
                    cache::StatusArgs {
                        api_base,
                        admin_token,
                        timeout_secs,
                    },
                    fmt,
                )
                .await?
            }
        },
        Command::Serve(args) => serve::run(args).await?,
    }
    Ok(())
}

fn resolve_cache_port(port: Option<u16>) -> u16 {
    port.or_else(|| {
        std::env::var("PORT")
            .ok()
            .and_then(|port| port.parse::<u16>().ok())
    })
    .unwrap_or(DEFAULT_CACHE_PORT)
}

fn run_evidence(what: EvidenceCmd, fmt: OutputFormat) -> Result<bool> {
    match what {
        EvidenceCmd::Export {
            session_dir,
            out,
            signing_key,
        } => {
            evidence::export(
                evidence::ExportArgs {
                    session_dir,
                    out,
                    signing_key,
                },
                fmt,
            )?;
            Ok(true)
        }
        EvidenceCmd::Verify { bundle, verify_key } => {
            evidence::verify(evidence::VerifyArgs { bundle, verify_key }, fmt)
        }
        EvidenceCmd::Replay { bundle, verify_key } => {
            evidence::replay(evidence::VerifyArgs { bundle, verify_key }, fmt)
        }
    }
}

fn run_decode(what: DecodeCmd, fmt: OutputFormat) -> Result<()> {
    let decoded: Decoded = match what {
        DecodeCmd::Jwt { input } => decode::decode_jwt(&read_input(&input)?)?,
        DecodeCmd::SdJwt { input } => decode::decode_sd_jwt(&read_input(&input)?)?,
        DecodeCmd::Regcert { input } => decode::decode_regcert(&read_input(&input)?)?,
        DecodeCmd::Request { input } => decode::decode_request(&read_input(&input)?)?,
        DecodeCmd::Offer { input } => decode::decode_offer(&read_input(&input)?)?,
        DecodeCmd::StatusList { input } => decode::decode_status_list(&read_input(&input)?)?,
        DecodeCmd::Mdoc { input } => mdoc::decode_mdoc(&read_input_bytes(&input)?)?,
    };
    emit(fmt, &decoded.json, &decoded.text)?;
    Ok(())
}

fn run_verify(what: VerifyCmd, fmt: OutputFormat) -> Result<bool> {
    match what {
        VerifyCmd::Presentation(args) => {
            let trust_anchor_pem = match &args.trust_anchor {
                Some(v) => Some(read_input(v)?),
                None => None,
            };
            let status_token = match &args.status_token {
                Some(v) => Some(read_input(v)?),
                None => None,
            };
            let status_key_pem = match &args.status_key {
                Some(v) => Some(read_input(v)?),
                None => None,
            };
            verify::verify_presentation(
                verify::PresentationArgs {
                    presentation: read_input(&args.input)?,
                    nonce: args.nonce,
                    aud: args.aud,
                    vct: args.vct,
                    max_age: args.max_age,
                    now: args.now,
                    trust_anchor_pem,
                    status_token,
                    status_key_pem,
                },
                fmt,
            )
        }
        VerifyCmd::Trust { input, anchor, now } => {
            verify::verify_trust(&read_input(&input)?, &read_input(&anchor)?, now, fmt)
        }
        VerifyCmd::Status { input, token, key } => verify::verify_status(
            &read_input(&input)?,
            &read_input(&token)?,
            &read_input(&key)?,
            fmt,
        ),
        VerifyCmd::StatusList { token, key, index } => {
            verify::verify_status_list(&read_input(&token)?, &read_input(&key)?, index, fmt)
        }
    }
}

fn exit_if(bad: bool) {
    if bad {
        std::process::exit(1);
    }
}

/// Resolve an input argument: `-` reads stdin, an existing file path is read,
/// anything else is treated as the literal value. This is what lets every
/// command accept a file, an inline token, or a pipe.
fn read_input(arg: &str) -> Result<String> {
    if arg == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read stdin")?;
        return Ok(buf);
    }
    let path = Path::new(arg);
    if path.is_file() {
        return std::fs::read_to_string(path).with_context(|| format!("read {arg}"));
    }
    Ok(arg.to_string())
}

/// Resolve an input argument as raw bytes: `-` reads stdin, an existing file path
/// is read as bytes (so binary CBOR works), anything else is the literal value's
/// bytes. Used by decoders that accept binary input (mdoc).
fn read_input_bytes(arg: &str) -> Result<Vec<u8>> {
    if arg == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("read stdin")?;
        return Ok(buf);
    }
    let path = Path::new(arg);
    if path.is_file() {
        return std::fs::read(path).with_context(|| format!("read {arg}"));
    }
    Ok(arg.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_case_value_is_stable() {
        assert_eq!(
            UseCase::AgeCheck.to_possible_value().unwrap().get_name(),
            "age-check"
        );
    }

    #[test]
    fn verify_cli_parses() {
        // Smoke: the command tree builds without conflicting args.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
