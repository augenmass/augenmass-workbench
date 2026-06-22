//! The wallet-interaction trace: a per-session, timestamped event log that
//! captures every step of the OpenID4VP exchange (request built, the signed
//! request object fetched by the wallet, the encrypted response received, the
//! JWE decrypted, the presentation verified, plus trust, revocation, and the
//! over-ask analysis) together with the raw artifacts at each step.
//!
//! This is what turns the verifier-in-a-box into a wallet *debugger*: the same
//! events stream live to the console, render as a browser timeline, and
//! serialize at `/api/trace/:id`, so a developer can see exactly what their
//! wallet sent and where the exchange succeeded or broke.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;
use uuid::Uuid;

/// A coarse severity used for console coloring and quick scanning.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraceLevel {
    Info,
    Good,
    Warn,
    Bad,
}

/// The kind of step in the wallet interaction. The string [`TraceKind::code`] is
/// stable and appears in the console, the timeline, and the JSON.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum TraceKind {
    SessionCreated,
    RequestBuilt,
    RequestObjectFetched,
    ResponseReceived,
    ResponseDecrypted,
    Verified,
    Rejected,
    StatusChecked,
    OverAskAnalyzed,
    Note,
    Error,
}

impl TraceKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::SessionCreated => "SESSION_CREATED",
            Self::RequestBuilt => "REQUEST_BUILT",
            Self::RequestObjectFetched => "REQUEST_OBJECT_FETCHED",
            Self::ResponseReceived => "RESPONSE_RECEIVED",
            Self::ResponseDecrypted => "RESPONSE_DECRYPTED",
            Self::Verified => "VERIFIED",
            Self::Rejected => "REJECTED",
            Self::StatusChecked => "STATUS_CHECKED",
            Self::OverAskAnalyzed => "OVER_ASK_ANALYZED",
            Self::Note => "NOTE",
            Self::Error => "ERROR",
        }
    }

    fn default_level(self) -> TraceLevel {
        match self {
            Self::Verified => TraceLevel::Good,
            Self::Rejected | Self::Error => TraceLevel::Bad,
            Self::OverAskAnalyzed | Self::StatusChecked => TraceLevel::Info,
            _ => TraceLevel::Info,
        }
    }
}

/// One recorded step of a session's wallet interaction.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    /// Monotonic process-wide sequence number (stable ordering across sessions).
    pub seq: u64,
    /// Wall-clock time of the event, Unix milliseconds.
    pub at_unix_ms: i64,
    /// Local time of day, `HH:MM:SS.mmm`, for the console and timeline.
    pub at: String,
    pub kind: TraceKind,
    pub code: &'static str,
    pub level: TraceLevel,
    /// A one-line, human-legible summary.
    pub summary: String,
    /// Structured detail: the raw artifact, decoded payload, or reason at this
    /// step. Present for most events, omitted when there is nothing to attach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

/// The full ordered trace for one session.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionTrace {
    pub session: String,
    pub events: Vec<TraceEvent>,
}

/// A short summary of a session for the `/api/sessions` listing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub session: String,
    /// Number of recorded events (named distinctly from the `events` array that
    /// `/api/trace/:id` returns, so the two endpoints do not collide on a key).
    pub event_count: usize,
    pub last_code: &'static str,
    pub last_level: TraceLevel,
    pub last_at: String,
}

struct Inner {
    map: HashMap<Uuid, SessionTrace>,
    order: Vec<Uuid>,
}

/// An in-memory, session-keyed store of [`TraceEvent`]s. Cheap, bounded only by
/// process lifetime; this is a development debugger, not a durable audit log.
pub struct TraceStore {
    seq: AtomicU64,
    inner: Mutex<Inner>,
    /// Mirror each event to the console (stderr) as it happens.
    console: bool,
    /// Emit ANSI color (only when stderr is a terminal).
    color: bool,
}

impl TraceStore {
    pub fn new(console: bool) -> Self {
        Self {
            seq: AtomicU64::new(1),
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: Vec::new(),
            }),
            console,
            color: console && std::io::stderr().is_terminal(),
        }
    }

    /// Record an event for a session, with the kind's default level.
    pub async fn record(
        &self,
        session: Uuid,
        kind: TraceKind,
        summary: impl Into<String>,
        detail: Option<Value>,
    ) {
        self.record_at(session, kind, kind.default_level(), summary, detail)
            .await
    }

    /// Record an event with an explicit level (e.g. a green "trusted" or a red
    /// "revoked" outcome under the same [`TraceKind`]).
    pub async fn record_at(
        &self,
        session: Uuid,
        kind: TraceKind,
        level: TraceLevel,
        summary: impl Into<String>,
        detail: Option<Value>,
    ) {
        let now = chrono::Local::now();
        let at = now.format("%H:%M:%S%.3f").to_string();
        let at_unix_ms = now.timestamp_millis();
        let summary = summary.into();

        // Allocate the sequence number, print to the console, and append all
        // under the same lock, so seq order, console order, and stored order
        // agree even under concurrent recording.
        let mut inner = self.inner.lock().await;
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        if self.console {
            self.console_line(session, &at, kind.code(), level, &summary);
        }
        let event = TraceEvent {
            seq,
            at_unix_ms,
            at,
            kind,
            code: kind.code(),
            level,
            summary,
            detail,
        };
        let entry = inner.map.entry(session).or_insert_with(|| SessionTrace {
            session: session.to_string(),
            events: Vec::new(),
        });
        entry.events.push(event);
        if !inner.order.contains(&session) {
            inner.order.push(session);
        }
    }

    fn console_line(&self, session: Uuid, at: &str, code: &str, level: TraceLevel, summary: &str) {
        let short = short_id(session);
        if self.color {
            let (open, close) = ("\x1b[", "\x1b[0m");
            let col = match level {
                TraceLevel::Good => "32m",
                TraceLevel::Warn => "33m",
                TraceLevel::Bad => "31m",
                TraceLevel::Info => "36m",
            };
            eprintln!(
                "  {at}  {short}  {open}{col}{code:<22}{close}  {summary}",
                at = at,
                short = short,
                open = open,
                col = col,
                code = code,
                close = close,
                summary = summary,
            );
        } else {
            eprintln!("  {at}  {short}  {code:<22}  {summary}");
        }
    }

    pub async fn get(&self, session: Uuid) -> Option<SessionTrace> {
        self.inner.lock().await.map.get(&session).cloned()
    }

    /// List every session in creation order, newest last.
    pub async fn sessions(&self) -> Vec<SessionSummary> {
        let inner = self.inner.lock().await;
        inner
            .order
            .iter()
            .filter_map(|id| inner.map.get(id))
            .map(|t| {
                let last = t.events.last();
                SessionSummary {
                    session: t.session.clone(),
                    event_count: t.events.len(),
                    last_code: last.map(|e| e.code).unwrap_or(""),
                    last_level: last.map(|e| e.level).unwrap_or(TraceLevel::Info),
                    last_at: last.map(|e| e.at.clone()).unwrap_or_default(),
                }
            })
            .collect()
    }
}

/// The first 8 characters of a session UUID, for compact console and UI display.
pub fn short_id(session: Uuid) -> String {
    session.to_string().chars().take(8).collect()
}
