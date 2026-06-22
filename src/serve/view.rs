//! Server-rendered HTML: the landing page (present + inspect + trace), the
//! over-ask inspector view, and the wallet-interaction trace timeline.
//!
//! The report rendering mirrors the over-ask CLI's text output on purpose. The
//! trace timeline is the browser face of the debugger: every recorded step with
//! its raw artifact, refreshing live while a wallet interacts.

use uuid::Uuid;

use augenmass_core::inspector::{ClaimStatus, OverAskReport};

use crate::serve::state::AppState;
use crate::serve::trace::{short_id, SessionTrace, TraceLevel};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn status_class(s: ClaimStatus) -> &'static str {
    match s {
        ClaimStatus::MinimalForPurpose => "ok",
        ClaimStatus::BeyondPurpose => "warn",
        ClaimStatus::BeyondRegistration => "over",
        ClaimStatus::NotEvaluated => "",
    }
}

fn status_word(s: ClaimStatus) -> &'static str {
    match s {
        ClaimStatus::MinimalForPurpose => "minimal",
        ClaimStatus::BeyondPurpose => "beyond purpose",
        ClaimStatus::BeyondRegistration => "beyond registration",
        ClaimStatus::NotEvaluated => "not evaluated",
    }
}

fn level_class(l: TraceLevel) -> &'static str {
    match l {
        TraceLevel::Good => "ok",
        TraceLevel::Warn => "warn",
        TraceLevel::Bad => "over",
        TraceLevel::Info => "info",
    }
}

fn qr_svg(url: &str) -> String {
    use qrcode::render::svg;
    use qrcode::QrCode;
    match QrCode::new(url.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

fn page(title: &str, head_extra: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         {head_extra}<title>{title}</title><style>{CSS}</style></head><body>{body}</body></html>"
    )
}

pub fn landing_page(state: &AppState, session_id: &Uuid, auth_url: &str) -> String {
    let qr = qr_svg(auth_url);
    let inspect = format!("{}inspect/{}", state.public_url, session_id);
    let trace = format!("{}trace/{}", state.public_url, session_id);
    let request_url = format!("{}request/{}", state.public_url, session_id);
    let mode = if state.ephemeral {
        "<p class=\"banner over\">Development mode: a throwaway certificate. The client_id below is not the registered sandbox identity. Set RP_KEY_PATH and RP_LEAF_PATH to sign with the real registrar leaf.</p>"
    } else {
        "<p class=\"banner ok\">Signing with the registrar-issued leaf.</p>"
    };

    let body = format!(
        "<header><h1>Present your German PID</h1>\
         <p class=\"sub\">ERICA checks whether the protocol is valid. This checks whether the relying party is asking responsibly, and traces the whole exchange so you can debug it.</p></header>\
         <main>{mode}\
         <section class=\"card\"><h3>Scan to present</h3>\
         <p class=\"blurb\">The minimal ask: given name, family name, and over-18. Nothing else.</p>\
         <div class=\"qr\">{qr}</div>\
         <p class=\"mono\"><code>{auth}</code></p>\
         <p>client_id: <code>{cid}</code></p></section>\
         <section class=\"card\"><h3>Watch the exchange</h3>\
         <p class=\"blurb\">The wallet-interaction trace shows every step (request fetched, response decrypted, verification, trust, revocation, over-ask) with the raw artifacts, refreshing live.</p>\
         <p><a class=\"btn\" href=\"{trace}\">Open the live trace</a></p></section>\
         <section class=\"card\"><h3>Inspect the request</h3>\
         <p class=\"blurb\">See the over-ask analysis without presenting anything.</p>\
         <p><a class=\"btn ghost\" href=\"{inspect}\">Inspect this request (minimal)</a> \
         <a class=\"btn ghost\" href=\"{inspect}?demo=overask\">Inspect an over-asking variant</a></p>\
         <p class=\"blurb\">Signed request object (for ERICA): <code>{req}</code></p></section></main>\
         <footer><p class=\"note\">Sandbox shortcuts are labelled. The minimal baseline is a curated judgment, not a Rulebook derivation.</p></footer>",
        mode = mode,
        qr = qr,
        auth = esc(auth_url),
        trace = esc(&trace),
        cid = esc(&state.client_id),
        inspect = esc(&inspect),
        req = esc(&request_url),
    );
    page("Present your German PID", "", &body)
}

pub fn inspect_page(report: &OverAskReport, ephemeral: bool) -> String {
    let mut rows = String::new();
    for v in &report.requested {
        let corr = if v.correlatable {
            " <span class=\"tag\">correlatable</span>"
        } else {
            ""
        };
        rows.push_str(&format!(
            "<tr class=\"{cls}\"><td><code>{key}</code></td><td>{label}</td>\
             <td><span class=\"badge {cls}\">{word}</span></td><td>{rat}{corr}</td></tr>",
            cls = status_class(v.status),
            key = esc(&v.key),
            label = esc(&v.label),
            word = status_word(v.status),
            rat = esc(&v.rationale),
            corr = corr
        ));
    }

    let grid = if report.claim_rows.iter().any(|c| c.disclosed) {
        let items: String = report
            .claim_rows
            .iter()
            .map(|c| {
                let cls = if c.disclosed { "d" } else { "w" };
                format!("<li class=\"{}\">{}</li>", cls, esc(&c.label))
            })
            .collect();
        format!("<div class=\"grid\"><h4>Disclosed vs withheld</h4><ul class=\"claims\">{items}</ul></div>")
    } else {
        "<p class=\"blurb\">No presentation received yet; showing the request analysis.</p>"
            .to_string()
    };

    let over = if report.over_disclosed.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"over-note\">Over-disclosed (revealed but not requested): {}</p>",
            esc(&report.over_disclosed.join(", "))
        )
    };

    let suggestion = report
        .suggested_minimal
        .as_ref()
        .filter(|keys| !keys.is_empty())
        .map(|keys| {
            format!(
                "<p class=\"purpose\">Suggested minimal request: {}</p>",
                esc(&keys.join(", "))
            )
        })
        .unwrap_or_default();

    let purpose = report
        .purpose
        .as_deref()
        .map(|p| format!("<p class=\"purpose\">Stated purpose: {}</p>", esc(p)))
        .unwrap_or_default();

    let verdict_cls = report.verdict_class();

    let legal: String = report
        .legal_basis
        .iter()
        .map(|l| {
            format!(
                "<li><strong>{} {}</strong>: {}</li>",
                esc(l.source),
                esc(l.locator),
                esc(l.text)
            )
        })
        .collect();

    let dev = if ephemeral {
        "<p class=\"banner over\">Development certificate; not the registered identity.</p>"
    } else {
        ""
    };

    let body = format!(
        "<header><h1>Klartext</h1>\
         <p class=\"sub\">{vct}</p></header><main>{dev}\
         <section class=\"card\">{purpose}\
         <p class=\"verdict {vcls}\">{verdict}</p>\
         <table><thead><tr><th>Requested claim</th><th></th><th>Status</th><th>Why</th></tr></thead>\
         <tbody>{rows}</tbody></table>{suggestion}{over}{grid}</section></main>\
         <footer><h4>Basis</h4><ul class=\"legal\">{legal}</ul>\
         <p class=\"note\">Minimal baselines are curated judgments, not Rulebook derivations.</p></footer>",
        vct = esc(&report.vct),
        dev = dev,
        purpose = purpose,
        vcls = verdict_cls,
        verdict = esc(&report.verdict_line),
        rows = rows,
        suggestion = suggestion,
        over = over,
        grid = grid,
        legal = legal,
    );
    page("Klartext (over-ask inspector)", "", &body)
}

pub fn rejection_page(reason: &str, ephemeral: bool) -> String {
    let dev = if ephemeral {
        "<p class=\"banner over\">Development certificate; not the registered identity.</p>"
    } else {
        ""
    };
    let body = format!(
        "<header><h1>Klartext</h1>\
         <p class=\"sub\">Presentation verification failed</p></header><main>{dev}\
         <section class=\"card\"><p class=\"verdict over\">Presentation rejected</p>\
         <p class=\"blurb\">{reason}</p></section></main>",
        dev = dev,
        reason = esc(reason),
    );
    page("Klartext (presentation rejected)", "", &body)
}

/// The wallet-interaction trace timeline for a session. Refreshes live so a
/// developer can watch each step appear as the wallet interacts.
pub fn trace_page(state: &AppState, session: &Uuid, trace: Option<&SessionTrace>) -> String {
    let short = short_id(*session);
    let json_url = format!("{}api/trace/{}", state.public_url, session);

    let (timeline, count, terminal) = match trace {
        None => (
            "<p class=\"blurb\">No events yet for this session. Scan the QR on the \
             <a href=\"../\">landing page</a> to present, then this timeline fills in live.</p>"
                .to_string(),
            0usize,
            false,
        ),
        Some(t) => {
            let mut out = String::new();
            for e in &t.events {
                let cls = level_class(e.level);
                let detail = e
                    .detail
                    .as_ref()
                    .map(|d| {
                        let pretty =
                            serde_json::to_string_pretty(d).unwrap_or_else(|_| d.to_string());
                        format!(
                            "<details><summary>detail</summary><pre>{}</pre></details>",
                            esc(&pretty)
                        )
                    })
                    .unwrap_or_default();
                out.push_str(&format!(
                    "<li class=\"evt {cls}\"><div class=\"evt-head\">\
                     <span class=\"seq\">#{seq}</span>\
                     <span class=\"time\">{at}</span>\
                     <span class=\"badge {cls}\">{code}</span>\
                     <span class=\"evt-sum\">{summary}</span></div>{detail}</li>",
                    cls = cls,
                    seq = e.seq,
                    at = esc(&e.at),
                    code = esc(e.code),
                    summary = esc(&e.summary),
                    detail = detail,
                ));
            }
            let terminal = t.events.iter().any(|e| {
                matches!(e.level, TraceLevel::Good | TraceLevel::Bad) && is_outcome(e.code)
            });
            (
                format!("<ul class=\"timeline\">{out}</ul>"),
                t.events.len(),
                terminal,
            )
        }
    };

    // Refresh while the exchange is still in flight; stop once it reached an
    // outcome so a finished trace stays still and is easy to read.
    let head_extra = if terminal {
        String::new()
    } else {
        "<meta http-equiv=\"refresh\" content=\"2\">".to_string()
    };

    let dev = if state.ephemeral {
        "<p class=\"banner over\">Development certificate; not the registered identity.</p>"
    } else {
        ""
    };
    let live = if terminal {
        "<span class=\"pill done\">exchange complete</span>"
    } else {
        "<span class=\"pill live\">live, refreshing</span>"
    };

    let body = format!(
        "<header><h1>Wallet-interaction trace</h1>\
         <p class=\"sub\">session <code>{short}</code> {live} ({count} event(s))</p></header>\
         <main>{dev}\
         <section class=\"card\">{timeline}</section>\
         <p class=\"blurb\">Machine-readable: <a href=\"{json}\">{json}</a></p></main>\
         <footer><p class=\"note\">Each step carries the raw artifact the wallet sent or the verifier produced; expand \"detail\".</p></footer>",
        short = esc(&short),
        live = live,
        count = count,
        dev = dev,
        timeline = timeline,
        json = esc(&json_url),
    );
    page("Wallet-interaction trace", &head_extra, &body)
}

/// Whether a trace code marks a terminal outcome of the exchange.
fn is_outcome(code: &str) -> bool {
    matches!(code, "VERIFIED" | "REJECTED" | "ERROR")
}

const CSS: &str = r#"
:root{--ok:#1b7f4b;--warn:#b8730a;--over:#b4231f;--info:#2563eb;--ink:#1b1d22;--mut:#6b7280;--line:#e5e7eb;--bg:#fafafa}
*{box-sizing:border-box}
body{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);margin:0;background:var(--bg)}
header{padding:2.5rem 1.5rem 1rem;max-width:60rem;margin:0 auto}
header h1{font-size:1.8rem;margin:0 0 .3rem}
.sub{color:var(--mut);margin:0}
main{max-width:60rem;margin:0 auto;padding:0 1.5rem}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.25rem 1.5rem;margin:1.25rem 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.card h3{margin:.2rem 0 .4rem}
.blurb{color:var(--mut);margin:.2rem 0 .8rem}
.purpose{font-size:.95rem;margin:.2rem 0 .6rem}
.banner{padding:.6rem .9rem;border-radius:8px;margin:1rem auto;max-width:60rem;font-size:.95rem}
.banner.ok{background:#e9f7ef;color:var(--ok)}
.banner.over{background:#fdeceb;color:var(--over)}
.verdict{font-weight:600;padding:.5rem .75rem;border-radius:8px;margin:.6rem 0}
.verdict.ok{background:#e9f7ef;color:var(--ok)}
.verdict.over{background:#fdeceb;color:var(--over)}
table{width:100%;border-collapse:collapse;margin:.5rem 0;font-size:.95rem}
th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:var(--mut)}
code{background:#f3f4f6;padding:.05rem .35rem;border-radius:5px;font-size:.9em;word-break:break-all}
.mono{font-size:.82rem}
.badge{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.78rem;font-weight:600}
.badge.ok{background:#e9f7ef;color:var(--ok)}
.badge.warn{background:#fbf1e0;color:var(--warn)}
.badge.over{background:#fdeceb;color:var(--over)}
.badge.info{background:#e8eefc;color:var(--info)}
.tag{display:inline-block;margin-left:.3rem;font-size:.72rem;color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:0 .45rem}
.over-note{color:var(--over);font-size:.92rem}
.grid h4{margin:.8rem 0 .4rem;font-size:.85rem;text-transform:uppercase;letter-spacing:.03em;color:var(--mut)}
ul.claims{list-style:none;display:flex;flex-wrap:wrap;gap:.4rem;padding:0;margin:0}
ul.claims li{font-size:.85rem;padding:.15rem .55rem;border-radius:6px;border:1px solid var(--line)}
ul.claims li.d{background:#e9f7ef;color:var(--ok);border-color:#bfe6cf;font-weight:600}
ul.claims li.w{color:#9ca3af;text-decoration:line-through;background:#fff}
.qr{margin:.5rem 0;max-width:260px}
.qr svg{width:100%;height:auto}
.btn{display:inline-block;background:var(--ink);color:#fff;text-decoration:none;padding:.5rem .9rem;border-radius:8px;font-size:.9rem;margin:.2rem .3rem .2rem 0}
.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line)}
footer{max-width:60rem;margin:2rem auto;padding:1rem 1.5rem 3rem;color:var(--mut);font-size:.9rem;border-top:1px solid var(--line)}
footer h4{margin:.5rem 0 .4rem;color:var(--ink)}
ul.legal{margin:.3rem 0;padding-left:1.1rem}
.note{font-style:italic;margin-top:1rem}
.pill{display:inline-block;font-size:.75rem;font-weight:600;padding:.05rem .5rem;border-radius:999px;margin-left:.4rem}
.pill.live{background:#e8eefc;color:var(--info)}
.pill.done{background:#e9f7ef;color:var(--ok)}
ul.timeline{list-style:none;padding:0;margin:0}
li.evt{border-left:3px solid var(--line);padding:.5rem .25rem .5rem .9rem;margin:0 0 .4rem}
li.evt.ok{border-color:var(--ok)}
li.evt.warn{border-color:var(--warn)}
li.evt.over{border-color:var(--over)}
li.evt.info{border-color:var(--info)}
.evt-head{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}
.evt .seq{color:var(--mut);font-size:.78rem;font-variant-numeric:tabular-nums}
.evt .time{color:var(--mut);font-size:.82rem;font-variant-numeric:tabular-nums}
.evt-sum{flex:1}
.evt details{margin:.4rem 0 0}
.evt summary{cursor:pointer;color:var(--mut);font-size:.82rem}
.evt pre{background:#0f172a;color:#e2e8f0;padding:.75rem;border-radius:8px;overflow:auto;font-size:.78rem;max-height:24rem}
"#;
