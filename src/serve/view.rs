//! Server-rendered HTML: the landing page (present + inspect + trace), the
//! over-ask inspector view, and the wallet-interaction trace timeline.
//!
//! The report rendering mirrors the over-ask CLI's text output on purpose. The
//! trace timeline is the browser face of the debugger: every recorded step with
//! redacted protocol detail, refreshing live while a wallet interacts.

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
    // Fonts: self-contained system stacks (no external font CDN), so the served
    // debugger HTML has zero external network dependency and stays offline-safe.
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         {head_extra}<title>{title}</title><style>{CSS}</style></head><body>\
         <nav class=\"topbar\"><a class=\"brand\" href=\"/\"><span class=\"glyph\">A</span>Augenma\u{00df}</a>\
         <div class=\"meta\"><b>Workbench</b>wallet-interaction debugger</div></nav>\
         {body}</body></html>"
    )
}

pub fn landing_page(state: &AppState, session_id: &Uuid, auth_url: &str) -> String {
    let qr = qr_svg(auth_url);
    let inspect = format!("{}inspect/{}", state.operator_url, session_id);
    let trace = format!("{}trace/{}", state.operator_url, session_id);
    let request_url = format!("{}request/{}", state.public_url, session_id);
    let mode = if state.ephemeral {
        "<p class=\"banner over\">Development mode: a throwaway certificate. The client_id below is not the registered sandbox identity. Set RP_KEY_PATH and RP_LEAF_PATH to sign with the real registrar leaf.</p>"
    } else {
        "<p class=\"banner ok\">Signing with the registrar-issued leaf.</p>"
    };
    let request_blurb = if state.request_profile.starts_with("age-only") {
        "The phone-demo ask: only whether the PID says age over 18. No name, family name, birthdate, address, or nationality. Reloading this page starts a fresh request (a new session and QR)."
    } else {
        "The minimal ask: given name, family name, and over-18. Nothing else. Reloading this page starts a fresh request (a new session and QR)."
    };
    let inspect_label = if state.request_profile.starts_with("age-only") {
        "Inspect this request (age-only)"
    } else {
        "Inspect this request (minimal)"
    };

    let body = format!(
        "<header><div class=\"kicker\"><span class=\"dot\"></span>Present \u{00b7} Verify \u{00b7} Trace</div><h1>Present your German PID</h1>\
         <p class=\"sub\">ERICA checks whether the protocol is valid. This checks whether the relying party is asking responsibly, and traces the whole exchange so you can debug it.</p></header>\
         <main>{mode}\
         <section class=\"card\"><h3>Scan to present</h3>\
         <p class=\"blurb\">{request_blurb}</p>\
         <div class=\"qr\">{qr}</div>\
         <p class=\"mono\"><code>{auth}</code></p>\
         <p>client_id: <code>{cid}</code></p></section>\
         <section class=\"card\"><h3>Watch the exchange</h3>\
         <p class=\"blurb\">The wallet-interaction trace shows every step (request fetched, response decrypted, verification, trust, revocation, over-ask) with PID-bearing wallet material redacted by default.</p>\
         <p><a class=\"btn\" href=\"{trace}\">Open the live trace</a></p></section>\
         <section class=\"card\"><h3>Inspect the request</h3>\
         <p class=\"blurb\">See the over-ask analysis without presenting anything.</p>\
         <p><a class=\"btn ghost\" href=\"{inspect}\">{inspect_label}</a> \
         <a class=\"btn ghost\" href=\"{inspect}?demo=overask\">Inspect an over-asking variant</a></p>\
         <p class=\"blurb\">Signed request object (for ERICA): <code>{req}</code></p></section></main>\
         <footer><p class=\"note\">Sandbox shortcuts are labelled. The minimal baseline is a curated judgment, not a Rulebook derivation.</p></footer>",
        mode = mode,
        request_blurb = request_blurb,
        qr = qr,
        auth = esc(auth_url),
        trace = esc(&trace),
        cid = esc(&state.client_id),
        inspect = esc(&inspect),
        inspect_label = inspect_label,
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
        "<header><div class=\"kicker\"><span class=\"dot\"></span>Over-ask inspector</div><h1>Klartext</h1>\
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
        "<header><div class=\"kicker\"><span class=\"dot\"></span>Over-ask inspector</div><h1>Klartext</h1>\
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
    let json_url = format!("{}api/trace/{}", state.operator_url, session);

    let (timeline, count) = match trace {
        None => (
            "<p class=\"blurb\">No events yet for this session. Scan the QR on the \
             <a href=\"../\">landing page</a> to present, then this timeline fills in live.</p>"
                .to_string(),
            0usize,
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
            (format!("<ul class=\"timeline\">{out}</ul>"), t.events.len())
        }
    };

    // Derive the outcome from the LAST terminal event, not merely any success: a
    // revoked credential first VERIFIES and is then REJECTED, so keying off the
    // last outcome event keeps the pill and refresh honest.
    let last_outcome = trace.and_then(|t| t.events.iter().rev().find(|e| is_outcome(e.code)));
    let terminal = last_outcome.is_some();

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
    let live = match last_outcome {
        Some(e) if e.code == "VERIFIED" => "<span class=\"pill done\">verified</span>",
        Some(_) => "<span class=\"pill fail\">rejected</span>",
        None => "<span class=\"pill live\">live, refreshing</span>",
    };

    let body = format!(
        "<header><div class=\"kicker\"><span class=\"dot\"></span>Live wallet trace</div><h1>Wallet-interaction trace</h1>\
         <p class=\"sub\">session <code>{short}</code> {live} ({count} event(s))</p></header>\
         <main>{dev}\
         <section class=\"card\">{timeline}</section>\
         <p class=\"blurb\">Machine-readable: <a href=\"{json}\">{json}</a></p></main>\
         <footer><p class=\"note\">PID-bearing wallet response material is redacted in the HTTP trace API; expand \"detail\" for hashes, shapes, request context, and verifier outcomes.</p></footer>",
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

// Neo-brutalist board, ported from the Augenmaß website: flat yellow ground with a
// printed dot grid, white blocks with thick ink rules and hard offset shadows,
// rubber-stamp verdicts, mono micro-labels. The severity tokens (over/amber/blue/
// teal/steel) carry the same meaning here as on the board: red is the loudest
// over-ask, teal is proportionate. Display and body use a system sans stack,
// technical labels a system monospace stack. No rounded corners, no soft shadows.
const CSS: &str = r#"
:root{
  --yellow:#FFD400;--ink:#0E0D0A;--paper:#FBF6E3;--paper-2:#F3ECCF;
  --over:#FF3B2F;--over-deep:#D21F14;--amber:#FF9500;--blue:#2B4CFF;
  --steel:#AEB6C4;--grey:#9A9684;--teal:#0FB57E;--teal-deep:#0A7E58;
  --disp:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --body:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --bd:4px;--off:9px;--maxw:66rem;--ease:cubic-bezier(.2,.9,.25,1);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--yellow);color:var(--ink);font-family:var(--body);font-weight:500;font-size:16px;line-height:1.5;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;overflow-x:hidden;background-image:radial-gradient(var(--ink) 1.15px,transparent 1.25px);background-size:26px 26px;background-position:-3px -3px}
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(14,13,10,.04) 0 1px,transparent 1px 72px),repeating-linear-gradient(90deg,rgba(14,13,10,.04) 0 1px,transparent 1px 72px);mix-blend-mode:multiply}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
a{color:inherit}
::selection{background:var(--ink);color:var(--yellow)}

.topbar{position:relative;z-index:3;display:flex;align-items:center;justify-content:space-between;gap:16px;max-width:var(--maxw);margin:0 auto;padding:18px clamp(16px,3.5vw,40px)}
.brand{display:flex;align-items:center;gap:13px;font-family:var(--disp);font-weight:800;font-size:21px;letter-spacing:-.015em;text-decoration:none}
.brand .glyph{width:40px;height:40px;display:grid;place-items:center;background:var(--ink);color:var(--yellow);border:3px solid var(--ink);box-shadow:5px 5px 0 var(--over);transform:rotate(-5deg);font-family:var(--disp);font-weight:800;font-size:20px}
.topbar .meta{font-family:var(--mono);font-size:11.5px;text-align:right;line-height:1.35}
.topbar .meta b{display:block;letter-spacing:.04em;text-transform:uppercase}
@media (max-width:560px){.topbar .meta{display:none}}

header{position:relative;z-index:1;max-width:var(--maxw);margin:0 auto;padding:26px clamp(16px,3.5vw,40px) 6px}
header h1{font-family:var(--disp);font-weight:800;text-transform:uppercase;font-size:clamp(32px,6vw,64px);line-height:.92;letter-spacing:-.025em;margin:14px 0 0;max-width:20ch}
.sub{font-family:var(--mono);font-size:13px;line-height:1.6;margin:14px 0 0;max-width:74ch;font-weight:400}
.kicker{display:inline-flex;align-items:center;gap:10px;font-family:var(--mono);font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.09em;line-height:1}
.kicker .dot{width:12px;height:12px;background:var(--over);border:2px solid var(--ink);border-radius:50%;box-shadow:2px 2px 0 var(--ink)}

main{position:relative;z-index:1;max-width:var(--maxw);margin:0 auto;padding:6px clamp(16px,3.5vw,40px) 0}
.card{position:relative;background:#fff;border:var(--bd) solid var(--ink);box-shadow:var(--off) var(--off) 0 var(--ink);padding:22px clamp(18px,2.5vw,26px);margin:24px 0}
.card h3{font-family:var(--disp);font-weight:800;text-transform:uppercase;font-size:clamp(18px,3vw,26px);line-height:.98;letter-spacing:-.02em;margin:0 0 10px}
.card h4,.grid h4{font-family:var(--mono);font-weight:700;text-transform:uppercase;letter-spacing:.05em;font-size:11.5px;margin:16px 0 8px}
.blurb{font-family:var(--mono);font-size:12.5px;line-height:1.6;margin:0 0 14px;max-width:76ch}
p{margin:.5rem 0}

.banner{font-family:var(--mono);font-weight:700;font-size:12.5px;line-height:1.5;padding:12px 15px;margin:6px 0 18px;border:3px solid var(--ink);box-shadow:5px 5px 0 var(--ink)}
.banner.ok{background:var(--teal);color:#04241a}
.banner.over{background:var(--over);color:#fff}

.verdict{display:inline-flex;align-items:center;font-family:var(--disp);font-weight:800;text-transform:uppercase;letter-spacing:.01em;font-size:clamp(15px,2.4vw,21px);line-height:1;padding:12px 16px;border:3px solid var(--ink);box-shadow:5px 5px 0 var(--ink);transform:rotate(-1.4deg);margin:6px 0 18px}
.verdict.ok{background:var(--teal);color:#04241a}
.verdict.over{background:var(--over);color:#fff}

code{font-family:var(--mono);font-weight:700;font-size:.85em;background:var(--ink);color:var(--yellow);padding:1px 6px;word-break:break-all}
.mono{font-family:var(--mono);font-size:12px}

.qr{display:inline-block;margin:8px 0 6px;width:100%;max-width:280px;background:#fff;border:var(--bd) solid var(--ink);box-shadow:7px 7px 0 var(--over);padding:14px}
.qr svg{display:block;width:100%;height:auto}

.btn{display:inline-flex;align-items:center;gap:10px;cursor:pointer;font-family:var(--disp);font-weight:700;font-size:14px;text-transform:uppercase;letter-spacing:.01em;padding:13px 18px;background:var(--blue);color:#fff;border:var(--bd) solid var(--ink);box-shadow:6px 6px 0 var(--ink);text-decoration:none;transition:transform .09s var(--ease),box-shadow .09s var(--ease);margin:6px 10px 6px 0}
.btn:hover{transform:translate(3px,3px);box-shadow:3px 3px 0 var(--ink)}
.btn:active{transform:translate(6px,6px);box-shadow:0 0 0 var(--ink)}
.btn:focus-visible{outline:4px solid var(--over);outline-offset:3px}
.btn.ghost{background:#fff;color:var(--ink)}

table{width:100%;border-collapse:collapse;margin:12px 0;font-family:var(--body);font-size:14px}
thead th{font-family:var(--mono);font-weight:700;text-transform:uppercase;letter-spacing:.04em;font-size:10.5px;text-align:left;padding:9px 10px;background:var(--ink);color:var(--yellow)}
tbody td{text-align:left;padding:10px;border-bottom:2px solid var(--ink);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr.over{background:rgba(255,59,47,.10)}
tbody tr.warn{background:rgba(255,149,0,.13)}
tbody tr.ok{background:rgba(15,181,126,.10)}

.badge{display:inline-block;font-family:var(--mono);font-weight:700;text-transform:uppercase;letter-spacing:.03em;font-size:10px;padding:3px 8px;border:2px solid var(--ink);box-shadow:2px 2px 0 var(--ink);white-space:nowrap}
.badge.ok{background:var(--teal);color:#04241a}
.badge.warn{background:var(--amber);color:var(--ink)}
.badge.over{background:var(--over);color:#fff}
.badge.info{background:var(--blue);color:#fff}

.tag{display:inline-block;margin-left:.4rem;font-family:var(--mono);font-weight:700;font-size:9.5px;text-transform:uppercase;letter-spacing:.04em;border:2px solid var(--ink);background:var(--amber);color:var(--ink);padding:1px 6px}
.over-note{font-family:var(--mono);font-weight:700;font-size:12px;color:var(--over-deep);margin:12px 0 0}
.purpose{font-family:var(--mono);font-size:12.5px;line-height:1.5;margin:0 0 10px}
.note{font-family:var(--mono);font-size:11.5px;font-style:italic;line-height:1.6;margin-top:12px}

ul.claims{list-style:none;display:flex;flex-wrap:wrap;gap:8px;padding:0;margin:0}
ul.claims li{font-family:var(--mono);font-weight:700;font-size:11px;padding:5px 9px;border:2px solid var(--ink)}
ul.claims li.d{background:var(--teal);color:#04241a;box-shadow:2px 2px 0 var(--ink)}
ul.claims li.w{background:#fff;color:var(--grey);text-decoration:line-through;text-decoration-thickness:2px}

footer{margin-top:46px;background:var(--ink);color:var(--paper);position:relative;z-index:1;padding:34px 0 52px}
footer>*{max-width:var(--maxw);margin:0 auto;padding:0 clamp(16px,3.5vw,40px)}
footer h4{font-family:var(--disp);font-weight:800;text-transform:uppercase;font-size:clamp(18px,3vw,26px);letter-spacing:-.02em;margin:0 0 8px;color:var(--yellow)}
footer .note{color:#cfcbbb}
footer a{color:var(--yellow)}
ul.legal{font-family:var(--mono);font-size:12px;line-height:1.65;margin:8px 0;padding-left:1.1rem}
ul.legal strong{color:var(--yellow)}

.pill{display:inline-flex;align-items:center;font-family:var(--mono);font-weight:700;text-transform:uppercase;letter-spacing:.04em;font-size:10px;padding:3px 9px;border:2px solid var(--ink);box-shadow:2px 2px 0 var(--ink);margin-left:8px}
.pill.live{background:var(--blue);color:#fff;animation:blink 1.1s steps(2,end) infinite}
.pill.done{background:var(--teal);color:#04241a}
.pill.fail{background:var(--over);color:#fff}
@keyframes blink{50%{opacity:.4}}
@media (prefers-reduced-motion:reduce){.pill.live{animation:none}}

ul.timeline{list-style:none;padding:0;margin:0;display:grid;gap:12px}
li.evt{position:relative;background:#fff;border:3px solid var(--ink);border-left-width:10px;box-shadow:5px 5px 0 var(--ink);padding:12px 14px}
li.evt.ok{border-left-color:var(--teal)}
li.evt.warn{border-left-color:var(--amber)}
li.evt.over{border-left-color:var(--over)}
li.evt.info{border-left-color:var(--blue)}
.evt-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.evt .seq{font-family:var(--mono);font-weight:700;font-size:12px;color:var(--grey);font-variant-numeric:tabular-nums}
.evt .time{font-family:var(--mono);font-size:11px;color:var(--grey);font-variant-numeric:tabular-nums}
.evt-sum{flex:1;font-weight:600;font-size:14px;min-width:12ch}
.evt details{margin:10px 0 0}
.evt summary{cursor:pointer;font-family:var(--mono);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--blue)}
.evt pre{background:var(--ink);color:var(--paper);padding:12px;margin:8px 0 0;overflow:auto;font-family:var(--mono);font-size:11.5px;line-height:1.5;max-height:24rem}

@media (max-width:560px){:root{--bd:3px;--off:6px}header h1{font-size:clamp(28px,9vw,44px)}}
"#;
