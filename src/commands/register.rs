//! `register` and `list`: the guard-railed registrar write path. Writes are
//! dry-run by default, demand an explicit `--yes`, and refuse to proceed past an
//! over-ask warning, or past a body that could not be evaluated, unless
//! `--force` is given. `--force` is accepted only together with `--yes` (the
//! argument parser enforces it), so a dry run never passes a refused body.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::checkbody::{check_body_str, CheckResult};
use crate::config::Config;
use crate::http_target::{self, Target};
use crate::output::{self, out, outln};
use crate::render::{render_check, REGCERT_NOTICE};

pub struct RegisterArgs {
    pub target: Target,
    pub yes: bool,
    pub force: bool,
}

/// The line printed before a forced write (`--yes --force`) of a body the
/// gate would refuse. It states the exit code, because the report above it
/// carries the headline OVER-ASK or NOT EVALUATED, and a successful forced
/// write is the one case in which that headline ends with exit code 0.
fn forced_write_warning(result: CheckResult) -> Option<&'static str> {
    match result {
        CheckResult::OverAsk => Some(
            "Warning: writing an over-asking registration because --force was given. A forced write that succeeds exits 0.",
        ),
        CheckResult::NotEvaluated => Some(
            "Warning: writing a registration that could not be evaluated because --force was given. A forced write that succeeds exits 0.",
        ),
        CheckResult::Ok | CheckResult::FormatError => None,
    }
}

pub async fn register(label: &str, content: &str, args: RegisterArgs) -> Result<()> {
    register_with(
        label,
        content,
        args,
        output::stdout_closed,
        |target, body, config| async move {
            http_target::post_registration(target, &body, &config).await
        },
    )
    .await
}

/// The body of [`register`], with the two things it takes from outside as
/// parameters: `stdout_closed` says whether the reader of standard output is
/// gone, and `post` is the transport of a confirmed write. `post` is called
/// at most once, and only after `stdout_closed` was asked and returned
/// false: a confirmed write whose check report nobody could read stops
/// before anything is sent.
async fn register_with<P, Fut>(
    label: &str,
    content: &str,
    args: RegisterArgs,
    stdout_closed: impl Fn() -> bool,
    post: P,
) -> Result<()>
where
    P: FnOnce(Target, Value, Config) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    // `--force` without `--yes` is a usage error in the argument parser. A
    // caller that builds the arguments itself gets the same refusal here, so
    // a dry run cannot pass a body that over-asks or was not evaluated.
    if args.force && !args.yes {
        anyhow::bail!("--force requires --yes");
    }
    let (body, outcome) = check_body_str(content)?;
    out(&render_check(label, &outcome))?;

    let result = outcome.outcome();
    if result == CheckResult::FormatError {
        anyhow::bail!("Refusing to write: fix the blocking format errors above.");
    }

    if result == CheckResult::OverAsk && !args.force {
        outln(
            "Refusing to write: this request over-asks (see above). Re-run with --yes --force to write it anyway.",
        )?;
        std::process::exit(result.exit_code());
    }

    // A body nobody could judge is refused like an over-ask, also in a dry
    // run: the write gate opens only for a body that was judged and passed.
    if result == CheckResult::NotEvaluated && !args.force {
        outln(
            "Refusing to write: this request could not be evaluated (see above). Re-run with --yes --force to write it anyway.",
        )?;
        std::process::exit(result.exit_code());
    }

    if !args.yes {
        outln(&format!(
            "DRY RUN: nothing written. Re-run with --yes to write to {}.",
            args.target.as_str()
        ))?;
        return Ok(());
    }

    if matches!(args.target, Target::CachedSandbox) {
        anyhow::bail!(
            "cached-sandbox is read-only; use --target sandbox for real writes or --target clone for offline demo writes"
        );
    }

    if let Some(warning) = forced_write_warning(result) {
        // Reached only with --force: both results were refused above without it.
        outln(warning)?;
    } else {
        let rp_id = body
            .get("rpId")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        outln(&format!(
            "Writing to {} under RP {rp_id}...",
            args.target.as_str()
        ))?;
    }

    // Until here a closed standard output changed nothing: a dry run, a
    // refusal and a format error ended above with their own exit code. A
    // confirmed write is different. Its check report could not be read, so
    // it stops before anything is sent.
    if stdout_closed() {
        anyhow::bail!(
            "standard output was closed before the check report could be read; nothing was written"
        );
    }

    let config = Config::from_env();
    let response = post(args.target, body, config).await?;
    let id = response
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<missing id>");
    outln(&format!(
        "Wrote registration {id} to {}.",
        args.target.as_str()
    ))
}

pub async fn list(target: Target, rp: &str) -> Result<()> {
    let config = Config::from_env();
    let response = http_target::list_registrations(target, rp, &config).await?;
    let Some(items) = response.as_array() else {
        anyhow::bail!("list response was not an array");
    };

    if items.is_empty() {
        return outln(&format!(
            "No registrations for RP {rp} on {}.",
            target.as_str()
        ));
    }

    out(&render_registration_list(target.as_str(), rp, items)?)
}

/// The text of a non-empty registration list. Every row is a decoded
/// registration certificate, so the not-verified notice comes first.
fn render_registration_list(target: &str, rp: &str, items: &[Value]) -> Result<String> {
    let mut out = format!(
        "{} registration(s) for RP {rp} on {target}:\n{REGCERT_NOTICE}\n\n",
        items.len()
    );
    for item in items {
        out.push_str(&render_registration(item)?);
    }
    Ok(out)
}

fn render_registration(item: &Value) -> Result<String> {
    let id = item
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<missing id>");
    let jwt = item
        .get("jwt")
        .and_then(Value::as_str)
        .context("registration row has no jwt")?;
    let scope =
        augenmass_core::regcert::decode_registration_jwt(jwt).context("decode registration jwt")?;
    let purpose = scope.purpose_text().unwrap_or("not stated");
    let claims = scope.all_claim_keys();
    Ok(format!(
        "- {id}  purpose: \"{purpose}\"\n    claims: {}\n",
        claims.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_write_warning_states_the_exit_code() {
        assert_eq!(
            forced_write_warning(CheckResult::OverAsk),
            Some("Warning: writing an over-asking registration because --force was given. A forced write that succeeds exits 0.")
        );
        assert_eq!(
            forced_write_warning(CheckResult::NotEvaluated),
            Some("Warning: writing a registration that could not be evaluated because --force was given. A forced write that succeeds exits 0.")
        );
        assert_eq!(forced_write_warning(CheckResult::Ok), None);
        assert_eq!(forced_write_warning(CheckResult::FormatError), None);
    }

    /// `--force` without `--yes` never reaches the check or the dry run.
    #[tokio::test]
    async fn force_without_yes_is_refused_before_anything_is_checked() {
        let body = std::fs::read_to_string("examples/min.json").expect("example");
        let error = register(
            "examples/min.json",
            &body,
            RegisterArgs {
                target: Target::Clone,
                yes: false,
                force: true,
            },
        )
        .await
        .expect_err("refused");
        assert_eq!(error.to_string(), "--force requires --yes");
    }

    /// Runs `register_with` on a body with a transport that only counts its
    /// calls. It opens no connection: no registrar and no clone is involved.
    async fn confirmed_write(
        body_file: &str,
        force: bool,
        stdout_closed: bool,
    ) -> (Result<()>, usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let body = std::fs::read_to_string(body_file).expect("example");
        let calls = AtomicUsize::new(0);
        let result = register_with(
            body_file,
            &body,
            RegisterArgs {
                target: Target::Clone,
                yes: true,
                force,
            },
            || stdout_closed,
            |_target, _body, _config| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({ "id": "test" }))
            },
        )
        .await;
        (result, calls.load(Ordering::SeqCst))
    }

    /// A confirmed write whose check report nobody could read stops before
    /// the transport is called. A check placed after the call of the
    /// transport would fail the first and the third case; the second shows
    /// that the test sees a call when one happens. No case uses a refused
    /// body without `--force`: that path ends the process.
    #[tokio::test]
    async fn confirmed_write_stops_before_the_transport_when_stdout_is_closed() {
        let (result, calls) = confirmed_write("examples/min.json", false, true).await;
        let error = result.expect_err("stopped");
        assert!(error.to_string().contains("nothing was written"), "{error}");
        assert_eq!(calls, 0);

        let (result, calls) = confirmed_write("examples/min.json", false, false).await;
        result.expect("written");
        assert_eq!(calls, 1);

        let (result, calls) = confirmed_write("examples/over.json", true, true).await;
        let error = result.expect_err("stopped");
        assert!(error.to_string().contains("nothing was written"), "{error}");
        assert_eq!(calls, 0);
    }

    #[test]
    fn registration_list_states_that_certificates_are_not_verified() {
        let entry: Value = serde_json::from_str(
            &std::fs::read_to_string("fixtures/regcert/rc-by-id.json").expect("fixture"),
        )
        .expect("json");
        let text = render_registration_list("clone", "rp", &[entry]).expect("render");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "1 registration(s) for RP rp on clone:");
        assert_eq!(lines[1], REGCERT_NOTICE);
        assert!(text.contains("claims: age_equal_or_over.18, family_name, given_name"));
    }
}
