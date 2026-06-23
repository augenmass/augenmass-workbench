//! `register` and `list`: the guard-railed registrar write path. Writes are
//! dry-run by default, demand an explicit `--yes`, and refuse to proceed past an
//! over-ask warning unless `--force` is given.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::checkbody::check_body_str;
use crate::config::Config;
use crate::http_target::{self, Target};
use crate::render::render_check;

pub struct RegisterArgs {
    pub target: Target,
    pub yes: bool,
    pub force: bool,
}

pub async fn register(label: &str, content: &str, args: RegisterArgs) -> Result<()> {
    let (body, outcome) = check_body_str(content)?;
    print!("{}", render_check(label, &outcome));

    if outcome.has_blocking_format_error() {
        anyhow::bail!("Refusing to write: fix the blocking format errors above.");
    }

    if outcome.has_over_ask() && !args.force {
        println!(
            "Refusing to write: this request over-asks (see above). Re-run with --yes --force to write it anyway."
        );
        std::process::exit(1);
    }

    if !args.yes {
        println!(
            "DRY RUN: nothing written. Re-run with --yes to write to {}.",
            args.target.as_str()
        );
        return Ok(());
    }

    if matches!(args.target, Target::CachedSandbox) {
        anyhow::bail!(
            "cached-sandbox is read-only; use --target sandbox for real writes or --target clone for offline demo writes"
        );
    }

    if outcome.has_over_ask() && args.force {
        println!("Warning: writing an over-asking registration because --force was given.");
    } else {
        let rp_id = body
            .get("rpId")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        println!("Writing to {} under RP {rp_id}...", args.target.as_str());
    }

    let config = Config::from_env();
    let response = http_target::post_registration(args.target, &body, &config).await?;
    let id = response
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<missing id>");
    println!("Wrote registration {id} to {}.", args.target.as_str());
    Ok(())
}

pub async fn list(target: Target, rp: &str) -> Result<()> {
    let config = Config::from_env();
    let response = http_target::list_registrations(target, rp, &config).await?;
    let Some(items) = response.as_array() else {
        anyhow::bail!("list response was not an array");
    };

    if items.is_empty() {
        println!("No registrations for RP {rp} on {}.", target.as_str());
        return Ok(());
    }

    println!(
        "{} registration(s) for RP {rp} on {}:\n",
        items.len(),
        target.as_str()
    );

    for item in items {
        render_registration(item)?;
    }
    Ok(())
}

fn render_registration(item: &Value) -> Result<()> {
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
    println!("- {id}  purpose: \"{purpose}\"");
    println!("    claims: {}", claims.join(", "));
    Ok(())
}
