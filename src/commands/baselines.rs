//! Reference command: list the curated purpose baselines and the legal basis
//! the over-ask guardrail cites. Auditor- and developer-facing documentation
//! that stays in sync with the engine because it reads the engine's data.

use anyhow::Result;
use augenmass_core::inspector::{self, LEGAL_BASIS};
use serde_json::{json, Value};

use crate::output::{emit, OutputFormat};

/// The baseline ids the engine knows. Keep in sync with `inspector::baseline`.
pub const KNOWN_BASELINES: &[&str] = &["age_gate_18", "event_checkin", "car_rental", "bank_kyc"];

pub fn run(show: Option<&str>, format: OutputFormat) -> Result<()> {
    match show {
        Some(id) => show_one(id, format),
        None => list_all(format),
    }
}

fn list_all(format: OutputFormat) -> Result<()> {
    let baselines: Vec<Value> = KNOWN_BASELINES
        .iter()
        .filter_map(|id| inspector::baseline(id))
        .map(|b| serde_json::to_value(&b).unwrap_or(Value::Null))
        .collect();
    let legal: Vec<Value> = LEGAL_BASIS
        .iter()
        .map(|l| json!({ "source": l.source, "locator": l.locator, "text": l.text }))
        .collect();

    let json = json!({ "baselines": baselines, "legalBasis": legal });

    let mut text = String::new();
    text.push_str("Curated purpose baselines:\n\n");
    for id in KNOWN_BASELINES {
        if let Some(b) = inspector::baseline(id) {
            text.push_str(&format!("  {}  ({})\n", b.id, b.label));
            text.push_str(&format!("    minimal: {}\n", b.minimal_keys.join(", ")));
        }
    }
    text.push_str("\nLegal basis cited on every over-ask finding:\n");
    for l in LEGAL_BASIS {
        text.push_str(&format!("  {}, {}\n    {}\n", l.source, l.locator, l.text));
    }
    text.push_str("\nNote: the baselines are curated taste judgments, not Rulebook derivations.\n");
    emit(format, &json, &text)?;
    Ok(())
}

fn show_one(id: &str, format: OutputFormat) -> Result<()> {
    match inspector::baseline(id) {
        Some(b) => {
            let json = serde_json::to_value(&b)?;
            let mut text = String::new();
            text.push_str(&format!("{}  ({})\n", b.id, b.label));
            text.push_str(&format!(
                "  minimal claims: {}\n",
                b.minimal_keys.join(", ")
            ));
            text.push_str(&format!("  note: {}\n", b.note));
            emit(format, &json, &text)?;
            Ok(())
        }
        None => {
            let known = KNOWN_BASELINES.join(", ");
            anyhow::bail!("unknown baseline '{id}'. Known baselines: {known}");
        }
    }
}
