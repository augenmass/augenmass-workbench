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
            if !b.mdoc_elements.is_empty() {
                text.push_str(&format!("    mdoc elements: {}\n", mdoc_elements(&b)));
            }
            text.push_str(&format!("    credential types: {}\n", credential_types(&b)));
        }
    }
    text.push_str("\nLegal basis cited on every over-ask finding:\n");
    for l in LEGAL_BASIS {
        text.push_str(&format!("  {}, {}\n    {}\n", l.source, l.locator, l.text));
    }
    text.push_str("\nNote: the baselines are curated assessments, not law and not legal advice.\n");
    emit(format, &json, &text)?;
    Ok(())
}

/// The baseline's mso_mdoc elements as `namespace/element`, comma separated.
/// The slash keeps namespace and element apart (the namespace holds dots).
fn mdoc_elements(b: &inspector::PurposeBaseline) -> String {
    b.mdoc_elements
        .iter()
        .map(|[namespace, element]| format!("{namespace}/{element}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The credential types the baseline models, one phrase per type set,
/// separated by "; ".
fn credential_types(b: &inspector::PurposeBaseline) -> String {
    inspector::describe_credential_types(&b.credential_types).join("; ")
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
            if !b.mdoc_elements.is_empty() {
                text.push_str(&format!("  mdoc elements: {}\n", mdoc_elements(&b)));
            }
            text.push_str(&format!("  credential types: {}\n", credential_types(&b)));
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
