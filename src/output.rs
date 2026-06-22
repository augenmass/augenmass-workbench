//! Output format handling. Every read-only command can emit either a
//! human-readable text rendering or a machine-readable JSON document, selected
//! by the global `--json` flag. JSON output is what makes the toolkit usable
//! from agents, scripts, and CI.

use anyhow::Result;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn from_json_flag(json: bool) -> Self {
        if json {
            Self::Json
        } else {
            Self::Text
        }
    }

    pub fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

/// Print a result as either pretty JSON or the supplied text rendering.
/// The text is printed verbatim (callers include their own trailing newline
/// where needed); JSON is always newline-terminated.
pub fn emit(format: OutputFormat, json: &Value, text: &str) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(json)?),
        OutputFormat::Text => print!("{text}"),
    }
    Ok(())
}
