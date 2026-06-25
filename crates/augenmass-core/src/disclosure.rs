//! Disclosed-claim extraction.
//!
//! After the signature checks pass, the inspector needs to know exactly which
//! selectively-disclosable claims the holder chose to reveal, and their values.
//! `ssi`'s `decode_reveal_any` applies the disclosures to the issuer payload and
//! records each revealed value at its JSON pointer, which handles nested and
//! recursive disclosures correctly. The keys of that map are precisely the
//! selectively-disclosed paths; everything else in the PID model is "withheld".

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use ssi::claims::sd_jwt::SdJwt;

/// A single disclosed claim: its path segments and the revealed value.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisclosedClaim {
    pub path: Vec<String>,
    pub value: Value,
}

impl DisclosedClaim {
    /// The dotted path key, e.g. `age_equal_or_over.18`.
    pub fn key(&self) -> String {
        self.path.join(".")
    }
}

/// The revealed view of a presented SD-JWT VC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RevealedView {
    /// The full revealed claim object (always-visible claims plus disclosed).
    pub claims: Value,
    /// The selectively-disclosed claims (path plus value), sorted by path.
    pub disclosed: Vec<DisclosedClaim>,
}

/// Reveal the disclosed claim set of a (already signature-checked) SD-JWT VC.
pub fn revealed_claims(sd_jwt: &SdJwt) -> Result<RevealedView> {
    let revealed = sd_jwt
        .decode_reveal_any()
        .map_err(|e| anyhow!("reveal failed: {e}"))?;

    let claims: Value =
        serde_json::to_value(revealed.claims()).context("serialize revealed claims")?;

    let mut disclosed = BTreeMap::new();
    for pointer in revealed.disclosures.keys() {
        // JSON pointer form, e.g. "/given_name" or "/age_equal_or_over/18".
        let ptr = pointer.to_string();
        let value = claims.pointer(&ptr).cloned().unwrap_or(Value::Null);
        let path = pointer_path(&ptr);
        collect_disclosed_leaves(&mut disclosed, path, value);
    }
    let disclosed = disclosed
        .into_iter()
        .map(|(path, value)| DisclosedClaim { path, value })
        .collect();

    Ok(RevealedView { claims, disclosed })
}

fn pointer_path(ptr: &str) -> Vec<String> {
    ptr.trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn collect_disclosed_leaves(
    disclosed: &mut BTreeMap<Vec<String>, Value>,
    path: Vec<String>,
    value: Value,
) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, value) in map {
                let mut child = path.clone();
                child.push(key);
                collect_disclosed_leaves(disclosed, child, value);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (idx, value) in items.into_iter().enumerate() {
                let mut child = path.clone();
                child.push(idx.to_string());
                collect_disclosed_leaves(disclosed, child, value);
            }
        }
        other => {
            disclosed.insert(path, other);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_path_unescapes_json_pointer_segments() {
        assert_eq!(
            pointer_path("/address/a~1b/c~0d"),
            vec!["address", "a/b", "c~d"]
        );
    }

    #[test]
    fn disclosed_object_is_accounted_as_leaf_claims() {
        let mut disclosed = BTreeMap::new();
        collect_disclosed_leaves(
            &mut disclosed,
            vec!["age_equal_or_over".to_string()],
            serde_json::json!({
                "12": true,
                "14": true,
                "16": true,
                "18": true,
                "21": true,
                "65": false
            }),
        );

        let keys: Vec<String> = disclosed.keys().map(|path| path.join(".")).collect();
        assert_eq!(
            keys,
            vec![
                "age_equal_or_over.12",
                "age_equal_or_over.14",
                "age_equal_or_over.16",
                "age_equal_or_over.18",
                "age_equal_or_over.21",
                "age_equal_or_over.65",
            ]
        );
    }
}
