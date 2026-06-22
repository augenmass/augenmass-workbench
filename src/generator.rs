//! Generators for proportionate (and, for contrast, over-broad) registrar
//! registration bodies.

use augenmass_core::{pid, PID_VCT};
use serde_json::{json, Value};

use crate::{DEFAULT_PRIVACY_POLICY, DEFAULT_PURPOSE, DEFAULT_RP_ID, DEFAULT_SUPPORT_URI};

#[derive(Debug, Clone)]
pub struct GenerateOptions {
    pub over_broad: bool,
    pub rp_id: String,
    pub support_uri: String,
    pub privacy_policy: String,
    pub purpose: String,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            over_broad: false,
            rp_id: DEFAULT_RP_ID.to_string(),
            support_uri: DEFAULT_SUPPORT_URI.to_string(),
            privacy_policy: DEFAULT_PRIVACY_POLICY.to_string(),
            purpose: DEFAULT_PURPOSE.to_string(),
        }
    }
}

pub fn age_check_body(options: &GenerateOptions) -> Value {
    let paths = if options.over_broad {
        over_broad_paths()
    } else {
        age_gate_paths()
    };

    json!({
        "rpId": options.rp_id,
        "support_uri": options.support_uri,
        "privacy_policy": options.privacy_policy,
        "purpose": [
            {
                "lang": "en",
                "content": options.purpose
            }
        ],
        "credentials": [
            {
                "format": pid::PID_FORMAT,
                "meta": {
                    "vct_values": [PID_VCT]
                },
                "claims": paths.into_iter().map(|path| json!({ "path": path })).collect::<Vec<_>>()
            }
        ]
    })
}

pub fn age_gate_paths() -> Vec<Vec<String>> {
    vec![vec!["age_equal_or_over".to_string(), "18".to_string()]]
}

pub fn over_broad_paths() -> Vec<Vec<String>> {
    vec![
        vec!["given_name".to_string()],
        vec!["family_name".to_string()],
        vec!["birthdate".to_string()],
        vec!["address".to_string(), "resident_street".to_string()],
        vec!["address".to_string(), "resident_city".to_string()],
        vec!["nationalities".to_string()],
    ]
}

#[cfg(test)]
mod tests {
    use augenmass_core::{inspector, pid, regcert, PID_VCT};

    use super::*;

    #[test]
    fn generated_minimal_age_gate_is_clean_against_age_baseline() {
        let body = age_check_body(&GenerateOptions::default());
        let registered = regcert::scope_from_payload(&body).expect("generated body decodes");
        let query = pid::pid_query(&[&["age_equal_or_over", "18"]]);
        let baseline = inspector::baseline("age_gate_18");
        let report = inspector::analyze(PID_VCT, &query, Some(&registered), baseline.as_ref(), &[]);

        assert!(!report.has_over_ask());
    }
}
