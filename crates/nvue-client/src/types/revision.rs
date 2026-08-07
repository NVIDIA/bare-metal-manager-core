use std::collections::BTreeMap;

use serde_json::Value as JsonValue;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RevisionData {
    pub message: Option<String>,
    pub state: Option<String>,
    pub transition: Option<RevisionTransition>,
    pub last_apply: Option<JsonValue>,
    pub additional_data: Option<JsonValue>,
    pub auto_prompt: Option<JsonValue>,
    pub state_controls: Option<JsonValue>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RevisionTransition {
    pub progress: Option<String>,
    pub issue: Option<BTreeMap<String, RevisionIssue>>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RevisionIssue {
    pub severity: Option<RevisionIssueSeverity>,
    pub code: Option<String>,
    pub message: Option<String>,
    pub data: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RevisionIssueSeverity {
    Error,
    Warning,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_revision_data_with_transition_issue() {
        let json = r#"
        {
            "additional-data": {
                "parent-revision-id": "applied"
            },
            "auto-prompt": {
                "ays": "ays_yes"
            },
            "last-apply": {
                "apply-id": "rev_1_apply_1"
            },
            "message": "apply config",
            "state": "apply",
            "state-controls": {
                "apply-type": "API"
            },
            "transition": {
                "progress": "checking",
                "issue": {
                    "1": {
                        "severity": "warning",
                        "code": "sample-warning",
                        "message": "sample warning",
                        "data": {
                            "path": "/system"
                        }
                    }
                }
            }
        }
        "#;

        let revision: RevisionData = serde_json::from_str(json).expect("revision should parse");

        assert_eq!(revision.message.as_deref(), Some("apply config"));
        assert_eq!(revision.state.as_deref(), Some("apply"));
        assert!(revision.additional_data.is_some());
        assert!(revision.auto_prompt.is_some());
        assert!(revision.last_apply.is_some());
        assert!(revision.state_controls.is_some());

        let transition = revision.transition.expect("transition should parse");
        assert_eq!(transition.progress.as_deref(), Some("checking"));

        let issues = transition.issue.expect("issues should parse");
        let issue = issues.get("1").expect("issue should parse");
        assert_eq!(issue.severity, Some(RevisionIssueSeverity::Warning));
        assert_eq!(issue.code.as_deref(), Some("sample-warning"));
        assert_eq!(issue.message.as_deref(), Some("sample warning"));
        assert_eq!(
            issue
                .data
                .as_ref()
                .and_then(|data| data.get("path"))
                .map(String::as_str),
            Some("/system")
        );
    }
}
