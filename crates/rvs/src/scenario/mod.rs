#![allow(dead_code)]

mod resolver;

use std::path::Path;

pub use resolver::resolve_artifact_urls;
use serde::Deserialize;

/// Rack model + SOT release this scenario targets.
#[derive(Debug, Deserialize)]
pub struct RackTarget {
    pub model: String,
    pub sot_release: String,
}

/// Ephemeral OS image to boot on validation nodes.
#[derive(Debug, Deserialize)]
pub struct OsImage {
    pub uri: String,
}

/// Pre-cached artifact -- resolved via direct URI or SOT JSONPath.
#[derive(Debug, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub output: String,
    /// Direct download URL (mutually exclusive with `sotpath`).
    ///
    /// Exactly one of `uri`/`sotpath` must be set; enforced in
    /// `Scenario::load` after deserialization.
    pub uri: Option<String>,
    /// JSONPath into SOT JSON to resolve download URL.
    pub sotpath: Option<String>,
}

/// Setup step -- runs before tests, aborts validation on failure.
#[derive(Debug, Deserialize)]
pub struct SetupStep {
    pub execute: String,
}

/// Test step -- result recorded independently under `name`.
#[derive(Debug, Deserialize)]
pub struct TestStep {
    pub name: String,
    pub execute: String,
}

/// Teardown step -- always runs, regardless of test outcome.
#[derive(Debug, Deserialize)]
pub struct TeardownStep {
    pub execute: String,
}

/// Complete rack validation scenario definition.
#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub rack: RackTarget,
    pub os: OsImage,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub setup: Vec<SetupStep>,
    #[serde(default)]
    pub test: Vec<TestStep>,
    #[serde(default)]
    pub teardown: Vec<TeardownStep>,
}

impl Scenario {
    /// Parse a scenario from a TOML file on disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let scenario: Scenario =
            toml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))?;
        scenario
            .validate()
            .map_err(|e| format!("validate {}: {e}", path.display()))?;
        Ok(scenario)
    }

    fn validate(&self) -> Result<(), String> {
        for artifact in &self.artifacts {
            match (&artifact.uri, &artifact.sotpath) {
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "artifact '{}': both 'uri' and 'sotpath' set; exactly one required",
                        artifact.name
                    ));
                }
                (None, None) => {
                    return Err(format!(
                        "artifact '{}': neither 'uri' nor 'sotpath' set; exactly one required",
                        artifact.name
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_example_scenario() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("doc/example_scenario.toml");
        let scenario = Scenario::load(&path).unwrap();
        assert_eq!(scenario.rack.model, "gb200nvl");
        assert_eq!(scenario.rack.sot_release, "1.2.5");
        assert!(!scenario.os.uri.is_empty());
        assert_eq!(scenario.artifacts.len(), 6);
        assert_eq!(scenario.setup.len(), 1);
        assert_eq!(scenario.test.len(), 2);
        assert_eq!(scenario.teardown.len(), 1);
        assert_eq!(scenario.test[0].name, "nv_basic");
    }

    fn scenario_with_artifacts(artifacts: Vec<Artifact>) -> Scenario {
        Scenario {
            rack: RackTarget {
                model: "gb200nvl".to_string(),
                sot_release: "1.2.5".to_string(),
            },
            os: OsImage {
                uri: "https://example.com/os.img".to_string(),
            },
            artifacts,
            setup: vec![],
            test: vec![],
            teardown: vec![],
        }
    }

    fn artifact(name: &str, uri: Option<&str>, sotpath: Option<&str>) -> Artifact {
        Artifact {
            name: name.to_string(),
            output: format!("{name}.bin"),
            uri: uri.map(str::to_string),
            sotpath: sotpath.map(str::to_string),
        }
    }

    #[test]
    fn validate_accepts_uri_only() {
        let s = scenario_with_artifacts(vec![artifact("a", Some("https://x/y"), None)]);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn validate_accepts_sotpath_only() {
        let s = scenario_with_artifacts(vec![artifact("a", None, Some("$.foo"))]);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn validate_rejects_both_uri_and_sotpath() {
        let s = scenario_with_artifacts(vec![artifact("a", Some("https://x/y"), Some("$.foo"))]);
        let err = s.validate().unwrap_err();
        assert!(err.contains("both"), "got: {err}");
        assert!(err.contains("'a'"), "got: {err}");
    }

    #[test]
    fn validate_rejects_neither_uri_nor_sotpath() {
        let s = scenario_with_artifacts(vec![artifact("a", None, None)]);
        let err = s.validate().unwrap_err();
        assert!(err.contains("neither"), "got: {err}");
        assert!(err.contains("'a'"), "got: {err}");
    }
}
