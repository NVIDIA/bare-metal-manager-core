#![allow(dead_code)]

use std::path::Path;

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
    // TODO[#416]: enforce exactly one of `uri`/`sotpath` is set - add a
    // post-deserialization validation step in Scenario::load or a custom
    // Deserialize impl. Currently both can be set (or neither) without error.
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
        toml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))
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
}
