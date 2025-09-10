/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Serialization support for MLX configuration profiles.
//!
//! Provides YAML and JSON serialization/deserialization for profiles,
//! with proper validation and registry lookup during deserialization.

use crate::{error::MlxProfileError, profile::MlxConfigProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serializable representation of an MLX configuration profile.
/// This is the format used for YAML/JSON serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableProfile {
    /// Profile name for identification and documentation
    pub name: String,
    /// Registry name that this profile targets
    pub registry_name: String,
    /// Optional description of what this profile does
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Variable configurations as name -> YAML value mappings
    pub config: HashMap<String, serde_yaml::Value>,
}

impl SerializableProfile {
    /// Creates a new serializable profile.
    pub fn new<N: Into<String>, R: Into<String>>(name: N, registry_name: R) -> Self {
        Self {
            name: name.into(),
            registry_name: registry_name.into(),
            description: None,
            config: HashMap::new(),
        }
    }

    /// Sets the description for this profile.
    pub fn with_description<D: Into<String>>(mut self, description: D) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Adds a variable configuration to this profile.
    pub fn with_config<K: Into<String>, V: Into<serde_yaml::Value>>(
        mut self,
        variable_name: K,
        value: V,
    ) -> Self {
        self.config.insert(variable_name.into(), value.into());
        self
    }

    /// Converts this serializable profile to an MlxConfigProfile by resolving
    /// the registry and validating all variable configurations.
    pub fn into_profile(self) -> Result<MlxConfigProfile, MlxProfileError> {
        // Look up the registry
        let registry = mlxconfig_registry::registries::get(&self.registry_name)
            .ok_or_else(|| MlxProfileError::registry_not_found(&self.registry_name))?
            .clone();

        // Create the profile
        let mut profile = MlxConfigProfile::new(self.name, registry);

        if let Some(description) = self.description {
            profile = profile.with_description(description);
        }

        // Just pass the YAML value directly to .with() - our trait handles everything!
        for (variable_name, yaml_value) in self.config {
            profile = profile.with(&variable_name, yaml_value)?;
        }

        Ok(profile)
    }

    /// Creates a SerializableProfile from an MlxConfigProfile.
    pub fn from_profile(profile: &MlxConfigProfile) -> Result<Self, MlxProfileError> {
        let mut serializable = Self::new(&profile.name, &profile.registry.name);

        if let Some(description) = &profile.description {
            serializable = serializable.with_description(description);
        }

        // Convert each MlxConfigValue back to a simple YAML value
        for config_value in &profile.config_values {
            let yaml_value = config_value_to_yaml_value(config_value)?;
            serializable = serializable.with_config(config_value.name(), yaml_value);
        }

        Ok(serializable)
    }

    /// Loads a profile from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, MlxProfileError> {
        serde_yaml::from_str(yaml).map_err(MlxProfileError::from)
    }

    /// Loads a profile from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, MlxProfileError> {
        serde_json::from_str(json).map_err(MlxProfileError::from)
    }

    /// Serializes this profile to a YAML string.
    pub fn to_yaml(&self) -> Result<String, MlxProfileError> {
        serde_yaml::to_string(self).map_err(MlxProfileError::from)
    }

    /// Serializes this profile to a JSON string.
    pub fn to_json(&self) -> Result<String, MlxProfileError> {
        serde_json::to_string_pretty(self).map_err(MlxProfileError::from)
    }
}

/// Converts an MlxConfigValue back to a simple YAML value for serialization.
fn config_value_to_yaml_value(
    config_value: &mlxconfig_variables::MlxConfigValue,
) -> Result<serde_yaml::Value, MlxProfileError> {
    Ok(config_value.value.to_yaml_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializable_profile_creation() {
        let profile = SerializableProfile::new("test_profile", "test_registry")
            .with_description("Test profile for unit tests")
            .with_config("BOOL_VAR", true)
            .with_config("INT_VAR", 42);

        assert_eq!(profile.name, "test_profile");
        assert_eq!(profile.registry_name, "test_registry");
        assert_eq!(
            profile.description,
            Some("Test profile for unit tests".to_string())
        );
        assert_eq!(profile.config.len(), 2);
    }

    #[test]
    fn test_yaml_serialization() {
        let profile = SerializableProfile::new("test_profile", "test_registry")
            .with_description("Test profile")
            .with_config("BOOL_VAR", true)
            .with_config("INT_VAR", 123);

        let yaml = profile.to_yaml().expect("Should serialize to YAML");
        assert!(yaml.contains("name: test_profile"));
        assert!(yaml.contains("registry_name: test_registry"));
        assert!(yaml.contains("description: Test profile"));
        assert!(yaml.contains("BOOL_VAR: true"));
        assert!(yaml.contains("INT_VAR: 123"));

        // Test round-trip
        let deserialized =
            SerializableProfile::from_yaml(&yaml).expect("Should deserialize from YAML");
        assert_eq!(deserialized.name, profile.name);
        assert_eq!(deserialized.registry_name, profile.registry_name);
        assert_eq!(deserialized.description, profile.description);
        assert_eq!(deserialized.config.len(), profile.config.len());
    }

    #[test]
    fn test_json_serialization() {
        let profile = SerializableProfile::new("test_profile", "test_registry")
            .with_config("BOOL_VAR", false);

        let json = profile.to_json().expect("Should serialize to JSON");
        assert!(json.contains(r#""name": "test_profile""#));
        assert!(json.contains(r#""registry_name": "test_registry""#));
        assert!(json.contains(r#""BOOL_VAR": false"#));

        // Test round-trip
        let deserialized =
            SerializableProfile::from_json(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.name, profile.name);
        assert_eq!(deserialized.registry_name, profile.registry_name);
        assert_eq!(deserialized.config.len(), profile.config.len());
    }
}
