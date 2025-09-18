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

// src/serialization.rs
// Serialization support for MLX configuration profiles.
//
// Provides YAML and JSON serialization/deserialization for profiles,
// with proper validation and registry lookup during deserialization.

use crate::{error::MlxProfileError, profile::MlxConfigProfile};
use rpc::protos::mlx_device::SerializableMlxConfigProfile as SerializableMlxConfigProfilePb;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Serializable representation of an MLX configuration profile.
// This is the format used for YAML/JSON serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableProfile {
    // Profile name for identification and documentation
    pub name: String,
    // Registry name that this profile targets
    pub registry_name: String,
    // Optional description of what this profile does
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    // Variable configurations as name -> YAML value mappings
    pub config: HashMap<String, serde_yaml::Value>,
}

impl SerializableProfile {
    // Creates a new serializable profile.
    pub fn new<N: Into<String>, R: Into<String>>(name: N, registry_name: R) -> Self {
        Self {
            name: name.into(),
            registry_name: registry_name.into(),
            description: None,
            config: HashMap::new(),
        }
    }

    // Sets the description for this profile.
    pub fn with_description<D: Into<String>>(mut self, description: D) -> Self {
        self.description = Some(description.into());
        self
    }

    // Adds a variable configuration to this profile.
    pub fn with_config<K: Into<String>, V: Into<serde_yaml::Value>>(
        mut self,
        variable_name: K,
        value: V,
    ) -> Self {
        self.config.insert(variable_name.into(), value.into());
        self
    }

    // Converts this serializable profile to an MlxConfigProfile by resolving
    // the registry and validating all variable configurations.
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

    // Creates a SerializableProfile from an MlxConfigProfile.
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

    // from_yaml loads a profile from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, MlxProfileError> {
        serde_yaml::from_str(yaml).map_err(MlxProfileError::from)
    }

    // from_json loads a profile from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, MlxProfileError> {
        serde_json::from_str(json).map_err(MlxProfileError::from)
    }

    // from_toml loads a profile from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, MlxProfileError> {
        toml::from_str(toml_str).map_err(|e| MlxProfileError::serialization(e.to_string()))
    }

    // to_yaml serializes this profile to a YAML string.
    pub fn to_yaml(&self) -> Result<String, MlxProfileError> {
        serde_yaml::to_string(self).map_err(MlxProfileError::from)
    }

    // to_json serializes this profile to a JSON string.
    pub fn to_json(&self) -> Result<String, MlxProfileError> {
        serde_json::to_string_pretty(self).map_err(MlxProfileError::from)
    }

    // to_toml serializes this profile to a TOML string.
    pub fn to_toml(&self) -> Result<String, MlxProfileError> {
        toml::to_string_pretty(self).map_err(|e| MlxProfileError::serialization(e.to_string()))
    }

    // from_yaml_file loads a SerializableProfile from a YAML file,
    // leveraging our from_yaml constructor to make it happen.
    pub fn from_yaml_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, MlxProfileError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    // from_json_file loads a SerializableProfile from a JSON file,
    // leveraging our from_json constructor to make it happen.
    pub fn from_json_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, MlxProfileError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    // from_toml_file loads a SerializableProfile from a TOML file,
    // leveraging our from_toml constructor to make it happen.
    pub fn from_toml_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, MlxProfileError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    // to_yaml_file serializes a SerializableProfile to a YAML file,
    // leveraging our to_yaml method to make it happen.
    pub fn to_yaml_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), MlxProfileError> {
        let yaml = self.to_yaml()?;
        std::fs::write(path, yaml)?;
        Ok(())
    }

    // to_json_file serializes a SerializableProfile to a JSON file,
    // leveraging our to_json method to make it happen.
    pub fn to_json_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), MlxProfileError> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    // to_toml_file serializes a SerializableProfile to a TOML file,
    // leveraging our to_toml method to make it happen.
    pub fn to_toml_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), MlxProfileError> {
        let toml = self.to_toml()?;
        std::fs::write(path, toml)?;
        Ok(())
    }
}

// TryFrom implementation for converting from a protobuf to a SerializableProfile.
impl TryFrom<SerializableMlxConfigProfilePb> for SerializableProfile {
    type Error = MlxProfileError;

    fn try_from(proto: SerializableMlxConfigProfilePb) -> Result<Self, Self::Error> {
        let mut config = HashMap::new();

        // Convert protobuf string values back to serde_yaml::Value using serde_yaml.
        for (key, value_str) in proto.config {
            let yaml_value: serde_yaml::Value = serde_yaml::from_str(&value_str)?;
            config.insert(key, yaml_value);
        }

        Ok(Self {
            name: proto.name,
            registry_name: proto.registry_name,
            description: proto.description,
            config,
        })
    }
}

// TryFrom implementation for converting from a SerializableProfile to a protobuf.
impl TryFrom<&SerializableProfile> for SerializableMlxConfigProfilePb {
    type Error = MlxProfileError;

    fn try_from(profile: &SerializableProfile) -> Result<Self, Self::Error> {
        let mut config = HashMap::new();

        // Convert serde_yaml::Value to YAML string representations for protobuf.
        //
        // I make a mention of this in the mlx_device.proto file also, but when
        // I was defining the SerializableMlxConfigProfile message, I had a choice
        // of either making it a simple map<string, string>, or getting super
        // fancy and creating a special "oneof" type, and then instead making it
        // a map<string, special-oneof-type>, and then filling in the underlying
        // type + value there. The intent was to preserve some sense of type
        // safety within the proto itself. BUT, to be honest, it was kind of a lot
        // of extra effort just to have yet another layer of type safety; we
        // are already going to be translating the string value back into it's
        // expected type, so it doesn't really matter what the data looks like
        // when it's mashed into the protobuf.
        for (key, yaml_value) in &profile.config {
            let value_str = serde_yaml::to_string(yaml_value)
                .map_err(|e| MlxProfileError::serialization(e.to_string()))?;
            config.insert(key.clone(), value_str.trim().to_string());
        }

        Ok(Self {
            name: profile.name.clone(),
            registry_name: profile.registry_name.clone(),
            description: profile.description.clone(),
            config,
        })
    }
}

// Also implement TryFrom for owned SerializableProfile for convenience,
// since I'm guessing I'll probably end up wanting to do both.
impl TryFrom<SerializableProfile> for SerializableMlxConfigProfilePb {
    type Error = MlxProfileError;

    fn try_from(profile: SerializableProfile) -> Result<Self, Self::Error> {
        (&profile).try_into()
    }
}

// Converts an MlxConfigValue back to a simple YAML value for serialization.
fn config_value_to_yaml_value(
    config_value: &mlxconfig_variables::MlxConfigValue,
) -> Result<serde_yaml::Value, MlxProfileError> {
    Ok(config_value.value.to_yaml_value())
}
