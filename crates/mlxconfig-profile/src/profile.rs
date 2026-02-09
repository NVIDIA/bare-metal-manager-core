/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// src/profile.rs
// Defines the main MlxConfigProfile type and supporting
// implementation for our  mlxconfig-profile crate.

use std::collections::HashMap;
use std::path::Path;

use mlxconfig_runner::{ComparisonResult, ExecOptions, MlxConfigRunner, SyncResult};
use mlxconfig_variables::{IntoMlxValue, MlxConfigValue, MlxVariableRegistry};
use serde::{Deserialize, Serialize};

use crate::error::MlxProfileError;
use crate::serialization::SerializableProfile;

// MlxConfigProfile is a configuration profile that defines a complete set of
// variable values to apply to a device (DPU, SuperNIC, etc) -- any device whose
// configuration is controlled via `mlxconfig`. Every profile is backed by a
// given MlxVariableRegistry, which defines the variable types known to that
// registry, and what device(s) those variables are valid for. You can then
// define a profile of "expected" configuration, and then compare and/or sync
// the profile to the device (which uses mlxconfig-runner behind the scenes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlxConfigProfile {
    // name is the profile name.
    pub name: String,
    // registry is the target registry that defines the variables and
    // device filters available to this profile.
    pub registry: MlxVariableRegistry,
    // description is an optional description for this profile, which
    // will probably come in handy for site operators.
    pub description: Option<String>,
    // config_values are the values to set on the device. Each value
    // will be verified to exist in the backing registry.
    pub config_values: Vec<MlxConfigValue>,
    // config_lookup is an internally-managed hashmap to look up a
    // variable by name. The value is the index into `config_values`.
    #[serde(skip)]
    config_lookup: HashMap<String, usize>,
}

impl MlxConfigProfile {
    // new creates a new configuration profile.
    pub fn new<N: Into<String>>(name: N, registry: MlxVariableRegistry) -> Self {
        Self {
            name: name.into(),
            registry,
            description: None,
            config_values: Vec::new(),
            config_lookup: HashMap::new(),
        }
    }

    // with_description sets a description for this profile.
    pub fn with_description<D: Into<String>>(mut self, description: D) -> Self {
        self.description = Some(description.into());
        self
    }

    // with adds a variable setting to this profile, leveraging all of
    // the trait implementations that exist for backing specs, so you
    // should be able to toss the value up in most formats, and we'll
    // make sure it is properly typed according to the spec for the variable.
    pub fn with<T: IntoMlxValue>(
        self,
        variable_name: &str,
        value: T,
    ) -> Result<Self, MlxProfileError> {
        let variable = self.registry.get_variable(variable_name).ok_or_else(|| {
            MlxProfileError::variable_not_found(variable_name, &self.registry.name)
        })?;

        let config_value = variable
            .with(value)
            .map_err(|error| MlxProfileError::value_validation(variable_name, error))?;

        // NOTE(chet): I'm doing this to feed the new MlxConfigValue
        // through the same codepath that we use to feed MlxConfigValues
        // in. Technically it's inefficient since we end up looking up
        // the variable in the registry again, but it also means adding
        // a variable follows the same codepath that eventually updates
        // internal data structures.
        self.with_value(config_value)
    }

    // with_value adds a pre-built MlxConfigValue to this profile.
    // The value must exist in the backing registry.
    pub fn with_value(mut self, config_value: MlxConfigValue) -> Result<Self, MlxProfileError> {
        if self.registry.get_variable(config_value.name()).is_none() {
            return Err(MlxProfileError::variable_not_found(
                config_value.name(),
                &self.registry.name,
            ));
        }

        self.add_config_value(config_value);
        Ok(self)
    }

    // add_config_value is an internal method to add a config value
    // to the profile and update the lookup map.
    fn add_config_value(&mut self, config_value: MlxConfigValue) {
        let name = config_value.name().to_string();

        // Check if we already have this variable configured.
        if let Some(&existing_index) = self.config_lookup.get(&name) {
            // Replace the existing configuration in the same
            // index, leaving the config lookup map untouched.
            self.config_values[existing_index] = config_value;
        } else {
            // ..or not, and just add the new one.
            let index = self.config_values.len();
            self.config_values.push(config_value);
            self.config_lookup.insert(name, index);
        }
    }

    // get_variable returns a configured variable value by name.
    pub fn get_variable(&self, name: &str) -> Option<&MlxConfigValue> {
        self.config_lookup
            .get(name)
            .and_then(|&index| self.config_values.get(index))
    }

    // variable_names returns a list of all configured variable
    // names in this profile.
    pub fn variable_names(&self) -> Vec<&str> {
        self.config_values.iter().map(|cv| cv.name()).collect()
    }

    // variable_count returns the number of variables configured
    // in this profile.
    pub fn variable_count(&self) -> usize {
        self.config_values.len()
    }

    // validate validates the entire profile for internal consistency,
    // including validation of each stored MlxConfigValue.
    pub fn validate(&self) -> Result<(), MlxProfileError> {
        if self.config_values.is_empty() {
            return Err(MlxProfileError::profile_validation(
                "Profile contains no variable configurations",
            ));
        }

        for config_value in &self.config_values {
            config_value
                .validate()
                .map_err(|error| MlxProfileError::value_validation(config_value.name(), error))?;
        }

        Ok(())
    }

    // compare compares this profile against the current device state.
    pub fn compare(
        &self,
        device: &str,
        options: Option<ExecOptions>,
    ) -> Result<ComparisonResult, MlxProfileError> {
        // First, validate the profile.
        self.validate()?;

        // Then, create the runner with the registry and options.
        let runner = if let Some(opts) = options {
            MlxConfigRunner::with_options(device.to_string(), self.registry.clone(), opts)
        } else {
            MlxConfigRunner::new(device.to_string(), self.registry.clone())
        };

        // And finally, perform the comparison!
        let comparison_result = runner.compare(&self.config_values)?;
        Ok(comparison_result)
    }

    // sync synchronizes this profile to the specified device, applying any
    // necessary changes.
    pub fn sync(
        &self,
        device: &str,
        options: Option<ExecOptions>,
    ) -> Result<SyncResult, MlxProfileError> {
        // First, validate the profile.
        self.validate()?;

        // Then, create the runner with the registry and options.
        let runner = if let Some(opts) = options {
            MlxConfigRunner::with_options(device.to_string(), self.registry.clone(), opts)
        } else {
            MlxConfigRunner::new(device.to_string(), self.registry.clone())
        };

        // And finally, perform the sync!
        let sync_result = runner.sync(&self.config_values)?;
        Ok(sync_result)
    }

    // from_yaml_file loads a profile from a YAML file path.
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Self, MlxProfileError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    // from_yaml loads a profile from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, MlxProfileError> {
        let serializable = SerializableProfile::from_yaml(yaml)?;
        serializable.into_profile()
    }

    // from_json_file lads a profile from a JSON file path.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, MlxProfileError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    // from_json loads a profile from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, MlxProfileError> {
        let serializable = SerializableProfile::from_json(json)?;
        serializable.into_profile()
    }

    // to_yaml_file serializes + writes this profile to a YAML file path.
    pub fn to_yaml_file<P: AsRef<Path>>(&self, path: P) -> Result<(), MlxProfileError> {
        let yaml = self.to_yaml()?;
        std::fs::write(path, yaml)?;
        Ok(())
    }

    // to_yaml converts this profile to a YAML string.
    pub fn to_yaml(&self) -> Result<String, MlxProfileError> {
        let serializable = SerializableProfile::from_profile(self)?;
        serializable.to_yaml()
    }

    // to_json_file serializes + writes this profile to a JSON file path.
    pub fn to_json_file<P: AsRef<Path>>(&self, path: P) -> Result<(), MlxProfileError> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    // to_json converts this profile to a JSON string.
    pub fn to_json(&self) -> Result<String, MlxProfileError> {
        let serializable = SerializableProfile::from_profile(self)?;
        serializable.to_json()
    }

    // summary creates a summary string describing this profile,
    // mainly used for integrating with the CLI reference example.
    pub fn summary(&self) -> String {
        match &self.description {
            Some(desc) => format!(
                "Profile '{}': {} - {} variables for registry '{}'",
                self.name,
                desc,
                self.config_values.len(),
                self.registry.name,
            ),
            None => format!(
                "Profile '{}': {} variables for registry '{}'",
                self.name,
                self.config_values.len(),
                self.registry.name,
            ),
        }
    }
}
