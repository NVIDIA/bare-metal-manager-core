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

// src/error.rs
// Error types for mlxconfig-profile. Includes various
// implementations for working with error types across
// the other mlxconfig-* crates.

use mlxconfig_runner::MlxRunnerError;
use mlxconfig_variables::MlxValueError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MlxProfileError {
    // RegistryNotFound is returned when a registry configured
    // to be used with the profile is not found.
    #[error("Registry '{registry_name}' not found in available registries")]
    RegistryNotFound { registry_name: String },

    // VariableNotFound is returned when a mapped
    // variable for the profile is not found in
    // the configured registry.
    #[error("Variable '{variable_name}' not found in registry '{registry_name}'")]
    VariableNotFound {
        variable_name: String,
        registry_name: String,
    },

    // ValueValidation is returned when a given MlxConfigValue
    // fails validation. Generally speaking this shouldn't really
    // happen, unless someone hand-creates a value outside of
    // the constructor.
    #[error("Value validation failed for variable '{variable_name}': {error}")]
    ValueValidation {
        variable_name: String,
        error: MlxValueError,
    },

    // ProfileValidation is returned when validation of the
    // profile fails, which is likely when validation of
    // a value within the profile fails. Again, it shouldn't
    // really happen, but it's good to check just incase!
    #[error("Profile validation failed: {message}")]
    ProfileValidation { message: String },

    // Serialization is returned when there is a serialization
    // error while attempting to serialize the profile out to
    // JSON or YAML.
    #[error("Serialization error: {error}")]
    Serialization { error: String },

    // YamlParsing is returned when there is an error parsing
    // a profile (as YAML) to deserialize back into a profile.
    #[error("YAML parsing error: {error}")]
    YamlParsing { error: serde_yaml::Error },

    // JsonParsing is returned when there is an error parsing
    // a profile (as JSON) to deserialize back into a profile.
    #[error("JSON parsing error: {error}")]
    JsonParsing { error: serde_json::Error },

    #[error("TOML parsing error: {error}")]
    TomlParsing { error: toml::de::Error },

    // Runner is returned when the underlying mlxconfig-runner
    // returns an error while trying to sync or compare.
    #[error("MLX runner error: {error}")]
    Runner { error: MlxRunnerError },

    // Io is returned for a general I/O error.
    #[error("I/O error: {error}")]
    Io { error: std::io::Error },
}

impl From<toml::de::Error> for MlxProfileError {
    fn from(error: toml::de::Error) -> Self {
        Self::TomlParsing { error }
    }
}

impl MlxProfileError {
    // registry_not_found creates a registry not found error.
    pub fn registry_not_found<T: Into<String>>(registry_name: T) -> Self {
        Self::RegistryNotFound {
            registry_name: registry_name.into(),
        }
    }

    // variable_not_found creates a variable not found error.
    pub fn variable_not_found<T: Into<String>, R: Into<String>>(
        variable_name: T,
        registry_name: R,
    ) -> Self {
        Self::VariableNotFound {
            variable_name: variable_name.into(),
            registry_name: registry_name.into(),
        }
    }

    // value_validation creates a value validation error.
    pub fn value_validation<T: Into<String>>(variable_name: T, error: MlxValueError) -> Self {
        Self::ValueValidation {
            variable_name: variable_name.into(),
            error,
        }
    }

    // profile_validation creates a profile validation error.
    pub fn profile_validation<T: Into<String>>(message: T) -> Self {
        Self::ProfileValidation {
            message: message.into(),
        }
    }

    // serialization creates a serialization error.
    pub fn serialization<T: Into<String>>(error: T) -> Self {
        Self::Serialization {
            error: error.into(),
        }
    }
}

impl From<MlxRunnerError> for MlxProfileError {
    fn from(error: MlxRunnerError) -> Self {
        Self::Runner { error }
    }
}

impl From<MlxValueError> for MlxProfileError {
    fn from(error: MlxValueError) -> Self {
        Self::ValueValidation {
            variable_name: "unknown".to_string(),
            error,
        }
    }
}

impl From<serde_yaml::Error> for MlxProfileError {
    fn from(error: serde_yaml::Error) -> Self {
        Self::YamlParsing { error }
    }
}

impl From<serde_json::Error> for MlxProfileError {
    fn from(error: serde_json::Error) -> Self {
        Self::JsonParsing { error }
    }
}

impl From<std::io::Error> for MlxProfileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io { error }
    }
}
