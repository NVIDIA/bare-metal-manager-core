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

use thiserror::Error;

use crate::runner::error::MlxRunnerError;
use crate::variables::value::MlxValueError;

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

#[cfg(test)]
mod coverage_tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    // discriminant maps an MlxProfileError to a stable &'static str tag so
    // tests can assert which variant was produced without needing PartialEq
    // (several variants wrap non-PartialEq errors like serde_json::Error).
    fn discriminant(error: &MlxProfileError) -> &'static str {
        match error {
            MlxProfileError::RegistryNotFound { .. } => "RegistryNotFound",
            MlxProfileError::VariableNotFound { .. } => "VariableNotFound",
            MlxProfileError::ValueValidation { .. } => "ValueValidation",
            MlxProfileError::ProfileValidation { .. } => "ProfileValidation",
            MlxProfileError::Serialization { .. } => "Serialization",
            MlxProfileError::YamlParsing { .. } => "YamlParsing",
            MlxProfileError::JsonParsing { .. } => "JsonParsing",
            MlxProfileError::TomlParsing { .. } => "TomlParsing",
            MlxProfileError::Runner { .. } => "Runner",
            MlxProfileError::Io { .. } => "Io",
        }
    }

    // The constructors each build one specific variant. Project to the
    // discriminant so we verify the constructor selects the right arm,
    // independent of the (non-PartialEq) payloads.
    #[test]
    fn constructors_select_the_right_variant() {
        check_values(
            [
                Check {
                    scenario: "registry_not_found -> RegistryNotFound",
                    input: MlxProfileError::registry_not_found("reg"),
                    expect: "RegistryNotFound",
                },
                Check {
                    scenario: "variable_not_found -> VariableNotFound",
                    input: MlxProfileError::variable_not_found("var", "reg"),
                    expect: "VariableNotFound",
                },
                Check {
                    scenario: "value_validation -> ValueValidation",
                    input: MlxProfileError::value_validation(
                        "var",
                        MlxValueError::TypeMismatch {
                            expected: "Integer".to_string(),
                            got: "bool".to_string(),
                        },
                    ),
                    expect: "ValueValidation",
                },
                Check {
                    scenario: "profile_validation -> ProfileValidation",
                    input: MlxProfileError::profile_validation("bad"),
                    expect: "ProfileValidation",
                },
                Check {
                    scenario: "serialization -> Serialization",
                    input: MlxProfileError::serialization("boom"),
                    expect: "Serialization",
                },
            ],
            |error| discriminant(&error),
        );
    }

    // The Display strings for the hand-built variants are fixed format
    // strings, so we can pin them exactly. The ValueValidation row also
    // exercises the nested MlxValueError Display ("Type mismatch: ...").
    #[test]
    fn constructors_render_their_display_strings() {
        check_values(
            [
                Check {
                    scenario: "RegistryNotFound Display",
                    input: MlxProfileError::registry_not_found("my_registry"),
                    expect: "Registry 'my_registry' not found in available registries".to_string(),
                },
                Check {
                    scenario: "VariableNotFound Display",
                    input: MlxProfileError::variable_not_found("my_var", "my_registry"),
                    expect: "Variable 'my_var' not found in registry 'my_registry'".to_string(),
                },
                Check {
                    scenario: "ValueValidation Display nests the MlxValueError",
                    input: MlxProfileError::value_validation(
                        "my_var",
                        MlxValueError::TypeMismatch {
                            expected: "Integer".to_string(),
                            got: "bool".to_string(),
                        },
                    ),
                    expect: "Value validation failed for variable 'my_var': \
                             Type mismatch: expected Integer, got bool"
                        .to_string(),
                },
                Check {
                    scenario: "ProfileValidation Display",
                    input: MlxProfileError::profile_validation("something went wrong"),
                    expect: "Profile validation failed: something went wrong".to_string(),
                },
                Check {
                    scenario: "Serialization Display",
                    input: MlxProfileError::serialization("could not serialize"),
                    expect: "Serialization error: could not serialize".to_string(),
                },
            ],
            |error| error.to_string(),
        );
    }

    // The generic Into<String> bounds accept both &str and String; confirm
    // both flavors flow through the constructors and land in Display.
    #[test]
    fn constructors_accept_str_and_string() {
        check_values(
            [
                Check {
                    scenario: "registry_not_found from &str",
                    input: MlxProfileError::registry_not_found("a"),
                    expect: "Registry 'a' not found in available registries".to_string(),
                },
                Check {
                    scenario: "registry_not_found from String",
                    input: MlxProfileError::registry_not_found("b".to_string()),
                    expect: "Registry 'b' not found in available registries".to_string(),
                },
                Check {
                    scenario: "profile_validation from String",
                    input: MlxProfileError::profile_validation("msg".to_string()),
                    expect: "Profile validation failed: msg".to_string(),
                },
            ],
            |error| error.to_string(),
        );
    }

    // Each From impl must select its matching variant. We build a real
    // wrapped error per source type, convert via Into, and assert the
    // resulting discriminant (the wrapped payloads are not PartialEq).
    #[test]
    fn from_impls_select_the_right_variant() {
        check_values(
            [
                Check {
                    scenario: "MlxValueError -> ValueValidation",
                    input: MlxProfileError::from(MlxValueError::ReadOnlyVariable {
                        variable_name: "ro".to_string(),
                    }),
                    expect: "ValueValidation",
                },
                Check {
                    scenario: "MlxRunnerError -> Runner",
                    input: MlxProfileError::from(MlxRunnerError::NoDeviceFound),
                    expect: "Runner",
                },
                Check {
                    scenario: "std::io::Error -> Io",
                    input: MlxProfileError::from(std::io::Error::other("disk gone")),
                    expect: "Io",
                },
                Check {
                    scenario: "serde_json::Error -> JsonParsing",
                    input: MlxProfileError::from(
                        serde_json::from_str::<i32>("not json").unwrap_err(),
                    ),
                    expect: "JsonParsing",
                },
                Check {
                    scenario: "serde_yaml::Error -> YamlParsing",
                    input: MlxProfileError::from(
                        serde_yaml::from_str::<i32>("{ : : invalid").unwrap_err(),
                    ),
                    expect: "YamlParsing",
                },
                Check {
                    scenario: "toml::de::Error -> TomlParsing",
                    input: MlxProfileError::from(
                        toml::from_str::<toml::Value>("= broken").unwrap_err(),
                    ),
                    expect: "TomlParsing",
                },
            ],
            |error| discriminant(&error),
        );
    }

    // The From<MlxValueError> impl tags the variable name as "unknown" and
    // nests the inner Display; pin the full rendered string to lock that
    // contract in place.
    #[test]
    fn from_value_error_uses_unknown_variable_name() {
        Check {
            scenario: "From<MlxValueError> Display uses 'unknown'",
            input: MlxProfileError::from(MlxValueError::PresetOutOfRange {
                value: 9,
                max_allowed: 5,
            }),
            expect: "Value validation failed for variable 'unknown': \
                     Preset value 9 exceeds maximum 5"
                .to_string(),
        }
        .check(|error| error.to_string());
    }

    // The `?`-style conversion path: a function returning MlxProfileError
    // that uses `?` on a fallible toml parse must surface TomlParsing. This
    // exercises the From<toml::de::Error> impl through real `?` desugaring.
    #[test]
    fn question_mark_conversions_propagate_the_right_variant() {
        fn parse_toml(raw: &str) -> Result<toml::Value, MlxProfileError> {
            let value: toml::Value = toml::from_str(raw)?;
            Ok(value)
        }

        fn parse_json(raw: &str) -> Result<serde_json::Value, MlxProfileError> {
            let value: serde_json::Value = serde_json::from_str(raw)?;
            Ok(value)
        }

        check_cases(
            [
                Case {
                    scenario: "valid toml yields",
                    input: "key = 1",
                    expect: Yields("TomlParsing-or-ok"),
                },
                Case {
                    scenario: "invalid toml fails as TomlParsing",
                    input: "= nope",
                    expect: FailsWith("TomlParsing"),
                },
            ],
            |raw| {
                parse_toml(raw)
                    .map(|_| "TomlParsing-or-ok")
                    .map_err(|error| discriminant(&error))
            },
        );

        check_cases(
            [
                Case {
                    scenario: "valid json yields",
                    input: "{}",
                    expect: Yields("JsonParsing-or-ok"),
                },
                Case {
                    scenario: "invalid json fails as JsonParsing",
                    input: "not json",
                    expect: FailsWith("JsonParsing"),
                },
            ],
            |raw| {
                parse_json(raw)
                    .map(|_| "JsonParsing-or-ok")
                    .map_err(|error| discriminant(&error))
            },
        );
    }
}
