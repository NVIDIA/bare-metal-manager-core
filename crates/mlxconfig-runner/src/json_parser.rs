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

// src/json_parser.rs
// JSON response parser for converting mlxconfig JSON output into typed
// structures with all of our super fancy proper variable/value validation
// and array (and/or sparse array) handling.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use mlxconfig_variables::{MlxConfigValue, MlxVariableRegistry, MlxVariableSpec};
use serde::{Deserialize, Serialize};

use crate::error::MlxRunnerError;
use crate::exec_options::ExecOptions;
use crate::result_types::{QueriedDeviceInfo, QueriedVariable, QueryResult};

// JsonResponseParser handles parsing of mlxconfig JSON responses
// and conversion to strongly-typed QueryResult structures.
pub struct JsonResponseParser<'a> {
    // registry is the registry containing variable definitions
    // for validation.
    registry: &'a MlxVariableRegistry,
    // options are the execution options provided by the
    // parent runner, which in this case is primarily used
    // by the JSON parser for logging control.
    options: &'a ExecOptions,
}

// JsonResponse represents the top-level structure of the
// mlxconfig JSON output, where there is a "device", and
// within that is everything else (including info about
// the device, as well as the actual variable settings
// themselves).
#[derive(Debug, Deserialize, Serialize)]
struct JsonResponse {
    #[serde(rename = "Device #1")]
    device: JsonDevice,
}

// JsonDevice is the one and only entry at the top level
// of a JsonResponse, containing the device information
// and all variable configuration (which lives in the
// tlv_configuration parameter).
#[derive(Debug, Deserialize, Serialize)]
struct JsonDevice {
    description: String,
    device: String,
    device_type: String,
    name: String,
    tlv_configuration: HashMap<String, JsonVariable>,
}

// JsonVariable represents a single variable's state in
// the mlxconfig JSON response. The tlv_configuration
// hashmap is a map of VAR_NAME -> JsonVariable, with
// all of these fields populated.
#[derive(Debug, Deserialize, Serialize)]
pub struct JsonVariable {
    // current_value is current value actually applied
    // and being used by the device.
    current_value: serde_json::Value,
    // default_value is the factory default value the
    // device comes with.
    default_value: serde_json::Value,
    // modified is if the next_value is different than
    // the default value.
    modified: bool,
    // next_value is the value that *will* be applied
    // to the card on next reboot. If we have applied
    // changes, but *haven't* rebooted, then we will
    // see that next_value != current_value.
    next_value: serde_json::Value,
    // read_only is if this is a read-only variable
    // supplied by the card, and can't actually be
    // modified by mlxconfig.
    read_only: bool,
}

// JsonValueField is used to specify which field to
// extract from a JsonVariable and convert into an
// MlxConfigValue.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum JsonValueField {
    Default,
    Current,
    Next,
}

impl<'a> JsonResponseParser<'a> {
    // new creates a new JSON parser with registry and options.
    pub fn new(registry: &'a MlxVariableRegistry, options: &'a ExecOptions) -> Self {
        Self { registry, options }
    }

    // parse_json_response parses a complete JSON response file from mlxconfig
    // into a QueryResult. It also validates that the device in the response
    // matches the expected device we provided, because if those don't match,
    // that's kinda sus, and we don't want to be modifying values on the wrong
    // card.
    pub fn parse_json_response(
        &self,
        json_path: &Path,
        expected_device: &str,
    ) -> Result<QueryResult, MlxRunnerError> {
        let content = fs::read_to_string(json_path)
            .map_err(|e| MlxRunnerError::temp_file_error(json_path.to_path_buf(), e))?;

        if self.options.log_json_output {
            println!("[JSON] Response content:\n{content}");
        }

        let json_response: JsonResponse = serde_json::from_str(&content)
            .map_err(|e| MlxRunnerError::json_parsing(content.clone(), e))?;

        // And now verify the device from the response matches
        // what we [thought we] queried -- if it doesn't match,
        // something is wonky.
        if json_response.device.device != expected_device {
            return Err(MlxRunnerError::DeviceMismatch {
                expected: expected_device.to_string(),
                actual: json_response.device.device,
            });
        }

        // Finally, parse variables from the tlv_configuration
        // field and pass back a Vec<QueriedVariable> with everything
        // converted into properly typed values and such.
        let variables = self.parse_variables(&json_response.device.tlv_configuration)?;

        Ok(QueryResult::new(
            QueriedDeviceInfo {
                device_id: Some(json_response.device.device),
                device_type: Some(json_response.device.device_type),
                part_number: Some(json_response.device.name),
                description: Some(json_response.device.description),
            },
            variables,
        ))
    }

    // parse_variables is the thing that actually parses all variables
    // from the tlv_configuration HashMap, handling both scalar variables
    // and array variables (technically with sparse array support, even
    // though mlxconfig really shouldn't be giving us incomplete array
    // sets back).
    pub fn parse_variables(
        &self,
        json_vars: &HashMap<String, JsonVariable>,
    ) -> Result<Vec<QueriedVariable>, MlxRunnerError> {
        let mut variables = Vec::new();
        let mut processed_arrays = std::collections::HashSet::new();

        for (json_name, json_var) in json_vars {
            // Check if this is an array element like "ARRAY[0]".
            if let Some((base_name, _)) = crate::traits::parse_array_index(json_name)? {
                // Skip if we already processed this array.
                if processed_arrays.contains(&base_name) {
                    continue;
                }
                // Otherwise insert it as being processed...
                processed_arrays.insert(base_name.clone());

                // ...and then fire off the array parser, which will
                // just go and grab each index to build a fully-populated
                // array variable (instead of incrementally building
                // arrays and then assembling at the end).
                if let Some(registry_var) = self.registry.get_variable(&base_name) {
                    let queried_var =
                        self.parse_array_variable(registry_var, json_vars, &base_name)?;
                    variables.push(queried_var);
                }
            } else {
                // Or just do a basic processing of a scalar variable.
                if let Some(registry_var) = self.registry.get_variable(json_name) {
                    let queried_var = self.parse_single_variable(registry_var, json_var)?;
                    variables.push(queried_var);
                }
            }
        }

        Ok(variables)
    }

    // parse_single_variable parses a single scalar (non-array) variable
    // from mlxconfig JSON output. Returns a fully populated QueriedVariable
    // with all value states.
    pub fn parse_single_variable(
        &self,
        registry_var: &mlxconfig_variables::MlxConfigVariable,
        json_var: &JsonVariable,
    ) -> Result<QueriedVariable, MlxRunnerError> {
        let current_value =
            self.json_value_to_config_value(registry_var, &json_var.current_value)?;
        let default_value =
            self.json_value_to_config_value(registry_var, &json_var.default_value)?;
        let next_value = self.json_value_to_config_value(registry_var, &json_var.next_value)?;

        Ok(QueriedVariable::new(
            registry_var.clone(),
            current_value,
            default_value,
            next_value,
            json_var.modified,
            json_var.read_only,
        ))
    }

    // parse_array_variable parses an array variable by collecting
    // all indices from the mlxconfig JSON output, and reconstructing
    // the array from all individual [index] entries. Technically
    // this builds a "sparse" array, but really, mlxconfig *should*
    // be giving us each index anyway.
    pub fn parse_array_variable(
        &self,
        registry_var: &mlxconfig_variables::MlxConfigVariable,
        json_vars: &HashMap<String, JsonVariable>,
        base_name: &str,
    ) -> Result<QueriedVariable, MlxRunnerError> {
        // Get array size from registry spec.
        let array_size = self.get_array_size(&registry_var.spec)?;

        // Build sparse arrays for current, default, and next values.
        let current_value = self.build_sparse_array_from_json(
            registry_var,
            json_vars,
            base_name,
            array_size,
            JsonValueField::Current,
        )?;
        let default_value = self.build_sparse_array_from_json(
            registry_var,
            json_vars,
            base_name,
            array_size,
            JsonValueField::Default,
        )?;
        let next_value = self.build_sparse_array_from_json(
            registry_var,
            json_vars,
            base_name,
            array_size,
            JsonValueField::Next,
        )?;

        // Collect modified/read_only status from any index.
        let mut modified = false;
        let mut read_only = false;

        for index in 0..array_size {
            let indexed_name = format!("{base_name}[{index}]");
            if let Some(json_var) = json_vars.get(&indexed_name) {
                if json_var.modified {
                    modified = true;
                }
                if json_var.read_only {
                    read_only = true;
                }
            }
        }

        Ok(QueriedVariable::new(
            registry_var.clone(),
            current_value,
            default_value,
            next_value,
            modified,
            read_only,
        ))
    }

    // build_sparse_array_from_json builds a sparse array MlxConfigValue
    // from mlxconfig JSON data for a given field within a JsonVariable,
    // i.e. the default, current, or next value; handles all of the array
    // types, does proper type conversion, etc.
    pub fn build_sparse_array_from_json(
        &self,
        registry_var: &mlxconfig_variables::MlxConfigVariable,
        json_vars: &HashMap<String, JsonVariable>,
        base_name: &str,
        array_size: usize,
        value_field: JsonValueField,
    ) -> Result<MlxConfigValue, MlxRunnerError> {
        match &registry_var.spec {
            MlxVariableSpec::BooleanArray { .. } => {
                let sparse_values = self.build_typed_sparse_array(
                    json_vars,
                    base_name,
                    array_size,
                    value_field,
                    |json_value| self.parse_bool_from_json(json_value),
                )?;
                registry_var.with(sparse_values).map_err(|e| {
                    MlxRunnerError::value_conversion(
                        base_name.to_string(),
                        "boolean array".to_string(),
                        e,
                    )
                })
            }
            MlxVariableSpec::IntegerArray { .. } => {
                let sparse_values = self.build_typed_sparse_array(
                    json_vars,
                    base_name,
                    array_size,
                    value_field,
                    |json_value| self.parse_int_from_json(json_value),
                )?;
                registry_var.with(sparse_values).map_err(|e| {
                    MlxRunnerError::value_conversion(
                        base_name.to_string(),
                        "integer array".to_string(),
                        e,
                    )
                })
            }
            MlxVariableSpec::EnumArray { .. } => {
                let sparse_values = self.build_typed_sparse_array(
                    json_vars,
                    base_name,
                    array_size,
                    value_field,
                    |json_value| self.parse_string_from_json(json_value),
                )?;
                registry_var.with(sparse_values).map_err(|e| {
                    MlxRunnerError::value_conversion(
                        base_name.to_string(),
                        "enum array".to_string(),
                        e,
                    )
                })
            }
            MlxVariableSpec::BinaryArray { .. } => {
                let sparse_values = self.build_typed_sparse_array(
                    json_vars,
                    base_name,
                    array_size,
                    value_field,
                    |json_value| self.parse_hex_from_json(json_value),
                )?;
                registry_var.with(sparse_values).map_err(|e| {
                    MlxRunnerError::value_conversion(
                        base_name.to_string(),
                        "binary array".to_string(),
                        e,
                    )
                })
            }
            _ => Err(MlxRunnerError::ValueConversion {
                variable_name: base_name.to_string(),
                value: "array".to_string(),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "array type".to_string(),
                    got: format!("{:?}", registry_var.spec),
                },
            }),
        }
    }

    // build_typed_sparse_array is a generic helper for building typed
    // sparse arrays from mlxconfig JSON data. It takes a parsing function
    // from the caller to convert the input JSON values to the target
    // output type.
    pub fn build_typed_sparse_array<T, F>(
        &self,
        json_vars: &HashMap<String, JsonVariable>,
        base_name: &str,
        array_size: usize,
        value_field: JsonValueField,
        parse_fn: F,
    ) -> Result<Vec<Option<T>>, MlxRunnerError>
    where
        F: Fn(&serde_json::Value) -> Result<T, MlxRunnerError>,
    {
        let mut sparse_values: Vec<Option<T>> = Vec::with_capacity(array_size);

        for index in 0..array_size {
            let indexed_name = format!("{base_name}[{index}]");

            if let Some(json_var) = json_vars.get(&indexed_name) {
                let json_value = self.get_json_field_value(json_var, value_field)?;
                let parsed_value = parse_fn(json_value)?;
                sparse_values.push(Some(parsed_value));
            } else {
                // Missing indices become None in sparse arrays, so this
                // handles cases where device doesn't return all array elements,
                // which like I mentioned above, *shouldn't* happen, but if it
                // does, we just handle it gracefully.
                sparse_values.push(None);
            }
        }

        Ok(sparse_values)
    }

    // json_value_to_config_value converts a JSON value to an
    // MlxConfigValue using the variable's spec, handling automatic
    // type conversion and validation.
    pub fn json_value_to_config_value(
        &self,
        registry_var: &mlxconfig_variables::MlxConfigVariable,
        json_value: &serde_json::Value,
    ) -> Result<MlxConfigValue, MlxRunnerError> {
        match json_value {
            serde_json::Value::String(_) => {
                let cleaned_string = self.parse_string_from_json(json_value)?;
                registry_var.with(cleaned_string).map_err(|e| {
                    MlxRunnerError::value_conversion(
                        registry_var.name.clone(),
                        "string".to_string(),
                        e,
                    )
                })
            }
            serde_json::Value::Number(_) => {
                let int_val = self.parse_int_from_json(json_value)?;
                registry_var.with(int_val).map_err(|e| {
                    MlxRunnerError::value_conversion(
                        registry_var.name.clone(),
                        "number".to_string(),
                        e,
                    )
                })
            }
            _ => Err(MlxRunnerError::ValueConversion {
                variable_name: registry_var.name.clone(),
                value: format!("{json_value:?}"),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "string or number".to_string(),
                    got: format!("{json_value:?}"),
                },
            }),
        }
    }

    // get_json_field_value extracts the appropriate field value
    // from a JsonVariable (default, current, or next), based on
    // the JsonVariable and JsonValueField provided.
    fn get_json_field_value<'b>(
        &self,
        json_var: &'b JsonVariable,
        value_field: JsonValueField,
    ) -> Result<&'b serde_json::Value, MlxRunnerError> {
        match value_field {
            JsonValueField::Current => Ok(&json_var.current_value),
            JsonValueField::Default => Ok(&json_var.default_value),
            JsonValueField::Next => Ok(&json_var.next_value),
        }
    }

    // parse_bool_from_json parses boolean values from mlxconfig JSON
    // responses. Handles format like "TRUE(1)" or "FALSE(0)" by stripping
    // parentheticals.
    fn parse_bool_from_json(&self, json_value: &serde_json::Value) -> Result<bool, MlxRunnerError> {
        match json_value {
            serde_json::Value::String(s) => {
                let cleaned = if s.contains('(') {
                    s.split('(').next().unwrap_or(s)
                } else {
                    s
                };

                match cleaned.to_lowercase().as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    _ => Err(MlxRunnerError::ValueConversion {
                        variable_name: "boolean".to_string(),
                        value: s.clone(),
                        error: mlxconfig_variables::MlxValueError::TypeMismatch {
                            expected: "boolean".to_string(),
                            got: s.clone(),
                        },
                    }),
                }
            }
            _ => Err(MlxRunnerError::ValueConversion {
                variable_name: "boolean".to_string(),
                value: format!("{json_value:?}"),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "string".to_string(),
                    got: format!("{json_value:?}"),
                },
            }),
        }
    }

    // parse_int_from_json parses integer values from mlxconfig
    // JSON responses.
    fn parse_int_from_json(&self, json_value: &serde_json::Value) -> Result<i64, MlxRunnerError> {
        match json_value {
            serde_json::Value::Number(n) => {
                n.as_i64().ok_or_else(|| MlxRunnerError::ValueConversion {
                    variable_name: "integer".to_string(),
                    value: n.to_string(),
                    error: mlxconfig_variables::MlxValueError::TypeMismatch {
                        expected: "integer".to_string(),
                        got: "float".to_string(),
                    },
                })
            }
            _ => Err(MlxRunnerError::ValueConversion {
                variable_name: "integer".to_string(),
                value: format!("{json_value:?}"),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "number".to_string(),
                    got: format!("{json_value:?}"),
                },
            }),
        }
    }

    // parse_string_from_json parses string values from mlxconfig
    // JSON responses. Handles format like "ENUM_VALUE(1)" by stripping
    // parentheticals.
    fn parse_string_from_json(
        &self,
        json_value: &serde_json::Value,
    ) -> Result<String, MlxRunnerError> {
        match json_value {
            serde_json::Value::String(s) => {
                let cleaned = if s.contains('(') {
                    s.split('(').next().unwrap_or(s).to_string()
                } else {
                    s.clone()
                };
                Ok(cleaned)
            }
            _ => Err(MlxRunnerError::ValueConversion {
                variable_name: "string".to_string(),
                value: format!("{json_value:?}"),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "string".to_string(),
                    got: format!("{json_value:?}"),
                },
            }),
        }
    }

    // parse_hex_from_json parses hex string values from mlxconfig
    // JSON responses. Handles both "0x1a2b3c" and "1a2b3c" formats.
    fn parse_hex_from_json(
        &self,
        json_value: &serde_json::Value,
    ) -> Result<Vec<u8>, MlxRunnerError> {
        match json_value {
            serde_json::Value::String(s) => {
                let hex_str = if s.starts_with("0x") || s.starts_with("0X") {
                    &s[2..]
                } else {
                    s
                };

                hex::decode(hex_str).map_err(|_| MlxRunnerError::ValueConversion {
                    variable_name: "binary".to_string(),
                    value: s.clone(),
                    error: mlxconfig_variables::MlxValueError::TypeMismatch {
                        expected: "hex string".to_string(),
                        got: s.clone(),
                    },
                })
            }
            _ => Err(MlxRunnerError::ValueConversion {
                variable_name: "binary".to_string(),
                value: format!("{json_value:?}"),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "string".to_string(),
                    got: format!("{json_value:?}"),
                },
            }),
        }
    }

    // get_array_size gets the array size from a
    // variable spec for doing array processing.
    fn get_array_size(&self, spec: &MlxVariableSpec) -> Result<usize, MlxRunnerError> {
        crate::traits::get_array_size_from_spec(spec)
    }
}
