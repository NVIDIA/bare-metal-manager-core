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

// src/value.rs
// This module is used for creating variable spec-backed values
// from an MlxConfigVariable, which is intended to be made "simple"
// by the introduction of a IntoMlxValue trait, so you can call
// var.with(<some-val>) and it will leverage the spec
// to create a properly-typed value.
use crate::spec::MlxVariableSpec;
use crate::variable::MlxConfigVariable;
use serde::{Deserialize, Serialize};
use std::fmt;

// MlxConfigValue defines a typed value for an mlxconfig variable.
// It contains both the variable definition and the actual value,
// ensuring type safety and providing validation context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlxConfigValue {
    // The variable backing this value, which includes
    // the underlying spec for the value type.
    pub variable: MlxConfigVariable,
    // The actual typed value, which has been
    // created based on the spec of the variable.
    pub value: MlxValueType,
}

// MlxValueType defines the actual typed values that can be stored
// for mlxconfig variables. Each variant corresponds to their
// respective MlxVariableSpec types. Array types use Vec<Option<T>>
// to support sparse arrays where some indices may be unset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum MlxValueType {
    Boolean(bool),
    Integer(i64),
    String(String),
    Binary(Vec<u8>),
    Bytes(Vec<u8>),
    Array(Vec<String>), // TODO(chet): Do I still need this?
    Enum(String),       // In this case the string is the selected enum.
    Preset(u8),
    // Array types support sparse arrays with Option<T> for partial configuration
    BooleanArray(Vec<Option<bool>>),
    IntegerArray(Vec<Option<i64>>),
    EnumArray(Vec<Option<String>>), // Selected values for each index.
    BinaryArray(Vec<Option<Vec<u8>>>),
    Opaque(Vec<u8>), // Just stores raw bytes for opaque types.
}

// MlxValueError defines errors that can occur when creating or
// validating configuration values.
#[derive(Debug, Clone, PartialEq)]
pub enum MlxValueError {
    // The provided value doesn't match the variable's spec type.
    TypeMismatch {
        expected: String,
        got: String,
    },
    // An enum value is not in the allowed options.
    InvalidEnumOption {
        value: String,
        allowed: Vec<String>,
    },
    // A preset value exceeds the maximum allowed.
    PresetOutOfRange {
        value: u8,
        max_allowed: u8,
    },
    // An array size doesn't match the expected size.
    ArraySizeMismatch {
        expected: usize,
        got: usize,
    },
    // An enum array contains invalid options.
    InvalidEnumArrayOption {
        position: usize,
        value: String,
        allowed: Vec<String>,
    },
    // A variable is read-only and cannot be modified.
    ReadOnlyVariable {
        variable_name: String,
    },
}

impl fmt::Display for MlxValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeMismatch { expected, got } => {
                write!(f, "Type mismatch: expected {expected}, got {got}")
            }
            Self::InvalidEnumOption { value, allowed } => {
                write!(
                    f,
                    "Invalid enum option '{}', allowed: [{}]",
                    value,
                    allowed.join(", ")
                )
            }
            Self::PresetOutOfRange { value, max_allowed } => {
                write!(f, "Preset value {value} exceeds maximum {max_allowed}")
            }
            Self::ArraySizeMismatch { expected, got } => {
                write!(f, "Array size mismatch: expected {expected}, got {got}")
            }
            Self::InvalidEnumArrayOption {
                position,
                value,
                allowed,
            } => {
                write!(
                    f,
                    "Invalid enum option '{value}' at position {position}, allowed: [{}]",
                    allowed.join(", ")
                )
            }
            Self::ReadOnlyVariable { variable_name } => {
                write!(f, "Variable '{variable_name}' is read-only")
            }
        }
    }
}

impl std::error::Error for MlxValueError {}

impl MlxConfigValue {
    // new creates a new MlxConfigValue with the provided
    // backing variable and value, performing validation
    // across the variable spec and value type to ensure
    // they match.
    pub fn new(variable: MlxConfigVariable, value: MlxValueType) -> Result<Self, MlxValueError> {
        let config_value = Self { variable, value };
        config_value.validate()?;
        Ok(config_value)
    }

    // validate validates that the value type matches the variable spec type.
    pub fn validate(&self) -> Result<(), MlxValueError> {
        self.validate_internal()
    }

    // validate_internal is the internal call to make sure a variable spec
    // matches (or is at least compatible with) the value type.
    fn validate_internal(&self) -> Result<(), MlxValueError> {
        match (&self.variable.spec, &self.value) {
            (MlxVariableSpec::Boolean, MlxValueType::Boolean(_)) => Ok(()),
            (MlxVariableSpec::Integer, MlxValueType::Integer(_)) => Ok(()),
            (MlxVariableSpec::String, MlxValueType::String(_)) => Ok(()),
            (MlxVariableSpec::Binary, MlxValueType::Binary(_)) => Ok(()),
            (MlxVariableSpec::Bytes, MlxValueType::Bytes(_)) => Ok(()),
            (MlxVariableSpec::Array, MlxValueType::Array(_)) => Ok(()),
            // For an enum spec, make sure the value from the enum value
            // type is a value in the spec options.
            (MlxVariableSpec::Enum { options }, MlxValueType::Enum(value)) => {
                if options.contains(value) {
                    Ok(())
                } else {
                    Err(MlxValueError::InvalidEnumOption {
                        value: value.clone(),
                        allowed: options.clone(),
                    })
                }
            }
            // For a preset spec, make sure the value is within the range,
            // as in, it doesn't go over the max value.
            (MlxVariableSpec::Preset { max_preset }, MlxValueType::Preset(value)) => {
                if *value <= *max_preset {
                    Ok(())
                } else {
                    Err(MlxValueError::PresetOutOfRange {
                        value: *value,
                        max_allowed: *max_preset,
                    })
                }
            }
            // For boolean arrays, make sure the list of values
            // matches the expected size of the array per the spec.
            // Note: sparse arrays use Option<bool> so we validate array length.
            (MlxVariableSpec::BooleanArray { size }, MlxValueType::BooleanArray(values)) => {
                if values.len() == *size {
                    Ok(())
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: values.len(),
                    })
                }
            }
            // For integer arrays, make sure the list of values
            // matches the expected size of the array per the spec.
            // Note: sparse arrays use Option<i64> so we validate array length.
            (MlxVariableSpec::IntegerArray { size }, MlxValueType::IntegerArray(values)) => {
                if values.len() == *size {
                    Ok(())
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: values.len(),
                    })
                }
            }
            // For enum arrays, first make sure the list of values
            // matches the expected size of the array per the spec.
            (MlxVariableSpec::EnumArray { options, size }, MlxValueType::EnumArray(values)) => {
                if values.len() != *size {
                    return Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: values.len(),
                    });
                }

                // ..and then validate that each option value provided
                // is an allowed option per the spec. Skip None values (sparse support).
                for (pos, value) in values.iter().enumerate() {
                    if let Some(enum_value) = value {
                        if !options.contains(enum_value) {
                            return Err(MlxValueError::InvalidEnumArrayOption {
                                position: pos,
                                value: enum_value.clone(),
                                allowed: options.clone(),
                            });
                        }
                    }
                }
                Ok(())
            }
            // For binary arrays, make sure the list of values
            // matches the expected size of the array per the spec.
            // Note: sparse arrays use Option<Vec<u8>> so we validate array length.
            (MlxVariableSpec::BinaryArray { size }, MlxValueType::BinaryArray(values)) => {
                if values.len() == *size {
                    Ok(())
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: values.len(),
                    })
                }
            }
            (MlxVariableSpec::Opaque, MlxValueType::Opaque(_)) => Ok(()),
            // For all other cases, report as a type mismatch.
            (spec, value) => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: format!("{value:?}"),
            }),
        }
    }

    // name returns the underlying variable name
    // backing the value.
    pub fn name(&self) -> &str {
        &self.variable.name
    }

    // description returns the underlying variable
    // description backing the value.
    pub fn description(&self) -> &str {
        &self.variable.description
    }

    // is the backing variable read-only?
    pub fn is_read_only(&self) -> bool {
        self.variable.read_only
    }

    // spec returns the backing spec
    // for the variable backing the
    // value. Inception.
    pub fn spec(&self) -> &MlxVariableSpec {
        &self.variable.spec
    }

    // to_display_string converts the value to something
    // that's human-readable; make it so this is used
    // by impl Display for MlxConfigValue.
    pub fn to_display_string(&self) -> String {
        match &self.value {
            MlxValueType::Boolean(b) => b.to_string(),
            MlxValueType::Integer(i) => i.to_string(),
            MlxValueType::String(s) => s.clone(),
            MlxValueType::Binary(bytes) => format!("0x{}", hex::encode(bytes)),
            MlxValueType::Bytes(bytes) => format!("{} bytes", bytes.len()),
            MlxValueType::Array(arr) => format!("[{}]", arr.join(", ")),
            MlxValueType::Enum(option) => option.clone(),
            MlxValueType::Preset(preset) => format!("preset_{preset}"),
            // Sparse array display: show None values as "-" or similar
            MlxValueType::BooleanArray(arr) => format!(
                "[{}]",
                arr.iter()
                    .map(|opt| opt
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "-".to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            MlxValueType::IntegerArray(arr) => format!(
                "[{}]",
                arr.iter()
                    .map(|opt| opt
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "-".to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            MlxValueType::EnumArray(arr) => format!(
                "[{}]",
                arr.iter()
                    .map(|opt| opt.as_ref().map(|s| s.as_str()).unwrap_or("-"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            MlxValueType::BinaryArray(arr) => {
                let set_count = arr.iter().filter(|opt| opt.is_some()).count();
                format!("[{} binary values, {} set]", arr.len(), set_count)
            }
            MlxValueType::Opaque(bytes) => format!("opaque({} bytes)", bytes.len()),
        }
    }
}

impl fmt::Display for MlxConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_display_string())
    }
}

// IntoMlxValue is the trait used for creating new MlxValueTypes
// based on the provided input value, which allows us to just
// call `var.with(<val>)` for anything and have it work.
pub trait IntoMlxValue {
    fn into_mlx_value_for_spec(self, spec: &MlxVariableSpec)
        -> Result<MlxValueType, MlxValueError>;
}

// Implement IntoMlxValue for bools, which gives
// us back an MlxValueType::Boolean with the provided
// bool.
impl IntoMlxValue for bool {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::Boolean => Ok(MlxValueType::Boolean(self)),
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "bool".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for i64, which gives
// us back an MlxValueType::Integer with the provided
// i64, or converts to other types as appropriate.
impl IntoMlxValue for i64 {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::Integer => Ok(MlxValueType::Integer(self)),
            MlxVariableSpec::Preset { max_preset } => {
                // Convert i64 to u8 for "preset" values.
                if self < 0 {
                    return Err(MlxValueError::TypeMismatch {
                        expected: "non-negative integer for preset".to_string(),
                        got: format!("{self}"),
                    });
                }
                if self > u8::MAX as i64 {
                    return Err(MlxValueError::TypeMismatch {
                        expected: "integer <= 255 for preset".to_string(),
                        got: format!("{self}"),
                    });
                }
                let preset_val = self as u8;
                if preset_val <= *max_preset {
                    Ok(MlxValueType::Preset(preset_val))
                } else {
                    Err(MlxValueError::PresetOutOfRange {
                        value: preset_val,
                        max_allowed: *max_preset,
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "i64".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for i32, which gives
// us back an MlxValueType::Integer with the provided
// i32.
impl IntoMlxValue for i32 {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        (self as i64).into_mlx_value_for_spec(spec)
    }
}

// Implement IntoMlxValue for u8, which, depending on
// the backing variable spec, will give us either an
// MlxValueType::Preset or MlxValueType::Integer.
impl IntoMlxValue for u8 {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::Preset { max_preset } => {
                if self <= *max_preset {
                    Ok(MlxValueType::Preset(self))
                } else {
                    Err(MlxValueError::PresetOutOfRange {
                        value: self,
                        max_allowed: *max_preset,
                    })
                }
            }
            MlxVariableSpec::Integer => Ok(MlxValueType::Integer(self as i64)),
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "u8".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Strings, which, depending on
// the backing variable spec, will give us either an
// MlxValueType::String or MlxValueType::Enum (with validation
// that the input enum option is valid for the spec).
//
// ...BUT, this also gets leveraged for JSON responses
// from mlxconfig, which always gives values back as
// quoted strings, so this also supports that, where,
// if the backing value type is anything else, we'll
// attempt to convert the string into the expected
// type.
impl IntoMlxValue for String {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        let trimmed = self.trim().to_string();

        match spec {
            MlxVariableSpec::String => Ok(MlxValueType::String(trimmed)),

            MlxVariableSpec::Enum { options } => {
                if options.contains(&trimmed) {
                    Ok(MlxValueType::Enum(trimmed))
                } else {
                    Err(MlxValueError::InvalidEnumOption {
                        value: trimmed,
                        allowed: options.clone(),
                    })
                }
            }

            MlxVariableSpec::Boolean => {
                // Handle various boolean representations from MLX
                match trimmed.to_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" | "enabled" => Ok(MlxValueType::Boolean(true)),
                    "false" | "0" | "no" | "off" | "disabled" => Ok(MlxValueType::Boolean(false)),
                    _ => Err(MlxValueError::TypeMismatch {
                        expected: "boolean string (true/false, 1/0, yes/no, etc.)".to_string(),
                        got: format!("'{trimmed}'"),
                    }),
                }
            }

            MlxVariableSpec::Integer => {
                trimmed
                    .parse::<i64>()
                    .map(MlxValueType::Integer)
                    .map_err(|_| MlxValueError::TypeMismatch {
                        expected: "integer string".to_string(),
                        got: format!("'{trimmed}'"),
                    })
            }

            MlxVariableSpec::Preset { max_preset } => {
                let preset_val =
                    trimmed
                        .parse::<u8>()
                        .map_err(|_| MlxValueError::TypeMismatch {
                            expected: "preset number string".to_string(),
                            got: format!("'{trimmed}'"),
                        })?;

                if preset_val <= *max_preset {
                    Ok(MlxValueType::Preset(preset_val))
                } else {
                    Err(MlxValueError::PresetOutOfRange {
                        value: preset_val,
                        max_allowed: *max_preset,
                    })
                }
            }

            MlxVariableSpec::Binary => {
                // Parse hex string like "0x1a2b3c" or just "1a2b3c"
                let hex_str = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                    &trimmed[2..]
                } else {
                    &trimmed
                };

                hex::decode(hex_str).map(MlxValueType::Binary).map_err(|_| {
                    MlxValueError::TypeMismatch {
                        expected: "hex string".to_string(),
                        got: format!("'{trimmed}'"),
                    }
                })
            }

            MlxVariableSpec::Bytes => {
                let hex_str = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                    &trimmed[2..]
                } else {
                    &trimmed
                };

                hex::decode(hex_str).map(MlxValueType::Bytes).map_err(|_| {
                    MlxValueError::TypeMismatch {
                        expected: "hex string".to_string(),
                        got: format!("'{trimmed}'"),
                    }
                })
            }

            MlxVariableSpec::Opaque => {
                let hex_str = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                    &trimmed[2..]
                } else {
                    &trimmed
                };

                hex::decode(hex_str).map(MlxValueType::Opaque).map_err(|_| {
                    MlxValueError::TypeMismatch {
                        expected: "hex string".to_string(),
                        got: format!("'{trimmed}'"),
                    }
                })
            }

            // Array types should not accept single strings
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("single value for {spec:?}"),
                got: "String (use Vec<String> for array types)".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for &str, which just wraps
// around the trait implementation for String.
impl IntoMlxValue for &str {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        self.to_string().into_mlx_value_for_spec(spec)
    }
}

// Implement IntoMlxValue for &String, which just wraps
// around the trait implementation for String.
impl IntoMlxValue for &String {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        self.clone().into_mlx_value_for_spec(spec)
    }
}

// Implement IntoMlxValue for Vec<u8>, which, depending on
// the backing variable spec, will give us a ::Binary, ::Bytes,
// or ::Opaque value type back.
impl IntoMlxValue for Vec<u8> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::Binary => Ok(MlxValueType::Binary(self)),
            MlxVariableSpec::Bytes => Ok(MlxValueType::Bytes(self)),
            MlxVariableSpec::Opaque => Ok(MlxValueType::Opaque(self)),
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<u8>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<bool>, which will validate
// the input array matches the required length of the
// underlying spec and convert to sparse array format.
impl IntoMlxValue for Vec<bool> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::BooleanArray { size } => {
                if self.len() == *size {
                    // Convert to sparse array format
                    let sparse_array: Vec<Option<bool>> = self.into_iter().map(Some).collect();
                    Ok(MlxValueType::BooleanArray(sparse_array))
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<bool>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<Option<bool>> to support
// direct sparse array input for boolean arrays.
impl IntoMlxValue for Vec<Option<bool>> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::BooleanArray { size } => {
                if self.len() == *size {
                    Ok(MlxValueType::BooleanArray(self))
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<Option<bool>>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<i64>, which will validate
// the input array matches the required length of the
// underlying spec and convert to sparse array format.
impl IntoMlxValue for Vec<i64> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::IntegerArray { size } => {
                if self.len() == *size {
                    // Convert to sparse array format
                    let sparse_array: Vec<Option<i64>> = self.into_iter().map(Some).collect();
                    Ok(MlxValueType::IntegerArray(sparse_array))
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<i64>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<Option<i64>> to support
// direct sparse array input for integer arrays.
impl IntoMlxValue for Vec<Option<i64>> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::IntegerArray { size } => {
                if self.len() == *size {
                    Ok(MlxValueType::IntegerArray(self))
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<Option<i64>>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<i32>, just wraps Vec<i64>.
impl IntoMlxValue for Vec<i32> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        // Convert Vec<i32> to Vec<i64> and delegate
        let i64_vec: Vec<i64> = self.into_iter().map(|i| i as i64).collect();
        i64_vec.into_mlx_value_for_spec(spec)
    }
}

// Implement IntoMlxValue for Vec<String>, which will validate
// the input array matches the required length of the
// underlying spec.
//
// ...AND, this also gets leveraged for JSON responses
// from mlxconfig, which always gives values back as
// quoted strings, so this also supports that, where,
// if the backing value type is an array of anything
// else, we'll attempt to convert the values into the
// expected type.
impl IntoMlxValue for Vec<String> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::Array => {
                // Generic string array - just trim each string
                let trimmed: Vec<String> = self.into_iter().map(|s| s.trim().to_string()).collect();
                Ok(MlxValueType::Array(trimmed))
            }

            MlxVariableSpec::BooleanArray { size } => {
                if self.len() != *size {
                    return Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    });
                }

                let mut sparse_array = Vec::with_capacity(*size);
                for (pos, s) in self.iter().enumerate() {
                    let trimmed = s.trim().to_lowercase();
                    if trimmed == "-" || trimmed.is_empty() {
                        // Support sparse array notation: "-" or empty means None
                        sparse_array.push(None);
                    } else {
                        let bool_val = match trimmed.as_str() {
                            "true" | "1" | "yes" | "on" | "enabled" => true,
                            "false" | "0" | "no" | "off" | "disabled" => false,
                            _ => {
                                return Err(MlxValueError::TypeMismatch {
                                    expected: "boolean string in array".to_string(),
                                    got: format!("'{s}' at position {pos}"),
                                })
                            }
                        };
                        sparse_array.push(Some(bool_val));
                    }
                }
                Ok(MlxValueType::BooleanArray(sparse_array))
            }

            MlxVariableSpec::IntegerArray { size } => {
                if self.len() != *size {
                    return Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    });
                }

                let mut sparse_array = Vec::with_capacity(*size);
                for (pos, s) in self.iter().enumerate() {
                    let trimmed = s.trim();
                    if trimmed == "-" || trimmed.is_empty() {
                        // Support sparse array notation: "-" or empty means None
                        sparse_array.push(None);
                    } else {
                        let int_val =
                            trimmed
                                .parse::<i64>()
                                .map_err(|_| MlxValueError::TypeMismatch {
                                    expected: "integer string in array".to_string(),
                                    got: format!("'{s}' at position {pos}"),
                                })?;
                        sparse_array.push(Some(int_val));
                    }
                }
                Ok(MlxValueType::IntegerArray(sparse_array))
            }

            MlxVariableSpec::EnumArray { options, size } => {
                if self.len() != *size {
                    return Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    });
                }

                let mut sparse_array = Vec::with_capacity(*size);
                for (pos, s) in self.iter().enumerate() {
                    let trimmed = s.trim();
                    if trimmed == "-" || trimmed.is_empty() {
                        // Support sparse array notation: "-" or empty means None
                        sparse_array.push(None);
                    } else {
                        let enum_value = trimmed.to_string();
                        if !options.contains(&enum_value) {
                            return Err(MlxValueError::InvalidEnumArrayOption {
                                position: pos,
                                value: enum_value,
                                allowed: options.clone(),
                            });
                        }
                        sparse_array.push(Some(enum_value));
                    }
                }
                Ok(MlxValueType::EnumArray(sparse_array))
            }

            MlxVariableSpec::BinaryArray { size } => {
                if self.len() != *size {
                    return Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    });
                }

                let mut sparse_array = Vec::with_capacity(*size);
                for (pos, s) in self.iter().enumerate() {
                    let trimmed = s.trim();
                    if trimmed == "-" || trimmed.is_empty() {
                        // Support sparse array notation: "-" or empty means None
                        sparse_array.push(None);
                    } else {
                        let hex_str = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                            &trimmed[2..]
                        } else {
                            trimmed
                        };

                        let bytes =
                            hex::decode(hex_str).map_err(|_| MlxValueError::TypeMismatch {
                                expected: "hex string in array".to_string(),
                                got: format!("'{s}' at position {pos}"),
                            })?;
                        sparse_array.push(Some(bytes));
                    }
                }
                Ok(MlxValueType::BinaryArray(sparse_array))
            }

            // Single value types should not accept arrays
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("array value for {spec:?}"),
                got: "Vec<String> (use String for single value types)".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<&str>, which just wraps
// the impl for Vec<String>.
impl IntoMlxValue for Vec<&str> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        let string_vec: Vec<String> = self.into_iter().map(|s| s.to_string()).collect();
        string_vec.into_mlx_value_for_spec(spec)
    }
}

// Implement IntoMlxValue for Vec<Option<String>> to support
// direct sparse array input for enum arrays.
impl IntoMlxValue for Vec<Option<String>> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::EnumArray { options, size } => {
                if self.len() != *size {
                    return Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    });
                }

                // Validate all Some values are valid enum options
                for (pos, opt_value) in self.iter().enumerate() {
                    if let Some(value) = opt_value {
                        if !options.contains(value) {
                            return Err(MlxValueError::InvalidEnumArrayOption {
                                position: pos,
                                value: value.clone(),
                                allowed: options.clone(),
                            });
                        }
                    }
                }
                Ok(MlxValueType::EnumArray(self))
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<Option<String>>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<Vec<u8>>, which makes
// sure the array is the required length based on the spec,
// and then populates as a dense array (converts to sparse format).
impl IntoMlxValue for Vec<Vec<u8>> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::BinaryArray { size } => {
                if self.len() == *size {
                    // Convert to sparse array format
                    let sparse_array: Vec<Option<Vec<u8>>> = self.into_iter().map(Some).collect();
                    Ok(MlxValueType::BinaryArray(sparse_array))
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<Vec<u8>>".to_string(),
            }),
        }
    }
}

// Implement IntoMlxValue for Vec<Option<Vec<u8>>> to support
// direct sparse array input for binary arrays.
impl IntoMlxValue for Vec<Option<Vec<u8>>> {
    fn into_mlx_value_for_spec(
        self,
        spec: &MlxVariableSpec,
    ) -> Result<MlxValueType, MlxValueError> {
        match spec {
            MlxVariableSpec::BinaryArray { size } => {
                if self.len() == *size {
                    Ok(MlxValueType::BinaryArray(self))
                } else {
                    Err(MlxValueError::ArraySizeMismatch {
                        expected: *size,
                        got: self.len(),
                    })
                }
            }
            _ => Err(MlxValueError::TypeMismatch {
                expected: format!("{spec:?}"),
                got: "Vec<Option<Vec<u8>>>".to_string(),
            }),
        }
    }
}

impl MlxValueType {
    pub fn is_array_type(&self) -> bool {
        matches!(
            self,
            MlxValueType::BooleanArray(_)
                | MlxValueType::IntegerArray(_)
                | MlxValueType::EnumArray(_)
                | MlxValueType::BinaryArray(_)
        )
    }

    pub fn get_set_indices(&self) -> Option<Vec<usize>> {
        fn extract_indices<T>(values: &[Option<T>]) -> Vec<usize> {
            values
                .iter()
                .enumerate()
                .filter_map(
                    |(index, opt)| {
                        if opt.is_some() {
                            Some(index)
                        } else {
                            None
                        }
                    },
                )
                .collect()
        }

        match self {
            MlxValueType::BooleanArray(values) => Some(extract_indices(values)),
            MlxValueType::IntegerArray(values) => Some(extract_indices(values)),
            MlxValueType::EnumArray(values) => Some(extract_indices(values)),
            MlxValueType::BinaryArray(values) => Some(extract_indices(values)),
            _ => None,
        }
    }
}
