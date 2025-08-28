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

// src/registry.rs
// This defines code for the MlxVariableRegistry, which has a name,
// defines the variables that are a part of this registry, as well
// as any device constraints re: devices which are allowed to use
// this registry.

use crate::constraints::{ConstraintValidationResult, DeviceInfo, RegistryTargetConstraints};
use crate::variable::MlxConfigVariable;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlxVariableRegistry {
    pub name: String,
    pub variables: Vec<MlxConfigVariable>,
    #[serde(default, skip_serializing_if = "RegistryTargetConstraints::is_empty")]
    pub constraints: RegistryTargetConstraints,
}

impl MlxVariableRegistry {
    // validate_compatibility checks if this registry is compatible
    // with the given device info instance. It will return a result
    // saying if the device is valid, unconstrained, or, if invalid,
    // will list all of the reasons why we found it to be invalid.
    pub fn validate_compatibility(&self, device_info: &DeviceInfo) -> ConstraintValidationResult {
        let mut reasons = Vec::new();
        let mut has_constraints = false;

        // Check device type constraint.
        if let Some(allowed_device_types) = &self.constraints.device_types {
            has_constraints = true;
            if let Some(device_type) = &device_info.device_type {
                if !allowed_device_types.contains(device_type) {
                    reasons.push(format!(
                        "Device type '{}' not in allowed types: [{}]",
                        device_type,
                        allowed_device_types.join(", ")
                    ));
                }
            } else {
                reasons.push("Device type required but not provided".to_string());
            }
        }

        // Check part number constraint.
        if let Some(allowed_part_numbers) = &self.constraints.part_numbers {
            has_constraints = true;
            if let Some(part_number) = &device_info.part_number {
                if !allowed_part_numbers.contains(part_number) {
                    reasons.push(format!(
                        "Part number '{}' not in allowed part numbers: [{}]",
                        part_number,
                        allowed_part_numbers.join(", ")
                    ));
                }
            } else {
                reasons.push("Part number required but not provided".to_string());
            }
        }

        // Check firmware version constraint.
        if let Some(allowed_fw_versions) = &self.constraints.fw_versions {
            has_constraints = true;
            if let Some(fw_version) = &device_info.fw_version {
                if !allowed_fw_versions.contains(fw_version) {
                    reasons.push(format!(
                        "Firmware version '{}' not in allowed versions: [{}]",
                        fw_version,
                        allowed_fw_versions.join(", ")
                    ));
                }
            } else {
                reasons.push("Firmware version required but not provided".to_string());
            }
        }

        if !has_constraints {
            ConstraintValidationResult::Unconstrained
        } else if reasons.is_empty() {
            ConstraintValidationResult::Valid
        } else {
            ConstraintValidationResult::Invalid { reasons }
        }
    }

    // constraint_summary returns a string summary of the
    // constraints for this registry (mainly for CLI purposes).
    pub fn constraint_summary(&self) -> String {
        let mut parts = Vec::new();

        if let Some(device_types) = &self.constraints.device_types {
            parts.push(format!("Device types: [{}]", device_types.join(", ")));
        }

        if let Some(part_numbers) = &self.constraints.part_numbers {
            parts.push(format!("Part numbers: [{}]", part_numbers.join(", ")));
        }

        if let Some(fw_versions) = &self.constraints.fw_versions {
            parts.push(format!("FW versions: [{}]", fw_versions.join(", ")));
        }

        if parts.is_empty() {
            "No constraints (compatible with any device)".to_string()
        } else {
            parts.join("; ")
        }
    }

    // builder returns a new MlxVariableRegistryBuilder instance, used
    // for building a new registry. This is generally in existence to
    // support our build.rs script, making it a little easier for how
    // we build things.
    pub fn builder() -> MlxVariableRegistryBuilder {
        MlxVariableRegistryBuilder::new()
    }
}

// MlxVariableRegistryBuilder is used for building a shiny new
// MlxVariableRegistry instance. This is generally in existence to
// support our build.rs script, making it a little easier for how
// we build things.
pub struct MlxVariableRegistryBuilder {
    name: Option<String>,
    variables: Vec<MlxConfigVariable>,
    constraints: RegistryTargetConstraints,
}

impl Default for MlxVariableRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MlxVariableRegistryBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            variables: Vec::new(),
            constraints: RegistryTargetConstraints::default(),
        }
    }

    pub fn name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn variables(mut self, variables: Vec<MlxConfigVariable>) -> Self {
        self.variables = variables;
        self
    }

    pub fn add_variable(mut self, variable: MlxConfigVariable) -> Self {
        self.variables.push(variable);
        self
    }

    pub fn constraints(mut self, constraints: RegistryTargetConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    pub fn with_device_types<T: Into<Vec<String>>>(mut self, device_types: T) -> Self {
        self.constraints.device_types = Some(device_types.into());
        self
    }

    pub fn with_part_numbers<T: Into<Vec<String>>>(mut self, part_numbers: T) -> Self {
        self.constraints.part_numbers = Some(part_numbers.into());
        self
    }

    pub fn with_fw_versions<T: Into<Vec<String>>>(mut self, fw_versions: T) -> Self {
        self.constraints.fw_versions = Some(fw_versions.into());
        self
    }

    pub fn build(self) -> MlxVariableRegistry {
        MlxVariableRegistry {
            name: self.name.expect("name is required"),
            variables: self.variables,
            constraints: self.constraints,
        }
    }
}
