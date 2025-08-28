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

// src/constraints.rs
// This file defines types used for setting registry constraints,
// which is how we limit certain MlxVariableRegistry instances to only
// be valid for certain hardware (based on type, part number, and
// firmware versions).

use serde::{Deserialize, Serialize};

// RegistryTargetConstraints define which devices (including the device
// type and/or part number and/or firmware version) a given registry
// is compatible with. The more constraints, the more restrictive.
//
// For example, there may be a registry that works with Bluefield-3
// DPUs, but not SuperNICs or CX8 cards.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryTargetConstraints {
    // device_types list valid device types (e.g., "Bluefield3",
    // "ConnectX-7", etc).
    pub device_types: Option<Vec<String>>,
    // part_numbers list valid part numbers for a given
    // registry (e.g., "900-9D3D4-00EN-HA0").
    pub part_numbers: Option<Vec<String>>,
    // fw_versions list valid firmware versions (e.g., "32.41.130").
    pub fw_versions: Option<Vec<String>>,
}

// DeviceInfo is a small struct used to store device information
// used for constraint checking against RegistryTargetConstraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_type: Option<String>,
    pub part_number: Option<String>,
    pub fw_version: Option<String>,
}

// ConstraintValidationResult containts the result of a
// constraint validation check.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstraintValidationResult {
    // Valid means the device passed the constraints.
    Valid,
    // Invalid means the device failed the constraints.
    Invalid { reasons: Vec<String> },
    // Unconstrained means there were no constraints, and
    // the device is free to go on.
    Unconstrained,
}

impl ConstraintValidationResult {
    // is_valid is a simplification to let the caller know if
    // the device is good to go or not (ignoring the more specific
    // valid vs. unconstrained).
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            ConstraintValidationResult::Valid | ConstraintValidationResult::Unconstrained
        )
    }

    // reasons returns a list of reasons why the device
    // failed constraint validations.
    pub fn reasons(&self) -> Vec<String> {
        match self {
            ConstraintValidationResult::Invalid { reasons } => reasons.clone(),
            _ => Vec::new(),
        }
    }
}

impl DeviceInfo {
    // new initializes a new empty DeviceInfo instance.
    pub fn new() -> Self {
        Self {
            device_type: None,
            part_number: None,
            fw_version: None,
        }
    }

    // with_device_type is a builder for a new DeviceInfo
    // instance to set a device type.
    pub fn with_device_type<T: Into<String>>(mut self, device_type: T) -> Self {
        self.device_type = Some(device_type.into());
        self
    }

    // with_part_number is a builder for a new DeviceInfo
    // instance to set a part number.
    pub fn with_part_number<T: Into<String>>(mut self, part_number: T) -> Self {
        self.part_number = Some(part_number.into());
        self
    }

    // with_fw_version is a builder for a new DeviceInfo
    // instance to set a firmware version.
    pub fn with_fw_version<T: Into<String>>(mut self, fw_version: T) -> Self {
        self.fw_version = Some(fw_version.into());
        self
    }
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryTargetConstraints {
    // new initializes a new empty RegistryTargetConstraints instance.
    pub fn new() -> Self {
        Self::default()
    }

    // with_device_types is a builder for a new RegistryTargetConstraints
    // instance, used to set the constrained device types.
    pub fn with_device_types<T: Into<Vec<String>>>(mut self, device_types: T) -> Self {
        self.device_types = Some(device_types.into());
        self
    }

    // with_part_numbers is a builder for a new RegistryTargetConstraints
    // instance, used to set the constrained part numbers.
    pub fn with_part_numbers<T: Into<Vec<String>>>(mut self, part_numbers: T) -> Self {
        self.part_numbers = Some(part_numbers.into());
        self
    }

    // with_fw_versions is a builder for a new RegistryTargetConstraints
    // instance, used to set the constrained firmware versions.
    pub fn with_fw_versions<T: Into<Vec<String>>>(mut self, fw_versions: T) -> Self {
        self.fw_versions = Some(fw_versions.into());
        self
    }

    // has_constraints checks if any constraints are defined.
    pub fn has_constraints(&self) -> bool {
        self.device_types.is_some() || self.part_numbers.is_some() || self.fw_versions.is_some()
    }

    // is_empty checks if the constraints struct is completely
    // empty (for serde's skip condition).
    pub fn is_empty(&self) -> bool {
        !self.has_constraints()
    }
}
