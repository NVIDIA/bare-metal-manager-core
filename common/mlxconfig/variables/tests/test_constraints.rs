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

use mlxconfig_variables::{ConstraintValidationResult, DeviceInfo, RegistryTargetConstraints};

#[test]
fn test_device_info_builder_pattern() {
    let device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0")
        .with_fw_version("32.41.130");

    assert_eq!(device.device_type, Some("Bluefield3".to_string()));
    assert_eq!(device.part_number, Some("900-9D3D4-00EN-HA0".to_string()));
    assert_eq!(device.fw_version, Some("32.41.130".to_string()));
}

#[test]
fn test_device_info_default() {
    let device = DeviceInfo::default();
    assert!(device.device_type.is_none());
    assert!(device.part_number.is_none());
    assert!(device.fw_version.is_none());
}

#[test]
fn test_registry_target_constraints_builder_pattern() {
    let constraints = RegistryTargetConstraints::new()
        .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()])
        .with_fw_versions(vec!["32.41.130".to_string(), "32.42.100".to_string()]);

    assert_eq!(
        constraints.device_types,
        Some(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
    );
    assert_eq!(
        constraints.part_numbers,
        Some(vec!["900-9D3D4-00EN-HA0".to_string()])
    );
    assert_eq!(
        constraints.fw_versions,
        Some(vec!["32.41.130".to_string(), "32.42.100".to_string()])
    );
}

#[test]
fn test_registry_target_constraints_has_constraints() {
    let empty_constraints = RegistryTargetConstraints::new();
    assert!(!empty_constraints.has_constraints());

    let device_type_only =
        RegistryTargetConstraints::new().with_device_types(vec!["Bluefield3".to_string()]);
    assert!(device_type_only.has_constraints());

    let part_number_only =
        RegistryTargetConstraints::new().with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()]);
    assert!(part_number_only.has_constraints());

    let fw_version_only =
        RegistryTargetConstraints::new().with_fw_versions(vec!["32.41.130".to_string()]);
    assert!(fw_version_only.has_constraints());
}

#[test]
fn test_registry_target_constraints_is_empty() {
    let empty_constraints = RegistryTargetConstraints::new();
    assert!(empty_constraints.is_empty());

    let non_empty =
        RegistryTargetConstraints::new().with_device_types(vec!["Bluefield3".to_string()]);
    assert!(!non_empty.is_empty());
}

#[test]
fn test_constraint_validation_result_is_valid() {
    assert!(ConstraintValidationResult::Valid.is_valid());
    assert!(ConstraintValidationResult::Unconstrained.is_valid());
    assert!(!ConstraintValidationResult::Invalid {
        reasons: vec!["Test failure".to_string()]
    }
    .is_valid());
}

#[test]
fn test_constraint_validation_result_reasons() {
    let valid_result = ConstraintValidationResult::Valid;
    assert_eq!(valid_result.reasons(), Vec::<String>::new());

    let unconstrained_result = ConstraintValidationResult::Unconstrained;
    assert_eq!(unconstrained_result.reasons(), Vec::<String>::new());

    let invalid_result = ConstraintValidationResult::Invalid {
        reasons: vec!["Reason 1".to_string(), "Reason 2".to_string()],
    };
    assert_eq!(
        invalid_result.reasons(),
        vec!["Reason 1".to_string(), "Reason 2".to_string()]
    );
}

#[test]
fn test_serde_serialization_roundtrip() {
    let constraints = RegistryTargetConstraints::new()
        .with_device_types(vec!["Bluefield3".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()]);

    let json = serde_json::to_string(&constraints).expect("Serialization failed");
    let deserialized: RegistryTargetConstraints =
        serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(constraints.device_types, deserialized.device_types);
    assert_eq!(constraints.part_numbers, deserialized.part_numbers);
    assert_eq!(constraints.fw_versions, deserialized.fw_versions);
}

#[test]
fn test_device_info_serde_serialization_roundtrip() {
    let device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0")
        .with_fw_version("32.41.130");

    let json = serde_json::to_string(&device).expect("Serialization failed");
    let deserialized: DeviceInfo = serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(device.device_type, deserialized.device_type);
    assert_eq!(device.part_number, deserialized.part_number);
    assert_eq!(device.fw_version, deserialized.fw_version);
}

#[test]
fn test_constraint_validation_result_equality() {
    assert_eq!(
        ConstraintValidationResult::Valid,
        ConstraintValidationResult::Valid
    );
    assert_eq!(
        ConstraintValidationResult::Unconstrained,
        ConstraintValidationResult::Unconstrained
    );

    let invalid1 = ConstraintValidationResult::Invalid {
        reasons: vec!["Same reason".to_string()],
    };
    let invalid2 = ConstraintValidationResult::Invalid {
        reasons: vec!["Same reason".to_string()],
    };
    assert_eq!(invalid1, invalid2);

    let invalid3 = ConstraintValidationResult::Invalid {
        reasons: vec!["Different reason".to_string()],
    };
    assert_ne!(invalid1, invalid3);
}
