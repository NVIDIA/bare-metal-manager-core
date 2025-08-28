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

use mlxconfig_variables::{
    ConstraintValidationResult, DeviceInfo, MlxConfigVariable, MlxVariableRegistry,
    MlxVariableSpec, RegistryTargetConstraints,
};

fn create_sample_variable(name: &str, description: &str, read_only: bool) -> MlxConfigVariable {
    MlxConfigVariable::builder()
        .name(name)
        .description(description)
        .read_only(read_only)
        .spec(MlxVariableSpec::Integer)
        .build()
}

fn create_sample_variables() -> Vec<MlxConfigVariable> {
    vec![
        create_sample_variable("cpu_frequency", "CPU frequency in MHz", false),
        create_sample_variable("memory_size", "Memory size in GB", true),
        create_sample_variable("cache_size", "Cache size in KB", false),
    ]
}

#[test]
fn test_mlx_variable_registry_builder_basic() {
    let variables = create_sample_variables();

    let registry = MlxVariableRegistry::builder()
        .name("Test Registry")
        .variables(variables.clone())
        .build();

    assert_eq!(registry.name, "Test Registry");
    assert_eq!(registry.variables.len(), 3);
    assert_eq!(registry.variables[0].name, "cpu_frequency");
    assert_eq!(registry.variables[1].name, "memory_size");
    assert_eq!(registry.variables[2].name, "cache_size");

    // Default constraints should be empty
    assert!(!registry.constraints.has_constraints());
}

#[test]
fn test_mlx_variable_registry_builder_with_constraints() {
    let variables = create_sample_variables();
    let constraints = RegistryTargetConstraints::new()
        .with_device_types(vec!["Bluefield3".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()]);

    let registry = MlxVariableRegistry::builder()
        .name("Constrained Registry")
        .variables(variables)
        .constraints(constraints.clone())
        .build();

    assert_eq!(registry.name, "Constrained Registry");
    assert_eq!(
        registry.constraints.device_types,
        Some(vec!["Bluefield3".to_string()])
    );
    assert_eq!(
        registry.constraints.part_numbers,
        Some(vec!["900-9D3D4-00EN-HA0".to_string()])
    );
}

#[test]
fn test_mlx_variable_registry_builder_with_constraint_shortcuts() {
    let variables = create_sample_variables();

    let registry = MlxVariableRegistry::builder()
        .name("Shortcut Constraints Registry")
        .variables(variables)
        .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()])
        .with_fw_versions(vec!["32.41.130".to_string()])
        .build();

    assert_eq!(
        registry.constraints.device_types,
        Some(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
    );
    assert_eq!(
        registry.constraints.part_numbers,
        Some(vec!["900-9D3D4-00EN-HA0".to_string()])
    );
    assert_eq!(
        registry.constraints.fw_versions,
        Some(vec!["32.41.130".to_string()])
    );
}

#[test]
fn test_mlx_variable_registry_builder_add_variable() {
    let registry = MlxVariableRegistry::builder()
        .name("Incremental Registry")
        .add_variable(create_sample_variable("var1", "First variable", false))
        .add_variable(create_sample_variable("var2", "Second variable", true))
        .build();

    assert_eq!(registry.variables.len(), 2);
    assert_eq!(registry.variables[0].name, "var1");
    assert_eq!(registry.variables[1].name, "var2");
}

#[test]
#[should_panic(expected = "name is required")]
fn test_mlx_variable_registry_builder_missing_name() {
    MlxVariableRegistry::builder()
        .variables(create_sample_variables())
        .build();
}

#[test]
fn test_validate_compatibility_unconstrained() {
    let registry = MlxVariableRegistry::builder()
        .name("Unconstrained Registry")
        .variables(create_sample_variables())
        .build();

    let device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0");

    let result = registry.validate_compatibility(&device);
    assert_eq!(result, ConstraintValidationResult::Unconstrained);
    assert!(result.is_valid());
}

#[test]
fn test_validate_compatibility_valid() {
    let registry = MlxVariableRegistry::builder()
        .name("Constrained Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()])
        .build();

    let device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0");

    let result = registry.validate_compatibility(&device);
    assert_eq!(result, ConstraintValidationResult::Valid);
    assert!(result.is_valid());
}

#[test]
fn test_validate_compatibility_invalid_device_type() {
    let registry = MlxVariableRegistry::builder()
        .name("Device Type Constrained Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .build();

    let device = DeviceInfo::new().with_device_type("ConnectX-7");

    let result = registry.validate_compatibility(&device);
    assert!(!result.is_valid());
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("Device type 'ConnectX-7' not in allowed types"));
            assert!(reasons[0].contains("Bluefield3"));
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_validate_compatibility_missing_device_type() {
    let registry = MlxVariableRegistry::builder()
        .name("Device Type Required Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .build();

    let device = DeviceInfo::new(); // No device type set

    let result = registry.validate_compatibility(&device);
    assert!(!result.is_valid());
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("Device type required but not provided"));
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_validate_compatibility_invalid_part_number() {
    let registry = MlxVariableRegistry::builder()
        .name("Part Number Constrained Registry")
        .variables(create_sample_variables())
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()])
        .build();

    let device = DeviceInfo::new().with_part_number("900-WRONG-PART-NUM");

    let result = registry.validate_compatibility(&device);
    assert!(!result.is_valid());
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 1);
            assert!(
                reasons[0].contains("Part number '900-WRONG-PART-NUM' not in allowed part numbers")
            );
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_validate_compatibility_invalid_fw_version() {
    let registry = MlxVariableRegistry::builder()
        .name("FW Version Constrained Registry")
        .variables(create_sample_variables())
        .with_fw_versions(vec!["32.41.130".to_string()])
        .build();

    let device = DeviceInfo::new().with_fw_version("32.40.100");

    let result = registry.validate_compatibility(&device);
    assert!(!result.is_valid());
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("Firmware version '32.40.100' not in allowed versions"));
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_validate_compatibility_multiple_constraints_all_invalid() {
    let registry = MlxVariableRegistry::builder()
        .name("Multi Constrained Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()])
        .with_fw_versions(vec!["32.41.130".to_string()])
        .build();

    let device = DeviceInfo::new()
        .with_device_type("ConnectX-7")
        .with_part_number("900-WRONG-PART")
        .with_fw_version("32.40.100");

    let result = registry.validate_compatibility(&device);
    assert!(!result.is_valid());
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 3);
            // Should have all three failure reasons
            assert!(reasons.iter().any(|r| r.contains("Device type")));
            assert!(reasons.iter().any(|r| r.contains("Part number")));
            assert!(reasons.iter().any(|r| r.contains("Firmware version")));
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_validate_compatibility_multiple_allowed_values() {
    let registry = MlxVariableRegistry::builder()
        .name("Multiple Values Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
        .with_fw_versions(vec!["32.41.130".to_string(), "32.42.100".to_string()])
        .build();

    // Test first valid combination
    let device1 = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_fw_version("32.41.130");

    let result1 = registry.validate_compatibility(&device1);
    assert_eq!(result1, ConstraintValidationResult::Valid);

    // Test second valid combination
    let device2 = DeviceInfo::new()
        .with_device_type("ConnectX-7")
        .with_fw_version("32.42.100");

    let result2 = registry.validate_compatibility(&device2);
    assert_eq!(result2, ConstraintValidationResult::Valid);

    // Test invalid device type with valid fw version
    let device3 = DeviceInfo::new()
        .with_device_type("InvalidDevice")
        .with_fw_version("32.41.130");

    let result = registry.validate_compatibility(&device3);
    assert!(!result.is_valid());
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("Device type 'InvalidDevice' not in allowed types"));
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_constraint_summary() {
    // Empty constraints
    let registry1 = MlxVariableRegistry::builder()
        .name("No Constraints")
        .variables(create_sample_variables())
        .build();

    assert_eq!(
        registry1.constraint_summary(),
        "No constraints (compatible with any device)"
    );

    // Single constraint
    let registry2 = MlxVariableRegistry::builder()
        .name("Device Type Only")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .build();

    assert_eq!(registry2.constraint_summary(), "Device types: [Bluefield3]");

    // Multiple constraints
    let registry3 = MlxVariableRegistry::builder()
        .name("Multiple Constraints")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
        .with_part_numbers(vec!["900-9D3D4-00EN-HA0".to_string()])
        .with_fw_versions(vec!["32.41.130".to_string(), "32.42.100".to_string()])
        .build();

    let summary = registry3.constraint_summary();
    assert!(summary.contains("Device types: [Bluefield3, ConnectX-7]"));
    assert!(summary.contains("Part numbers: [900-9D3D4-00EN-HA0]"));
    assert!(summary.contains("FW versions: [32.41.130, 32.42.100]"));
    assert!(summary.contains(";")); // Should contain separators
}

#[test]
fn test_mlx_variable_registry_serde_serialization() {
    let registry = MlxVariableRegistry::builder()
        .name("Test Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .build();

    let json = serde_json::to_string(&registry).expect("Serialization failed");
    let deserialized: MlxVariableRegistry =
        serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(registry.name, deserialized.name);
    assert_eq!(registry.variables.len(), deserialized.variables.len());
    assert_eq!(
        registry.constraints.device_types,
        deserialized.constraints.device_types
    );
}

#[test]
fn test_mlx_variable_registry_yaml_serialization() {
    let registry = MlxVariableRegistry::builder()
        .name("YAML Test Registry")
        .variables(vec![MlxConfigVariable::builder()
            .name("test_var")
            .description("Test variable")
            .read_only(false)
            .spec(MlxVariableSpec::Boolean)
            .build()])
        .build();

    let yaml = serde_yaml::to_string(&registry).expect("YAML serialization failed");
    let deserialized: MlxVariableRegistry =
        serde_yaml::from_str(&yaml).expect("YAML deserialization failed");

    assert_eq!(registry.name, deserialized.name);
    assert_eq!(registry.variables.len(), deserialized.variables.len());
    assert_eq!(registry.variables[0].name, deserialized.variables[0].name);
}

#[test]
fn test_empty_variables_list() {
    let registry = MlxVariableRegistry::builder()
        .name("Empty Registry")
        .variables(vec![])
        .build();

    assert_eq!(registry.variables.len(), 0);

    let device = DeviceInfo::new();
    let result = registry.validate_compatibility(&device);
    assert_eq!(result, ConstraintValidationResult::Unconstrained);
}

#[test]
fn test_constraint_validation_result_reasons() {
    let registry = MlxVariableRegistry::builder()
        .name("Test Registry")
        .variables(create_sample_variables())
        .with_device_types(vec!["Bluefield3".to_string()])
        .build();

    let device = DeviceInfo::new().with_device_type("WrongDevice");

    let result = registry.validate_compatibility(&device);
    let reasons = result.reasons();

    assert_eq!(reasons.len(), 1);
    assert!(reasons[0].contains("Device type 'WrongDevice' not in allowed types"));
}
