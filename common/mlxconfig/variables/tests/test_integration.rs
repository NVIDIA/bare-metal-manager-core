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

// tests/integration_tests.rs
// Integration tests that test the entire system working together

use mlxconfig_variables::{
    ConstraintValidationResult, DeviceInfo, MlxConfigVariable, MlxVariableRegistry,
    MlxVariableSpec, RegistryTargetConstraints,
};

#[test]
fn test_complete_registry_creation_and_validation() {
    // Create a registry that matches the structure from the YAML files
    let registry = MlxVariableRegistry::builder()
        .name("Advanced Hardware Registry")
        .add_variable(
            MlxConfigVariable::builder()
                .name("memory_channels")
                .description("Memory channel configuration")
                .read_only(false)
                .spec(
                    MlxVariableSpec::builder()
                        .enum_array()
                        .with_options(vec![
                            "single".to_string(),
                            "dual".to_string(),
                            "quad".to_string(),
                        ])
                        .with_size(4)
                        .build(),
                )
                .build(),
        )
        .add_variable(
            MlxConfigVariable::builder()
                .name("performance_preset")
                .description("Performance optimization preset")
                .read_only(false)
                .spec(
                    MlxVariableSpec::builder()
                        .preset()
                        .with_max_preset(10)
                        .build(),
                )
                .build(),
        )
        .add_variable(
            MlxConfigVariable::builder()
                .name("gpio_pin_modes")
                .description("GPIO pin mode configuration")
                .read_only(false)
                .spec(
                    MlxVariableSpec::builder()
                        .enum_array()
                        .with_options(vec![
                            "input".to_string(),
                            "output".to_string(),
                            "bidirectional".to_string(),
                        ])
                        .with_size(8)
                        .build(),
                )
                .build(),
        )
        .add_variable(
            MlxConfigVariable::builder()
                .name("thermal_sensors")
                .description("Thermal sensor readings")
                .read_only(true)
                .spec(
                    MlxVariableSpec::builder()
                        .integer_array()
                        .with_size(6)
                        .build(),
                )
                .build(),
        )
        .add_variable(
            MlxConfigVariable::builder()
                .name("debug_enabled")
                .description("Enable debug mode")
                .read_only(false)
                .spec(MlxVariableSpec::Boolean)
                .build(),
        )
        .add_variable(
            MlxConfigVariable::builder()
                .name("firmware_version")
                .description("Current firmware version")
                .read_only(true)
                .spec(MlxVariableSpec::String)
                .build(),
        )
        .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
        .with_part_numbers(vec![
            "900-9D3D4-00EN-HA0".to_string(),
            "900-9D3D5-00EN-HA1".to_string(),
        ])
        .build();

    // Verify registry structure
    assert_eq!(registry.name, "Advanced Hardware Registry");
    assert_eq!(registry.variables.len(), 6);

    // Verify individual variables
    let memory_channels = &registry.variables[0];
    assert_eq!(memory_channels.name, "memory_channels");
    assert!(!memory_channels.read_only);
    match &memory_channels.spec {
        MlxVariableSpec::EnumArray { options, size } => {
            assert_eq!(options, &vec!["single", "dual", "quad"]);
            assert_eq!(*size, 4);
        }
        _ => panic!("Expected EnumArray spec for memory_channels"),
    }

    let thermal_sensors = &registry.variables[3];
    assert_eq!(thermal_sensors.name, "thermal_sensors");
    assert!(thermal_sensors.read_only);
    match &thermal_sensors.spec {
        MlxVariableSpec::IntegerArray { size } => {
            assert_eq!(*size, 6);
        }
        _ => panic!("Expected IntegerArray spec for thermal_sensors"),
    }

    // Test constraint validation
    let valid_device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0");

    let result = registry.validate_compatibility(&valid_device);
    assert_eq!(result, ConstraintValidationResult::Valid);
    assert!(result.is_valid());

    let invalid_device = DeviceInfo::new()
        .with_device_type("UnsupportedDevice")
        .with_part_number("900-INVALID-PART");

    let result = registry.validate_compatibility(&invalid_device);
    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 2);
            assert!(reasons.iter().any(|r| r.contains("Device type")));
            assert!(reasons.iter().any(|r| r.contains("Part number")));
        }
        _ => panic!("Expected Invalid result"),
    }
}

#[test]
fn test_yaml_like_registry_roundtrip() {
    // Create registry structure that matches the YAML format from the provided files
    let foo_registry_yaml = r#"
name: "foo_registry"
variables:
  - name: "cpu_frequency"
    description: "CPU frequency in MHz"
    read_only: false
    spec:
      type: "integer"
  - name: "enable_turbo"
    description: "Enable CPU turbo mode"
    read_only: false
    spec:
      type: "boolean"
  - name: "device_name"
    description: "Hardware device name"
    read_only: true
    spec:
      type: "string"
  - name: "power_mode"
    description: "Power management mode"
    read_only: false
    spec:
      type: "enum"
      config:
        options: ["low", "medium", "high", "turbo"]
"#;

    // Parse the YAML into our structures
    let registry: MlxVariableRegistry =
        serde_yaml::from_str(foo_registry_yaml).expect("Failed to parse registry YAML");

    // Verify the parsed structure
    assert_eq!(registry.name, "foo_registry");
    assert_eq!(registry.variables.len(), 4);

    // Check individual variables
    assert_eq!(registry.variables[0].name, "cpu_frequency");
    assert!(!registry.variables[0].read_only);
    matches!(registry.variables[0].spec, MlxVariableSpec::Integer);

    assert_eq!(registry.variables[1].name, "enable_turbo");
    assert!(!registry.variables[1].read_only);
    matches!(registry.variables[1].spec, MlxVariableSpec::Boolean);

    assert_eq!(registry.variables[2].name, "device_name");
    assert!(registry.variables[2].read_only);
    matches!(registry.variables[2].spec, MlxVariableSpec::String);

    assert_eq!(registry.variables[3].name, "power_mode");
    match &registry.variables[3].spec {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, &vec!["low", "medium", "high", "turbo"]);
        }
        _ => panic!("Expected Enum spec for power_mode"),
    }

    // Test roundtrip: serialize back to YAML and parse again
    let yaml_output =
        serde_yaml::to_string(&registry).expect("Failed to serialize registry to YAML");

    let roundtrip_registry: MlxVariableRegistry =
        serde_yaml::from_str(&yaml_output).expect("Failed to parse roundtrip YAML");

    // Verify roundtrip preserved structure
    assert_eq!(registry.name, roundtrip_registry.name);
    assert_eq!(registry.variables.len(), roundtrip_registry.variables.len());

    for (orig, roundtrip) in registry
        .variables
        .iter()
        .zip(roundtrip_registry.variables.iter())
    {
        assert_eq!(orig.name, roundtrip.name);
        assert_eq!(orig.description, roundtrip.description);
        assert_eq!(orig.read_only, roundtrip.read_only);
        assert_eq!(format!("{:?}", orig.spec), format!("{:?}", roundtrip.spec));
    }
}

#[test]
fn test_bar_registry_complex_types() {
    // Test the more complex registry from registry-bar.yaml
    let bar_registry_yaml = r#"
name: "bar_registry"
variables:
  - name: "memory_channels"
    description: "Memory channel configuration"
    read_only: false
    spec:
      type: "enum_array"
      config:
        options: ["single", "dual", "quad"]
        size: 4
  
  - name: "performance_preset"
    description: "Performance optimization preset"
    read_only: false
    spec:
      type: "preset"
      config:
        max_preset: 10
  
  - name: "gpio_pin_modes"
    description: "GPIO pin mode configuration"
    read_only: false
    spec:
      type: "enum_array"
      config:
        options: ["input", "output", "bidirectional"]
        size: 8
  
  - name: "thermal_sensors"
    description: "Thermal sensor readings"
    read_only: true
    spec:
      type: "integer_array"
      config:
        size: 6
  
  - name: "debug_enabled"
    description: "Enable debug mode"
    read_only: false
    spec:
      type: "boolean"
  
  - name: "firmware_version"
    description: "Current firmware version"
    read_only: true
    spec:
      type: "string"
"#;

    let registry: MlxVariableRegistry =
        serde_yaml::from_str(bar_registry_yaml).expect("Failed to parse bar registry YAML");

    assert_eq!(registry.name, "bar_registry");
    assert_eq!(registry.variables.len(), 6);

    // Test enum array
    match &registry.variables[0].spec {
        MlxVariableSpec::EnumArray { options, size } => {
            assert_eq!(options, &vec!["single", "dual", "quad"]);
            assert_eq!(*size, 4);
        }
        _ => panic!("Expected EnumArray for memory_channels"),
    }

    // Test preset
    match &registry.variables[1].spec {
        MlxVariableSpec::Preset { max_preset } => {
            assert_eq!(*max_preset, 10);
        }
        _ => panic!("Expected Preset for performance_preset"),
    }

    // Test integer array
    match &registry.variables[3].spec {
        MlxVariableSpec::IntegerArray { size } => {
            assert_eq!(*size, 6);
        }
        _ => panic!("Expected IntegerArray for thermal_sensors"),
    }
}

#[test]
fn test_multiple_registries_with_different_constraints() {
    let registries = vec![
        MlxVariableRegistry::builder()
            .name("Bluefield-specific Registry")
            .add_variable(
                MlxConfigVariable::builder()
                    .name("bf_specific_feature")
                    .description("Bluefield-specific feature control")
                    .read_only(false)
                    .spec(MlxVariableSpec::Boolean)
                    .build(),
            )
            .with_device_types(vec!["Bluefield3".to_string()])
            .build(),
        MlxVariableRegistry::builder()
            .name("ConnectX-specific Registry")
            .add_variable(
                MlxConfigVariable::builder()
                    .name("cx_bandwidth")
                    .description("ConnectX bandwidth configuration")
                    .read_only(false)
                    .spec(MlxVariableSpec::Integer)
                    .build(),
            )
            .with_device_types(vec!["ConnectX-7".to_string()])
            .build(),
        MlxVariableRegistry::builder()
            .name("Universal Registry")
            .add_variable(
                MlxConfigVariable::builder()
                    .name("universal_setting")
                    .description("Setting available on all devices")
                    .read_only(false)
                    .spec(MlxVariableSpec::String)
                    .build(),
            )
            .build(), // No constraints - universal
    ];

    // Test different device compatibility
    let bluefield_device = DeviceInfo::new().with_device_type("Bluefield3");

    let connectx_device = DeviceInfo::new().with_device_type("ConnectX-7");

    let unknown_device = DeviceInfo::new().with_device_type("UnknownDevice");

    // Test Bluefield device
    let bf_result = registries[0].validate_compatibility(&bluefield_device);
    assert_eq!(bf_result, ConstraintValidationResult::Valid);

    let cx_result_on_bf_registry = registries[0].validate_compatibility(&connectx_device);
    assert!(!cx_result_on_bf_registry.is_valid());

    // Test ConnectX device
    let cx_result = registries[1].validate_compatibility(&connectx_device);
    assert_eq!(cx_result, ConstraintValidationResult::Valid);

    let bf_result_on_cx_registry = registries[1].validate_compatibility(&bluefield_device);
    assert!(!bf_result_on_cx_registry.is_valid());

    // Test universal registry
    let universal_bf = registries[2].validate_compatibility(&bluefield_device);
    assert_eq!(universal_bf, ConstraintValidationResult::Unconstrained);

    let universal_cx = registries[2].validate_compatibility(&connectx_device);
    assert_eq!(universal_cx, ConstraintValidationResult::Unconstrained);

    let universal_unknown = registries[2].validate_compatibility(&unknown_device);
    assert_eq!(universal_unknown, ConstraintValidationResult::Unconstrained);
}

#[test]
fn test_complex_device_matching_scenarios() {
    // Registry with multiple constraints
    let registry = MlxVariableRegistry::builder()
        .name("Strict Compatibility Registry")
        .add_variable(
            MlxConfigVariable::builder()
                .name("strict_feature")
                .description("Feature requiring specific hardware and firmware")
                .read_only(false)
                .spec(MlxVariableSpec::Boolean)
                .build(),
        )
        .with_device_types(vec!["Bluefield3".to_string(), "Bluefield4".to_string()])
        .with_part_numbers(vec![
            "900-9D3D4-00EN-HA0".to_string(),
            "900-9D3D5-00EN-HA1".to_string(),
        ])
        .with_fw_versions(vec!["32.41.130".to_string(), "32.42.100".to_string()])
        .build();

    // Test all valid combinations
    let valid_combinations = vec![
        DeviceInfo::new()
            .with_device_type("Bluefield3")
            .with_part_number("900-9D3D4-00EN-HA0")
            .with_fw_version("32.41.130"),
        DeviceInfo::new()
            .with_device_type("Bluefield4")
            .with_part_number("900-9D3D5-00EN-HA1")
            .with_fw_version("32.42.100"),
        DeviceInfo::new()
            .with_device_type("Bluefield3")
            .with_part_number("900-9D3D5-00EN-HA1")
            .with_fw_version("32.41.130"),
    ];

    for device in &valid_combinations {
        let result = registry.validate_compatibility(device);
        assert_eq!(
            result,
            ConstraintValidationResult::Valid,
            "Device should be valid: {device:?}"
        );
    }

    // Test invalid combinations (each failing one constraint)
    let invalid_combinations = vec![
        (
            DeviceInfo::new()
                .with_device_type("InvalidDevice")
                .with_part_number("900-9D3D4-00EN-HA0")
                .with_fw_version("32.41.130"),
            "device type",
        ),
        (
            DeviceInfo::new()
                .with_device_type("Bluefield3")
                .with_part_number("900-INVALID-PART")
                .with_fw_version("32.41.130"),
            "part number",
        ),
        (
            DeviceInfo::new()
                .with_device_type("Bluefield3")
                .with_part_number("900-9D3D4-00EN-HA0")
                .with_fw_version("32.40.000"),
            "firmware version",
        ),
    ];

    for (device, expected_failure) in &invalid_combinations {
        let result = registry.validate_compatibility(device);
        assert!(!result.is_valid(), "Device should be invalid: {device:?}");

        let reasons = result.reasons();
        assert!(!reasons.is_empty());
        assert!(
            reasons
                .iter()
                .any(|r| r.to_lowercase().contains(expected_failure)),
            "Should contain failure reason for {expected_failure}: {reasons:?}"
        );
    }
}

#[test]
fn test_builder_pattern_consistency() {
    // Test that all builder patterns work consistently and produce expected results

    // Create spec using builder
    let enum_spec = MlxVariableSpec::builder()
        .enum_type()
        .with_options(vec!["option1".to_string(), "option2".to_string()])
        .build();

    // Create variable using builder
    let variable = MlxConfigVariable::builder()
        .name("test_variable")
        .description("Test variable description")
        .read_only(false)
        .spec(enum_spec)
        .build();

    // Create constraints using builder
    let constraints = RegistryTargetConstraints::new()
        .with_device_types(vec!["TestDevice".to_string()])
        .with_part_numbers(vec!["TEST-PART".to_string()]);

    // Create registry using builder
    let registry = MlxVariableRegistry::builder()
        .name("Test Registry")
        .add_variable(variable.clone())
        .constraints(constraints)
        .build();

    // Verify all components are properly constructed
    assert_eq!(registry.name, "Test Registry");
    assert_eq!(registry.variables.len(), 1);
    assert_eq!(registry.variables[0].name, "test_variable");
    assert_eq!(
        registry.constraints.device_types,
        Some(vec!["TestDevice".to_string()])
    );

    // Test device info builder
    let device = DeviceInfo::new()
        .with_device_type("TestDevice")
        .with_part_number("TEST-PART")
        .with_fw_version("1.0.0");

    let result = registry.validate_compatibility(&device);
    assert_eq!(result, ConstraintValidationResult::Valid);
}

#[test]
fn test_error_accumulation_and_reporting() {
    // Test that all validation errors are properly accumulated and reported
    let registry = MlxVariableRegistry::builder()
        .name("Error Testing Registry")
        .add_variable(
            MlxConfigVariable::builder()
                .name("test_var")
                .description("Test variable")
                .spec(MlxVariableSpec::Boolean)
                .build(),
        )
        .with_device_types(vec!["RequiredDevice".to_string()])
        .with_part_numbers(vec!["REQUIRED-PART".to_string()])
        .with_fw_versions(vec!["1.0.0".to_string()])
        .build();

    // Test device with all wrong values
    let bad_device = DeviceInfo::new()
        .with_device_type("WrongDevice")
        .with_part_number("WRONG-PART")
        .with_fw_version("0.9.9");

    let result = registry.validate_compatibility(&bad_device);

    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 3, "Should have exactly 3 error reasons");

            // Verify all error types are present
            let has_device_error = reasons.iter().any(|r| r.contains("Device type"));
            let has_part_error = reasons.iter().any(|r| r.contains("Part number"));
            let has_fw_error = reasons.iter().any(|r| r.contains("Firmware version"));

            assert!(has_device_error, "Should have device type error");
            assert!(has_part_error, "Should have part number error");
            assert!(has_fw_error, "Should have firmware version error");
        }
        _ => panic!("Expected Invalid result with multiple reasons"),
    }

    // Test device with missing values
    let incomplete_device = DeviceInfo::new(); // No fields set

    let result = registry.validate_compatibility(&incomplete_device);

    match result {
        ConstraintValidationResult::Invalid { reasons } => {
            assert_eq!(reasons.len(), 3);

            // All should be "required but not provided" errors
            assert!(reasons
                .iter()
                .all(|r| r.contains("required but not provided")));
        }
        _ => panic!("Expected Invalid result for incomplete device"),
    }
}

#[test]
fn test_constraint_summary_formatting() {
    // Test various constraint summary formats
    let test_cases = vec![
        (
            MlxVariableRegistry::builder()
                .name("No Constraints")
                .variables(vec![])
                .build(),
            "No constraints (compatible with any device)",
        ),
        (
            MlxVariableRegistry::builder()
                .name("Device Only")
                .variables(vec![])
                .with_device_types(vec!["Bluefield3".to_string()])
                .build(),
            "Device types: [Bluefield3]",
        ),
        (
            MlxVariableRegistry::builder()
                .name("Multiple Types")
                .variables(vec![])
                .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
                .with_part_numbers(vec!["PART1".to_string(), "PART2".to_string()])
                .build(),
            // Should contain both constraints separated by semicolon
            "", // We'll check this separately due to order sensitivity
        ),
    ];

    for (registry, expected) in &test_cases {
        let summary = registry.constraint_summary();
        if !expected.is_empty() {
            assert_eq!(summary, *expected);
        }
    }

    // Test the multiple constraints case separately
    let multi_constraint_registry = MlxVariableRegistry::builder()
        .name("Multiple Constraints")
        .variables(vec![])
        .with_device_types(vec!["Bluefield3".to_string(), "ConnectX-7".to_string()])
        .with_part_numbers(vec!["PART1".to_string(), "PART2".to_string()])
        .with_fw_versions(vec!["1.0.0".to_string()])
        .build();

    let summary = multi_constraint_registry.constraint_summary();
    assert!(summary.contains("Device types: [Bluefield3, ConnectX-7]"));
    assert!(summary.contains("Part numbers: [PART1, PART2]"));
    assert!(summary.contains("FW versions: [1.0.0]"));
    assert!(summary.contains(";")); // Should have separators
}

#[test]
fn test_real_world_usage_pattern() {
    // Simulate a real-world usage pattern where we have multiple registries
    // and need to find compatible ones for a specific device

    let registries = vec![
        // Basic features available on all devices
        MlxVariableRegistry::builder()
            .name("Basic Features")
            .add_variable(
                MlxConfigVariable::builder()
                    .name("device_name")
                    .description("Device name")
                    .read_only(true)
                    .spec(MlxVariableSpec::String)
                    .build(),
            )
            .add_variable(
                MlxConfigVariable::builder()
                    .name("power_state")
                    .description("Power state")
                    .read_only(false)
                    .spec(MlxVariableSpec::Enum {
                        options: vec!["on".to_string(), "off".to_string(), "standby".to_string()],
                    })
                    .build(),
            )
            .build(), // No constraints - universal
        // Bluefield-specific features
        MlxVariableRegistry::builder()
            .name("Bluefield Advanced Features")
            .add_variable(
                MlxConfigVariable::builder()
                    .name("arm_core_count")
                    .description("ARM core count")
                    .read_only(true)
                    .spec(MlxVariableSpec::Integer)
                    .build(),
            )
            .add_variable(
                MlxConfigVariable::builder()
                    .name("dpu_mode")
                    .description("DPU operation mode")
                    .read_only(false)
                    .spec(MlxVariableSpec::Enum {
                        options: vec!["separated".to_string(), "embedded".to_string()],
                    })
                    .build(),
            )
            .with_device_types(vec!["Bluefield3".to_string(), "Bluefield4".to_string()])
            .build(),
        // High-performance features requiring specific firmware
        MlxVariableRegistry::builder()
            .name("High Performance Features")
            .add_variable(
                MlxConfigVariable::builder()
                    .name("advanced_qos")
                    .description("Advanced QoS configuration")
                    .read_only(false)
                    .spec(MlxVariableSpec::Boolean)
                    .build(),
            )
            .with_fw_versions(vec!["32.41.130".to_string(), "32.42.100".to_string()])
            .build(),
    ];

    // Test device that should be compatible with basic and Bluefield features
    let bluefield_device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0")
        .with_fw_version("32.40.100"); // Old firmware

    let compatible_registries: Vec<&MlxVariableRegistry> = registries
        .iter()
        .filter(|registry| {
            registry
                .validate_compatibility(&bluefield_device)
                .is_valid()
        })
        .collect();

    assert_eq!(compatible_registries.len(), 2); // Basic + Bluefield features
    assert!(compatible_registries
        .iter()
        .any(|r| r.name == "Basic Features"));
    assert!(compatible_registries
        .iter()
        .any(|r| r.name == "Bluefield Advanced Features"));
    assert!(!compatible_registries
        .iter()
        .any(|r| r.name == "High Performance Features"));

    // Test device with new firmware
    let new_firmware_device = DeviceInfo::new()
        .with_device_type("Bluefield3")
        .with_part_number("900-9D3D4-00EN-HA0")
        .with_fw_version("32.41.130"); // New firmware

    let compatible_with_new_fw: Vec<&MlxVariableRegistry> = registries
        .iter()
        .filter(|registry| {
            registry
                .validate_compatibility(&new_firmware_device)
                .is_valid()
        })
        .collect();

    assert_eq!(compatible_with_new_fw.len(), 3); // All registries should be compatible

    // Count total available variables for this device
    let total_variables: usize = compatible_with_new_fw
        .iter()
        .map(|registry| registry.variables.len())
        .sum();

    assert_eq!(total_variables, 5); // 2 + 2 + 1 variables from the three registries
}
