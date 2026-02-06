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

use mlxconfig_variables::{MlxConfigVariable, MlxVariableSpec};

#[test]
fn test_mlx_config_variable_builder_basic() {
    let variable = MlxConfigVariable::builder()
        .name("cpu_frequency")
        .description("CPU frequency in MHz")
        .read_only(false)
        .spec(MlxVariableSpec::Integer)
        .build();

    assert_eq!(variable.name, "cpu_frequency");
    assert_eq!(variable.description, "CPU frequency in MHz");
    assert!(!variable.read_only);
    matches!(variable.spec, MlxVariableSpec::Integer);
}

#[test]
fn test_mlx_config_variable_builder_read_only() {
    let variable = MlxConfigVariable::builder()
        .name("firmware_version")
        .description("Current firmware version")
        .read_only(true)
        .spec(MlxVariableSpec::String)
        .build();

    assert_eq!(variable.name, "firmware_version");
    assert_eq!(variable.description, "Current firmware version");
    assert!(variable.read_only);
    matches!(variable.spec, MlxVariableSpec::String);
}

#[test]
fn test_mlx_config_variable_builder_with_enum_spec() {
    let spec = MlxVariableSpec::builder()
        .enum_type()
        .with_options(vec![
            "low".to_string(),
            "medium".to_string(),
            "high".to_string(),
        ])
        .build();

    let variable = MlxConfigVariable::builder()
        .name("power_mode")
        .description("Power management mode")
        .read_only(false)
        .spec(spec)
        .build();

    assert_eq!(variable.name, "power_mode");
    assert_eq!(variable.description, "Power management mode");
    assert!(!variable.read_only);

    match variable.spec {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, vec!["low", "medium", "high"]);
        }
        _ => panic!("Expected Enum spec"),
    }
}

#[test]
fn test_mlx_config_variable_builder_with_preset_spec() {
    let spec = MlxVariableSpec::builder()
        .preset()
        .with_max_preset(10)
        .build();

    let variable = MlxConfigVariable::builder()
        .name("performance_preset")
        .description("Performance optimization preset")
        .read_only(false)
        .spec(spec)
        .build();

    assert_eq!(variable.name, "performance_preset");
    assert_eq!(variable.description, "Performance optimization preset");
    assert!(!variable.read_only);

    match variable.spec {
        MlxVariableSpec::Preset { max_preset } => {
            assert_eq!(max_preset, 10);
        }
        _ => panic!("Expected Preset spec"),
    }
}

#[test]
fn test_mlx_config_variable_builder_with_array_specs() {
    // Test integer array
    let int_array_spec = MlxVariableSpec::builder()
        .integer_array()
        .with_size(6)
        .build();

    let int_array_var = MlxConfigVariable::builder()
        .name("thermal_sensors")
        .description("Thermal sensor readings")
        .read_only(true)
        .spec(int_array_spec)
        .build();

    match int_array_var.spec {
        MlxVariableSpec::IntegerArray { size } => {
            assert_eq!(size, 6);
        }
        _ => panic!("Expected IntegerArray spec"),
    }

    // Test enum array
    let enum_array_spec = MlxVariableSpec::builder()
        .enum_array()
        .with_options(vec![
            "input".to_string(),
            "output".to_string(),
            "bidirectional".to_string(),
        ])
        .with_size(8)
        .build();

    let enum_array_var = MlxConfigVariable::builder()
        .name("gpio_pin_modes")
        .description("GPIO pin mode configuration")
        .read_only(false)
        .spec(enum_array_spec)
        .build();

    match enum_array_var.spec {
        MlxVariableSpec::EnumArray { options, size } => {
            assert_eq!(options, vec!["input", "output", "bidirectional"]);
            assert_eq!(size, 8);
        }
        _ => panic!("Expected EnumArray spec"),
    }
}

#[test]
#[should_panic(expected = "name is required")]
fn test_mlx_config_variable_builder_missing_name() {
    MlxConfigVariable::builder()
        .description("Test description")
        .spec(MlxVariableSpec::Boolean)
        .build();
}

#[test]
#[should_panic(expected = "description is required")]
fn test_mlx_config_variable_builder_missing_description() {
    MlxConfigVariable::builder()
        .name("test_var")
        .spec(MlxVariableSpec::Boolean)
        .build();
}

#[test]
#[should_panic(expected = "spec is required")]
fn test_mlx_config_variable_builder_missing_spec() {
    MlxConfigVariable::builder()
        .name("test_var")
        .description("Test description")
        .build();
}

#[test]
fn test_mlx_config_variable_builder_default_read_only() {
    let variable = MlxConfigVariable::builder()
        .name("test_var")
        .description("Test description")
        .spec(MlxVariableSpec::Boolean)
        .build();

    // Default should be false (writable)
    assert!(!variable.read_only);
}

#[test]
fn test_mlx_config_variable_serde_serialization() {
    let variable = MlxConfigVariable::builder()
        .name("cpu_frequency")
        .description("CPU frequency in MHz")
        .read_only(false)
        .spec(MlxVariableSpec::Integer)
        .build();

    let json = serde_json::to_string(&variable).expect("Serialization failed");
    let deserialized: MlxConfigVariable =
        serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(variable.name, deserialized.name);
    assert_eq!(variable.description, deserialized.description);
    assert_eq!(variable.read_only, deserialized.read_only);

    // Compare spec types (debug formatting since direct equality isn't implemented)
    assert_eq!(
        format!("{:?}", variable.spec),
        format!("{:?}", deserialized.spec)
    );
}

#[test]
fn test_mlx_config_variable_yaml_serialization() {
    let variable = MlxConfigVariable::builder()
        .name("power_mode")
        .description("Power management mode")
        .read_only(false)
        .spec(MlxVariableSpec::Enum {
            options: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        })
        .build();

    let yaml = serde_yaml::to_string(&variable).expect("YAML serialization failed");
    let deserialized: MlxConfigVariable =
        serde_yaml::from_str(&yaml).expect("YAML deserialization failed");

    assert_eq!(variable.name, deserialized.name);
    assert_eq!(variable.description, deserialized.description);
    assert_eq!(variable.read_only, deserialized.read_only);

    match (variable.spec, deserialized.spec) {
        (MlxVariableSpec::Enum { options: orig }, MlxVariableSpec::Enum { options: deser }) => {
            assert_eq!(orig, deser);
        }
        _ => panic!("Spec types don't match after YAML roundtrip"),
    }
}

#[test]
fn test_mlx_config_variable_clone() {
    let variable = MlxConfigVariable::builder()
        .name("test_var")
        .description("Test variable for cloning")
        .read_only(true)
        .spec(MlxVariableSpec::String)
        .build();

    let cloned = variable.clone();

    assert_eq!(variable.name, cloned.name);
    assert_eq!(variable.description, cloned.description);
    assert_eq!(variable.read_only, cloned.read_only);
    assert_eq!(format!("{:?}", variable.spec), format!("{:?}", cloned.spec));
}

#[test]
fn test_mlx_config_variable_debug_formatting() {
    let variable = MlxConfigVariable::builder()
        .name("debug_enabled")
        .description("Enable debug mode")
        .read_only(false)
        .spec(MlxVariableSpec::Boolean)
        .build();

    let debug_str = format!("{variable:?}");

    // Should contain all the important fields
    assert!(debug_str.contains("debug_enabled"));
    assert!(debug_str.contains("Enable debug mode"));
    assert!(debug_str.contains("false")); // read_only
    assert!(debug_str.contains("Boolean"));
}

#[test]
fn test_multiple_variables_with_different_specs() {
    let variables = vec![
        MlxConfigVariable::builder()
            .name("boolean_var")
            .description("A boolean variable")
            .spec(MlxVariableSpec::Boolean)
            .build(),
        MlxConfigVariable::builder()
            .name("integer_var")
            .description("An integer variable")
            .spec(MlxVariableSpec::Integer)
            .build(),
        MlxConfigVariable::builder()
            .name("string_var")
            .description("A string variable")
            .read_only(true)
            .spec(MlxVariableSpec::String)
            .build(),
        MlxConfigVariable::builder()
            .name("enum_var")
            .description("An enum variable")
            .spec(MlxVariableSpec::Enum {
                options: vec!["option1".to_string(), "option2".to_string()],
            })
            .build(),
    ];

    assert_eq!(variables.len(), 4);

    // Verify each variable has the expected properties
    assert_eq!(variables[0].name, "boolean_var");
    assert!(!variables[0].read_only);
    matches!(variables[0].spec, MlxVariableSpec::Boolean);

    assert_eq!(variables[1].name, "integer_var");
    assert!(!variables[1].read_only);
    matches!(variables[1].spec, MlxVariableSpec::Integer);

    assert_eq!(variables[2].name, "string_var");
    assert!(variables[2].read_only);
    matches!(variables[2].spec, MlxVariableSpec::String);

    assert_eq!(variables[3].name, "enum_var");
    assert!(!variables[3].read_only);
    match &variables[3].spec {
        MlxVariableSpec::Enum { options } => {
            assert_eq!(options, &vec!["option1".to_string(), "option2".to_string()]);
        }
        _ => panic!("Expected Enum spec"),
    }
}
