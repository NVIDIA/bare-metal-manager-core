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

// tests/command_builder_tests.rs
// Tests for CommandBuilder functionality returning CommandSpec objects

use std::path::Path;

use mlxconfig_runner::ExecOptions;
use mlxconfig_runner::command_builder::{CommandBuilder, CommandSpec};

mod common;

#[test]
fn test_build_query_command_spec_basic() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let temp_file = Path::new("/tmp/test.json");
    let variables = vec!["SRIOV_EN".to_string(), "NUM_OF_VFS".to_string()];

    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();

    // Verify command spec structure
    assert_eq!(command_spec.program, "mlxconfig");
    assert!(command_spec.args.contains(&"-d".to_string()));
    assert!(command_spec.args.contains(&"01:00.0".to_string()));
    assert!(command_spec.args.contains(&"-e".to_string()));
    assert!(command_spec.args.contains(&"-j".to_string()));
    assert!(
        command_spec
            .args
            .contains(&temp_file.to_string_lossy().to_string())
    );
    assert!(command_spec.args.contains(&"q".to_string()));
    assert!(command_spec.args.contains(&"SRIOV_EN".to_string()));
    assert!(command_spec.args.contains(&"NUM_OF_VFS".to_string()));
}

#[test]
fn test_build_query_command_spec_empty_variables() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("02:00.0", &options);

    let temp_file = Path::new("/tmp/test_empty.json");
    let variables: Vec<String> = vec![];

    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();

    assert_eq!(command_spec.program, "mlxconfig");
    assert!(command_spec.args.contains(&"-d".to_string()));
    assert!(command_spec.args.contains(&"02:00.0".to_string()));
    assert!(command_spec.args.contains(&"q".to_string()));

    // Should not contain any variable names
    assert!(!command_spec.args.contains(&"SRIOV_EN".to_string()));
}

#[test]
fn test_build_query_command_spec_many_variables() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let temp_file = Path::new("/tmp/test_many.json");
    let variables = vec![
        "VAR1".to_string(),
        "VAR2".to_string(),
        "VAR3".to_string(),
        "ARRAY_VAR[0]".to_string(),
        "ARRAY_VAR[1]".to_string(),
    ];

    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();

    for var in &variables {
        assert!(command_spec.args.contains(var));
    }
}

#[test]
fn test_build_set_command_spec_basic() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = vec!["SRIOV_EN=true".to_string(), "NUM_OF_VFS=16".to_string()];

    let command_spec = builder.build_set_command(&assignments).unwrap();

    assert_eq!(command_spec.program, "mlxconfig");
    assert!(command_spec.args.contains(&"-d".to_string()));
    assert!(command_spec.args.contains(&"01:00.0".to_string()));
    assert!(command_spec.args.contains(&"--yes".to_string()));
    assert!(command_spec.args.contains(&"set".to_string()));
    assert!(command_spec.args.contains(&"SRIOV_EN=true".to_string()));
    assert!(command_spec.args.contains(&"NUM_OF_VFS=16".to_string()));
}

#[test]
fn test_build_set_command_spec_empty_assignments() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments: Vec<String> = vec![];

    let command_spec = builder.build_set_command(&assignments).unwrap();

    assert_eq!(command_spec.program, "mlxconfig");
    assert!(command_spec.args.contains(&"-d".to_string()));
    assert!(command_spec.args.contains(&"01:00.0".to_string()));
    assert!(command_spec.args.contains(&"--yes".to_string()));
    assert!(command_spec.args.contains(&"set".to_string()));
}

#[test]
fn test_command_spec_display_trait() {
    let spec = CommandSpec::new("mlxconfig")
        .arg("-d")
        .arg("01:00.0")
        .arg("q")
        .arg("SRIOV_EN");

    let display_str = format!("{spec}");
    assert_eq!(display_str, "mlxconfig -d 01:00.0 q SRIOV_EN");
}

#[test]
fn test_command_spec_display_trait_no_args() {
    let spec = CommandSpec::new("mlxconfig");
    let display_str = format!("{spec}");
    assert_eq!(display_str, "mlxconfig");
}

#[test]
fn test_command_spec_builder_pattern() {
    let spec = CommandSpec::new("mlxconfig")
        .arg("-d")
        .arg("01:00.0")
        .args(["-e", "-j", "/tmp/test.json"])
        .arg("q")
        .args(vec!["VAR1", "VAR2"]);

    assert_eq!(spec.program, "mlxconfig");
    assert_eq!(spec.args.len(), 8);
    assert_eq!(spec.args[0], "-d");
    assert_eq!(spec.args[1], "01:00.0");
    assert_eq!(spec.args[6], "VAR1");
    assert_eq!(spec.args[7], "VAR2");
}

#[test]
fn test_build_set_assignments_boolean() {
    let registry = common::create_test_registry();
    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
    let config_value = sriov_var.with(true).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0], "SRIOV_EN=true");
}

#[test]
fn test_build_set_assignments_integer() {
    let registry = common::create_test_registry();
    let vfs_var = registry.get_variable("NUM_OF_VFS").unwrap();
    let config_value = vfs_var.with(32i64).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0], "NUM_OF_VFS=32");
}

#[test]
fn test_build_set_assignments_enum() {
    let registry = common::create_test_registry();
    let power_var = registry.get_variable("POWER_MODE").unwrap();
    let config_value = power_var.with("HIGH").unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0], "POWER_MODE=HIGH");
}

#[test]
fn test_build_set_assignments_preset() {
    let registry = common::create_test_registry();
    let preset_var = registry.get_variable("PERFORMANCE_PRESET").unwrap();
    let config_value = preset_var.with(7u8).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0], "PERFORMANCE_PRESET=7");
}

#[test]
fn test_build_set_assignments_boolean_array_dense() {
    let registry = common::create_test_registry();
    let gpio_var = registry.get_variable("GPIO_ENABLED").unwrap();
    let config_value = gpio_var.with(vec![true, false, true, false]).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    assert_eq!(assignments.len(), 4);
    assert!(assignments.contains(&"GPIO_ENABLED[0]=true".to_string()));
    assert!(assignments.contains(&"GPIO_ENABLED[1]=false".to_string()));
    assert!(assignments.contains(&"GPIO_ENABLED[2]=true".to_string()));
    assert!(assignments.contains(&"GPIO_ENABLED[3]=false".to_string()));
}

#[test]
fn test_build_set_assignments_boolean_array_sparse() {
    let registry = common::create_test_registry();
    let gpio_var = registry.get_variable("GPIO_ENABLED").unwrap();
    let sparse_values = vec![Some(true), None, Some(false), None];
    let config_value = gpio_var.with(sparse_values).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    // Should only have assignments for non-None values
    assert_eq!(assignments.len(), 2);
    assert!(assignments.contains(&"GPIO_ENABLED[0]=true".to_string()));
    assert!(assignments.contains(&"GPIO_ENABLED[2]=false".to_string()));
    assert!(!assignments.iter().any(|a| a.contains("GPIO_ENABLED[1]")));
    assert!(!assignments.iter().any(|a| a.contains("GPIO_ENABLED[3]")));
}

#[test]
fn test_build_set_assignments_integer_array_sparse() {
    let registry = common::create_test_registry();
    let thermal_var = registry.get_variable("THERMAL_SENSORS").unwrap();
    let sparse_values = vec![Some(45i64), None, Some(42i64), None, Some(39i64), None];
    let config_value = thermal_var.with(sparse_values).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    // Should only have assignments for non-None values
    assert_eq!(assignments.len(), 3);
    assert!(assignments.contains(&"THERMAL_SENSORS[0]=45".to_string()));
    assert!(assignments.contains(&"THERMAL_SENSORS[2]=42".to_string()));
    assert!(assignments.contains(&"THERMAL_SENSORS[4]=39".to_string()));
}

#[test]
fn test_build_set_assignments_enum_array_sparse() {
    let registry = common::create_test_registry();
    let gpio_modes_var = registry.get_variable("GPIO_MODES").unwrap();
    let sparse_values = vec![
        Some("input".to_string()),
        Some("output".to_string()),
        None,
        Some("bidirectional".to_string()),
        None,
        None,
        None,
        None,
    ];
    let config_value = gpio_modes_var.with(sparse_values).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    // Should only have assignments for non-None values
    assert_eq!(assignments.len(), 3);
    assert!(assignments.contains(&"GPIO_MODES[0]=input".to_string()));
    assert!(assignments.contains(&"GPIO_MODES[1]=output".to_string()));
    assert!(assignments.contains(&"GPIO_MODES[3]=bidirectional".to_string()));
}

#[test]
fn test_build_set_assignments_binary_hex() {
    let registry = common::create_test_registry();
    let uuid_var = registry.get_variable("DEVICE_UUID").unwrap();
    let binary_data = vec![0x1au8, 0x2bu8, 0x3cu8, 0x4du8];
    let config_value = uuid_var.with(binary_data).unwrap();

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[config_value]).unwrap();

    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0], "DEVICE_UUID=0x1a2b3c4d");
}

#[test]
fn test_build_set_assignments_multiple_variables() {
    let registry = common::create_test_registry();

    let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
    let vfs_var = registry.get_variable("NUM_OF_VFS").unwrap();
    let power_var = registry.get_variable("POWER_MODE").unwrap();

    let config_values = vec![
        sriov_var.with(true).unwrap(),
        vfs_var.with(16i64).unwrap(),
        power_var.with("HIGH").unwrap(),
    ];

    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&config_values).unwrap();

    assert_eq!(assignments.len(), 3);
    assert!(assignments.contains(&"SRIOV_EN=true".to_string()));
    assert!(assignments.contains(&"NUM_OF_VFS=16".to_string()));
    assert!(assignments.contains(&"POWER_MODE=HIGH".to_string()));
}

#[test]
fn test_build_set_assignments_empty() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = builder.build_set_assignments(&[]).unwrap();

    assert!(assignments.is_empty());
}

#[test]
fn test_different_devices() {
    let options = ExecOptions::default();

    // Test different device identifiers
    let devices = ["01:00.0", "02:00.0", "03:00.1", "0000:01:00.0"];

    for device in &devices {
        let builder = CommandBuilder::new(device, &options);
        let temp_file = Path::new("/tmp/test.json");
        let variables = vec!["TEST_VAR".to_string()];

        let command_spec = builder.build_query_command(&variables, temp_file).unwrap();
        assert!(command_spec.args.contains(&device.to_string()));
    }
}

#[test]
fn test_verbose_logging() {
    let options = ExecOptions::new().with_verbose(true);
    let builder = CommandBuilder::new("01:00.0", &options);

    let temp_file = Path::new("/tmp/test.json");
    let variables = vec!["TEST_VAR".to_string()];

    // This should succeed even with verbose logging
    // (We can't easily test the actual logging output in unit tests)
    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();
    assert_eq!(command_spec.program, "mlxconfig");
}

#[test]
fn test_command_spec_to_command_conversion() {
    let spec = CommandSpec::new("echo").arg("hello").arg("world");

    let mut command = std::process::Command::new(&spec.program);
    command.args(&spec.args);

    // We can't easily test Command execution in unit tests, but we can verify
    // the structure is correct
    let debug_str = format!("{command:?}");
    assert!(debug_str.contains("echo"));
}

#[test]
fn test_realistic_mlxconfig_query_spec() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let variables = vec![
        "SRIOV_EN".to_string(),
        "NUM_OF_VFS".to_string(),
        "POWER_MODE".to_string(),
    ];
    let temp_file = Path::new("/tmp/output.json");

    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();

    let command_str = format!("{command_spec}");
    assert!(command_str.contains("mlxconfig -d 01:00.0 -e -j /tmp/output.json q SRIOV_EN"));
    assert!(command_str.contains("NUM_OF_VFS"));
    assert!(command_str.contains("POWER_MODE"));
}

#[test]
fn test_realistic_mlxconfig_set_spec() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = vec!["SRIOV_EN=true".to_string(), "NUM_OF_VFS=16".to_string()];

    let command_spec = builder.build_set_command(&assignments).unwrap();

    let command_str = format!("{command_spec}");
    assert!(command_str.contains("mlxconfig -d 01:00.0 --yes set SRIOV_EN=true NUM_OF_VFS=16"));
}

#[test]
fn test_command_spec_args_order() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let variables = vec!["VAR1".to_string(), "VAR2".to_string()];
    let temp_file = Path::new("/tmp/test.json");

    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();

    // Check that basic arguments are in the expected order
    let device_pos = command_spec
        .args
        .iter()
        .position(|x| x == "01:00.0")
        .unwrap();
    let d_flag_pos = command_spec.args.iter().position(|x| x == "-d").unwrap();
    let query_pos = command_spec.args.iter().position(|x| x == "q").unwrap();

    assert!(d_flag_pos < device_pos);
    assert!(device_pos < query_pos);
}

#[test]
fn test_command_spec_complex_path() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("01:00.0", &options);

    let temp_file = Path::new("/tmp/very/deep/directory/structure/test.json");
    let variables = vec!["TEST_VAR".to_string()];

    let command_spec = builder.build_query_command(&variables, temp_file).unwrap();

    assert!(
        command_spec
            .args
            .contains(&temp_file.to_string_lossy().to_string())
    );
}
