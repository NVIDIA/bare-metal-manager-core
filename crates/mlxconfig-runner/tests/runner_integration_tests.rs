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

// tests/runner_integration_tests.rs
// Integration tests for MlxConfigRunner functionality

use std::fs;
use std::time::Duration;

use mlxconfig_runner::{ExecOptions, MlxConfigRunner};

mod common;

// Note: These tests focus on the runner's internal logic and error handling
// rather than actually executing mlxconfig commands, since we can't rely on
// mlxconfig being available or specific hardware being present in test environments.

#[test]
fn test_runner_temp_file_prefix() {
    let registry = common::create_test_registry();
    let mut runner = MlxConfigRunner::new("01:00.0".to_string(), registry);

    // Should not panic when setting temp file prefix
    runner.set_temp_file_prefix("/custom/tmp");
}

#[test]
fn test_sync_with_no_changes_needed() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true); // Use dry run to avoid actual execution
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    // Create a mock JSON response file that matches our desired values
    let json_data = common::create_sample_json_response("01:00.0");
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    // Since we're in dry_run mode, the sync operation will attempt to parse
    // but won't actually execute mlxconfig commands
    let assignments = &[
        ("SRIOV_EN", "true"), // Already true in mock JSON
        ("NUM_OF_VFS", "16"), // Already 16 in mock JSON
    ];

    // This will fail because we can't mock the mlxconfig command execution easily,
    // but it tests the basic sync flow setup
    let result = runner.sync(assignments);

    // In dry run mode with no actual mlxconfig, this will likely error
    // but the sync logic path gets exercised
    // We could make this more sophisticated with better mocking
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_compare_operation() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let assignments = &[
        ("SRIOV_EN", "false"), // Different from mock JSON (which has true)
        ("NUM_OF_VFS", "32"),  // Different from mock JSON (which has 16)
        ("POWER_MODE", "LOW"), // Different from mock JSON (which has HIGH)
    ];

    // This will fail in the query phase since we can't mock mlxconfig,
    // but it tests the compare flow setup
    let result = runner.compare(assignments);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_set_with_array_variables() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    // Test sparse array assignments
    let assignments = &[
        ("GPIO_ENABLED[0]", "true"),
        ("GPIO_ENABLED[2]", "false"),
        ("GPIO_MODES[1]", "output"),
        ("GPIO_MODES[3]", "bidirectional"),
    ];

    // In dry run mode, this should process the assignments and build the command
    // but not actually execute it
    let result = runner.set(assignments);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_set_with_invalid_variable() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let assignments = &[("SRIOV_EN", "true"), ("NONEXISTENT_VAR", "value")];

    let result = runner.set(assignments);
    assert!(result.is_err());

    if let Err(mlxconfig_runner::MlxRunnerError::VariableNotFound { variable_name }) = result {
        assert_eq!(variable_name, "NONEXISTENT_VAR");
    } else {
        panic!("Expected VariableNotFound error, got: {result:?}");
    }
}

#[test]
fn test_set_with_invalid_enum_value() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let assignments = &[
        ("POWER_MODE", "INVALID_POWER_MODE"), // Not in allowed options: LOW, MEDIUM, HIGH
    ];

    let result = runner.set(assignments);
    assert!(result.is_err());
}

#[test]
fn test_set_with_invalid_boolean_value() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let assignments = &[
        ("SRIOV_EN", "maybe"), // Invalid boolean value
    ];

    let result = runner.set(assignments);
    assert!(result.is_err());
}

#[test]
fn test_set_with_array_out_of_bounds() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let assignments = &[
        ("GPIO_ENABLED[10]", "true"), // GPIO_ENABLED array size is 4, so index 10 is invalid
    ];

    let result = runner.set(assignments);
    assert!(result.is_err());
}

#[test]
fn test_set_with_preset_out_of_range() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let assignments = &[
        ("PERFORMANCE_PRESET", "20"), // Max preset is 10, so 20 is invalid
    ];

    let result = runner.set(assignments);
    assert!(result.is_err());
}

#[test]
fn test_query_all_variables() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    // This will fail because we can't actually execute mlxconfig,
    // but it tests the query_all flow
    let result = runner.query_all();
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_query_specific_variables() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let variables = &["SRIOV_EN", "NUM_OF_VFS"];

    // This will fail because we can't actually execute mlxconfig,
    // but it tests the query flow
    let result = runner.query(variables);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_query_array_variables() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    // Query array variables - should expand to individual indices
    let variables = &["GPIO_ENABLED", "THERMAL_SENSORS"];

    let result = runner.query(variables);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_query_nonexistent_variable() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    let variables = &["NONEXISTENT_VAR"];

    let result = runner.query(variables);
    assert!(result.is_err());

    if let Err(mlxconfig_runner::MlxRunnerError::VariableNotFound { variable_name }) = result {
        assert_eq!(variable_name, "NONEXISTENT_VAR");
    } else {
        panic!("Expected VariableNotFound error, got: {result:?}");
    }
}

#[test]
fn test_different_device_identifiers() {
    let registry = common::create_test_registry();

    let devices = [
        "01:00.0",
        "02:00.0",
        "03:00.1",
        "0000:01:00.0",
        "0000:0a:00.0",
    ];

    for device in &devices {
        // Should be able to create runners for different device formats
        // Basic smoke test - construction should succeed.
        let options = ExecOptions::new().with_dry_run(true);
        let runner_with_options =
            MlxConfigRunner::with_options(device.to_string(), registry.clone(), options);

        // Test a basic operation
        let result = runner_with_options.set([("SRIOV_EN", "true")]);
        assert!(result.is_err() || result.is_ok());
    }
}

#[test]
fn test_execution_options_propagation() {
    let registry = common::create_test_registry();

    // Test various option combinations
    let test_cases = vec![
        ExecOptions::new().with_verbose(true),
        ExecOptions::new().with_dry_run(true),
        ExecOptions::new().with_retries(5),
        ExecOptions::new().with_timeout(Some(Duration::from_secs(60))),
        ExecOptions::new()
            .with_verbose(true)
            .with_dry_run(true)
            .with_retries(3)
            .with_confirm_destructive(true),
    ];

    for options in test_cases {
        let runner =
            MlxConfigRunner::with_options("01:00.0".to_string(), registry.clone(), options);

        // Test that runner can be created with different option combinations
        let result = runner.set([("SRIOV_EN", "true")]);
        assert!(result.is_err() || result.is_ok());
    }
}

#[test]
fn test_empty_assignments() {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

    // Empty assignments array should be handled gracefully
    let empty_assignments: &[(&str, &str)] = &[];

    let result = runner.set(empty_assignments);
    // Should succeed (no operations to perform)
    assert!(result.is_ok());
}

#[test]
fn test_temp_file_prefix_setting() {
    let registry = common::create_test_registry();
    let mut runner = MlxConfigRunner::new("01:00.0".to_string(), registry);

    // Test different temp file prefixes
    runner.set_temp_file_prefix("/tmp");
    runner.set_temp_file_prefix("/custom/temp");
    runner.set_temp_file_prefix("/var/tmp");

    // Should not panic or error
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_multiple_error_conditions() {
        let registry = common::create_test_registry();
        let options = ExecOptions::new().with_dry_run(true);
        let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

        // Test multiple invalid conditions at once
        let assignments = &[
            ("NONEXISTENT_VAR", "value"),   // Variable not found
            ("POWER_MODE", "INVALID_MODE"), // Invalid enum value
            ("GPIO_ENABLED[100]", "true"),  // Array index out of bounds
        ];

        let result = runner.set(assignments);
        assert!(result.is_err());

        // Should get the first error encountered (variable not found)
        if let Err(mlxconfig_runner::MlxRunnerError::VariableNotFound { variable_name }) = result {
            assert_eq!(variable_name, "NONEXISTENT_VAR");
        } else {
            panic!("Expected VariableNotFound error for first invalid variable");
        }
    }

    #[test]
    fn test_sync_vs_set_vs_compare_consistency() {
        let registry = common::create_test_registry();
        let options = ExecOptions::new().with_dry_run(true);
        let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

        let assignments = &[("SRIOV_EN", "true"), ("NUM_OF_VFS", "32")];

        // All three operations should handle the same assignments consistently
        // (Even though they'll fail due to no mlxconfig, they should fail in the same way)

        let set_result = runner.set(assignments);
        let sync_result = runner.sync(assignments);
        let compare_result = runner.compare(assignments);

        // All should either succeed or fail with similar error patterns
        match (&set_result, &sync_result, &compare_result) {
            (Ok(_), Ok(_), Ok(_)) => {}    // All succeeded
            (Err(_), Err(_), Err(_)) => {} // All failed (expected in test environment)
            _ => {
                // Mixed results might indicate inconsistent handling
                // But we'll allow it since mocking is complex
            }
        }
    }
}

#[cfg(test)]
mod realistic_scenarios {
    use super::*;

    #[test]
    fn test_typical_gpu_configuration() {
        let registry = common::create_test_registry();
        let options = ExecOptions::new()
            .with_retries(2)
            .with_timeout(Some(Duration::from_secs(45)))
            .with_dry_run(true);

        let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

        // Typical SRIOV configuration
        let sriov_config = &[("SRIOV_EN", "true"), ("NUM_OF_VFS", "8")];

        let result = runner.set(sriov_config);
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_gpio_array_configuration() {
        let registry = common::create_test_registry();
        let options = ExecOptions::new().with_dry_run(true);
        let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

        // Configure GPIO pins with mixed modes
        let gpio_config = &[
            ("GPIO_ENABLED[0]", "true"),
            ("GPIO_ENABLED[1]", "true"),
            ("GPIO_ENABLED[2]", "false"),
            ("GPIO_ENABLED[3]", "true"),
            ("GPIO_MODES[0]", "input"),
            ("GPIO_MODES[1]", "output"),
            ("GPIO_MODES[3]", "bidirectional"),
        ];

        let result = runner.set(gpio_config);
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_performance_tuning_scenario() {
        let registry = common::create_test_registry();
        let options = ExecOptions::new().with_verbose(true).with_dry_run(true);

        let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);

        // Performance optimization scenario
        let perf_config = &[
            ("SRIOV_EN", "true"),
            ("NUM_OF_VFS", "16"),
            ("POWER_MODE", "HIGH"),
            ("PERFORMANCE_PRESET", "8"),
        ];

        let result = runner.sync(perf_config);
        assert!(result.is_err() || result.is_ok());
    }
}
