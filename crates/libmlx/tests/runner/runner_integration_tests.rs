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

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
use libmlx::runner::error::MlxRunnerError;
use libmlx::runner::exec_options::ExecOptions;
use libmlx::runner::runner::MlxConfigRunner;

use super::common;

// Note: These tests focus on the runner's internal logic and error handling
// rather than actually executing mlxconfig commands, since we can't rely on
// mlxconfig being available or specific hardware being present in test environments.

// A dry-run runner over a fresh test registry, targeting `01:00.0`. Dry run keeps
// these tests off any real mlxconfig binary; the construction was copy-pasted into
// almost every test below.
fn dry_run_runner() -> MlxConfigRunner {
    let registry = common::create_test_registry();
    let options = ExecOptions::new().with_dry_run(true);
    MlxConfigRunner::with_options("01:00.0".to_string(), registry, options)
}

// Runs `set` on a fresh dry-run runner and distills the error to a comparable
// shape: a `VariableNotFound` becomes its offending variable name (the part of the
// error that is the contract), any other failure becomes a generic marker. Lets one
// `check_cases` table both pin the not-found name (`FailsWith`) and assert plain
// rejection (`Fails`) for the validation failures.
fn set_outcome(assignments: &[(&str, &str)]) -> Result<(), String> {
    dry_run_runner().set(assignments).map_err(|err| match err {
        MlxRunnerError::VariableNotFound { variable_name } => variable_name,
        other => format!("other: {other:?}"),
    })
}

#[test]
fn test_runner_temp_file_prefix() {
    let registry = common::create_test_registry();
    let mut runner = MlxConfigRunner::new("01:00.0".to_string(), registry);

    // Should not panic when setting temp file prefix
    runner.set_temp_file_prefix("/custom/tmp");
}

// Every invalid `set` assignment is rejected before any mlxconfig command runs.
// The not-found rows pin the offending variable name (it's the contract, and the
// runner reports the *first* invalid variable); the enum / boolean / array-bounds /
// preset-range rows just assert rejection.
#[test]
fn invalid_set_assignments_are_rejected() {
    scenarios!(
        run = set_outcome;
        "unknown variable names itself" {
            &[("SRIOV_EN", "true"), ("NONEXISTENT_VAR", "value")][..] => FailsWith("NONEXISTENT_VAR".to_string()),
        }

        "first invalid variable wins over later invalid values" {
            &[
                ("NONEXISTENT_VAR", "value"),   // Variable not found
                ("POWER_MODE", "INVALID_MODE"), // Invalid enum value
                ("GPIO_ENABLED[100]", "true"),  // Array index out of bounds
            ][..] => FailsWith("NONEXISTENT_VAR".to_string()),
        }

        "enum value outside allowed options (LOW/MEDIUM/HIGH)" {
            &[("POWER_MODE", "INVALID_POWER_MODE")][..] => Fails,
        }

        "non-boolean value for a boolean variable" {
            &[("SRIOV_EN", "maybe")][..] => Fails,
        }

        "array index past the registry size of 4" {
            &[("GPIO_ENABLED[10]", "true")][..] => Fails,
        }

        "preset above the max of 10" {
            &[("PERFORMANCE_PRESET", "20")][..] => Fails,
        }
    );
}

#[test]
fn test_query_nonexistent_variable() {
    let runner = dry_run_runner();
    let result = runner.query(["NONEXISTENT_VAR"]);

    assert!(result.is_err());
    if let Err(MlxRunnerError::VariableNotFound { variable_name }) = result {
        assert_eq!(variable_name, "NONEXISTENT_VAR");
    } else {
        panic!("Expected VariableNotFound error, got: {result:?}");
    }
}

#[test]
fn test_empty_assignments() {
    let runner = dry_run_runner();

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

// The smoke tests below can't pin an outcome: without a mockable mlxconfig binary
// the operation may succeed or fail depending on the host. Each one asserts the
// weaker contract that the flow runs to completion without panicking. They stay
// standalone (no outcome to fold into a table) but share `dry_run_runner`.

#[test]
fn test_sync_with_no_changes_needed() {
    let runner = dry_run_runner();

    // Create a mock JSON response file that matches our desired values
    let json_data = common::create_sample_json_response("01:00.0");
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let json_string = serde_json::to_string_pretty(&json_data).unwrap();
    fs::write(temp_file.path(), json_string).unwrap();

    // Since we're in dry_run mode, the sync operation will attempt to parse
    // but won't actually execute mlxconfig commands. We can't mock the command
    // execution easily, but this exercises the basic sync flow setup.
    let assignments = &[
        ("SRIOV_EN", "true"), // Already true in mock JSON
        ("NUM_OF_VFS", "16"), // Already 16 in mock JSON
    ];

    let _ = runner.sync(assignments);
}

#[test]
fn test_compare_operation() {
    let runner = dry_run_runner();

    let assignments = &[
        ("SRIOV_EN", "false"), // Different from mock JSON (which has true)
        ("NUM_OF_VFS", "32"),  // Different from mock JSON (which has 16)
        ("POWER_MODE", "LOW"), // Different from mock JSON (which has HIGH)
    ];

    // Fails in the query phase (no mockable mlxconfig); exercises the compare setup.
    let _ = runner.compare(assignments);
}

#[test]
fn test_set_with_array_variables() {
    let runner = dry_run_runner();

    // Test sparse array assignments
    let assignments = &[
        ("GPIO_ENABLED[0]", "true"),
        ("GPIO_ENABLED[2]", "false"),
        ("GPIO_MODES[1]", "output"),
        ("GPIO_MODES[3]", "bidirectional"),
    ];

    // In dry run mode, this should process the assignments and build the command
    // but not actually execute it.
    let _ = runner.set(assignments);
}

#[test]
fn test_query_all_variables() {
    let runner = dry_run_runner();

    // Exercises the query_all flow (no mockable mlxconfig to actually execute).
    let _ = runner.query_all();
}

#[test]
fn test_query_specific_variables() {
    let runner = dry_run_runner();

    // Exercises the query flow (no mockable mlxconfig to actually execute).
    let _ = runner.query(["SRIOV_EN", "NUM_OF_VFS"]);
}

#[test]
fn test_query_array_variables() {
    let runner = dry_run_runner();

    // Query array variables - should expand to individual indices.
    let _ = runner.query(["GPIO_ENABLED", "THERMAL_SENSORS"]);
}

#[test]
fn test_sync_vs_set_vs_compare_consistency() {
    let runner = dry_run_runner();

    let assignments = &[("SRIOV_EN", "true"), ("NUM_OF_VFS", "32")];

    // All three operations accept the same assignments and run to completion without
    // panicking. We can't pin their outcome (no mockable mlxconfig), and the original
    // test deliberately tolerated mixed success/failure across the three.
    let _ = runner.set(assignments);
    let _ = runner.sync(assignments);
    let _ = runner.compare(assignments);
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
        // Construction should succeed for every device format, and a basic operation
        // should run without panicking.
        let options = ExecOptions::new().with_dry_run(true);
        let runner = MlxConfigRunner::with_options(device.to_string(), registry.clone(), options);
        let _ = runner.set([("SRIOV_EN", "true")]);
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
        // The runner builds with each option combination and runs without panicking.
        let runner =
            MlxConfigRunner::with_options("01:00.0".to_string(), registry.clone(), options);
        let _ = runner.set([("SRIOV_EN", "true")]);
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

        let _ = runner.set(sriov_config);
    }

    #[test]
    fn test_gpio_array_configuration() {
        let runner = dry_run_runner();

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

        let _ = runner.set(gpio_config);
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

        let _ = runner.sync(perf_config);
    }
}
