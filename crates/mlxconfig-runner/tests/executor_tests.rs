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

// tests/executor_tests.rs
// Tests for CommandExecutor functionality including timeout and retry logic

use std::fs;
use std::path::Path;
use std::time::Duration;

use mlxconfig_runner::command_builder::{CommandBuilder, CommandSpec};
use mlxconfig_runner::executor::CommandExecutor;
use mlxconfig_runner::{ExecOptions, MlxRunnerError};

mod common;

#[test]
fn test_create_temp_file() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    let temp_dir = tempfile::tempdir().unwrap();
    let prefix = temp_dir.path().to_str().unwrap();

    let temp_file = executor.create_temp_file(prefix).unwrap();

    // File should exist and be in the specified directory
    assert!(temp_file.exists());
    assert!(temp_file.starts_with(prefix));
    assert!(
        temp_file
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("mlxconfig-runner-")
    );
    assert_eq!(temp_file.extension().unwrap(), "json");

    // Clean up
    let _ = executor.cleanup_temp_file(&temp_file);
}

#[test]
fn test_cleanup_temp_file_existing() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    let temp_dir = tempfile::tempdir().unwrap();
    let prefix = temp_dir.path().to_str().unwrap();

    let temp_file = executor.create_temp_file(prefix).unwrap();
    assert!(temp_file.exists());

    // Clean up should succeed
    executor.cleanup_temp_file(&temp_file).unwrap();
    assert!(!temp_file.exists());
}

#[test]
fn test_cleanup_temp_file_nonexistent() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    let temp_dir = tempfile::tempdir().unwrap();
    let nonexistent_file = temp_dir.path().join("nonexistent.json");

    // Should not error when trying to clean up nonexistent file.
    executor.cleanup_temp_file(&nonexistent_file).unwrap();
}

#[test]
fn test_is_dry_run() {
    let dry_run_options = ExecOptions::new().with_dry_run(true);
    let executor = CommandExecutor::new(&dry_run_options);
    assert!(executor.is_dry_run());

    let normal_options = ExecOptions::new().with_dry_run(false);
    let executor = CommandExecutor::new(&normal_options);
    assert!(!executor.is_dry_run());
}

#[test]
fn test_is_verbose() {
    let verbose_options = ExecOptions::new().with_verbose(true);
    let executor = CommandExecutor::new(&verbose_options);
    assert!(executor.is_verbose());

    let quiet_options = ExecOptions::new().with_verbose(false);
    let executor = CommandExecutor::new(&quiet_options);
    assert!(!executor.is_verbose());
}

#[test]
fn test_execute_dry_run() {
    let options = ExecOptions::new().with_dry_run(true);
    let executor = CommandExecutor::new(&options);
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = vec!["TEST_VAR=test".to_string()];
    let command_spec = builder.build_set_command(&assignments).unwrap();

    // This should not actually "execute" but should not error.
    executor.execute_dry_run(&command_spec, "test");
}

#[test]
fn test_successful_command_execution() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    // Use a simple command that should always succeed.
    let command_spec = CommandSpec::new("echo").arg("hello");

    let output = executor.execute_with_retry(&command_spec).unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

#[test]
fn test_failed_command_execution() {
    // No retries to make the test faster.
    let options = ExecOptions::new().with_retries(0);
    let executor = CommandExecutor::new(&options);

    // Use a command that should always fail.
    let command_spec = CommandSpec::new("false");

    let result = executor.execute_with_retry(&command_spec);
    assert!(result.is_err());
}

#[test]
fn test_command_not_found() {
    // No retries to make the test faster.
    let options = ExecOptions::new().with_retries(0);
    let executor = CommandExecutor::new(&options);

    // Use a command that definitely doesn't exist.
    let command_spec = CommandSpec::new("duppet_is_real_but_not_like_this");

    let result = executor.execute_with_retry(&command_spec);
    assert!(result.is_err());
}

#[test]
fn test_timeout_functionality() {
    let options = ExecOptions::new()
        // Just use a short timeout.
        .with_timeout(Some(Duration::from_millis(100)))
        .with_retries(0); // No retries to make test faster

    let executor = CommandExecutor::new(&options);

    // Use sleep command that will exceed our timeout.
    let command_spec = CommandSpec::new("sleep").arg("5");

    let result = executor.execute_with_retry(&command_spec);
    assert!(result.is_err());

    // *Should* be a timeout error.
    if let Err(MlxRunnerError::Timeout { duration, .. }) = result {
        assert_eq!(duration, Duration::from_millis(100));
    } else {
        panic!("Expected timeout error, got: {result:?}");
    }
}

#[test]
fn test_no_timeout_successful_execution() {
    let options = ExecOptions::new()
        .with_timeout(None) // No timeout in this case.
        .with_retries(0);

    let executor = CommandExecutor::new(&options);

    // Use a command that should complete quickly
    let command_spec = CommandSpec::new("echo").arg("no timeout test");

    let output = executor.execute_with_retry(&command_spec).unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "no timeout test"
    );
}

#[test]
fn test_should_retry_error_classification() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    // Permanent errors should not be retried.
    assert!(
        !executor.should_retry_error(&MlxRunnerError::VariableNotFound {
            variable_name: "TEST".to_string()
        })
    );

    assert!(
        !executor.should_retry_error(&MlxRunnerError::ArraySizeMismatch {
            variable_name: "TEST".to_string(),
            expected: 4,
            found: 6,
        })
    );

    assert!(
        !executor.should_retry_error(&MlxRunnerError::DeviceMismatch {
            expected: "01:00.0".to_string(),
            actual: "02:00.0".to_string(),
        })
    );

    // Transient errors should be retried
    assert!(executor.should_retry_error(&MlxRunnerError::Timeout {
        command: "test".to_string(),
        duration: Duration::from_secs(1)
    }));

    assert!(
        executor.should_retry_error(&MlxRunnerError::CommandExecution {
            command: "test".to_string(),
            exit_code: Some(1),
            stdout: "".to_string(),
            stderr: "error".to_string(),
        })
    );

    assert!(
        executor.should_retry_error(&MlxRunnerError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "test"
        )))
    );
}

#[test]
fn test_exponential_backoff_configuration() {
    // Test custom exponential backoff parameters
    let options = ExecOptions::new()
        .with_retries(3)
        .with_retry_delay(Duration::from_millis(10))
        .with_max_retry_delay(Duration::from_millis(100))
        .with_retry_multiplier(3.0); // Triple each time

    let executor = CommandExecutor::new(&options);

    // Test that options are correctly set
    assert_eq!(options.retries, 3);
    assert_eq!(options.retry_delay, Duration::from_millis(10));
    assert_eq!(options.max_retry_delay, Duration::from_millis(100));
    assert_eq!(options.retry_multiplier, 3.0);

    // Test with a command that should succeed immediately
    let command_spec = CommandSpec::new("echo").arg("backoff test");

    let output = executor.execute_with_retry(&command_spec).unwrap();
    assert!(output.status.success());
}

#[test]
fn test_conservative_backoff() {
    // Test conservative backoff with slow growth
    let options = ExecOptions::new()
        .with_retry_delay(Duration::from_millis(50))
        .with_max_retry_delay(Duration::from_secs(10))
        .with_retry_multiplier(1.2) // Only 20% increase each time
        .with_retries(2);

    let executor = CommandExecutor::new(&options);

    // Use a command that should succeed
    let command_spec = CommandSpec::new("echo").arg("conservative test");

    let output = executor.execute_with_retry(&command_spec).unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "conservative test"
    );
}

#[test]
fn test_aggressive_backoff() {
    // Test aggressive backoff with fast growth but low cap
    let options = ExecOptions::new()
        .with_retry_delay(Duration::from_millis(5))
        .with_max_retry_delay(Duration::from_millis(50))
        .with_retry_multiplier(5.0) // 5x increase each time
        .with_retries(2);

    let executor = CommandExecutor::new(&options);

    // Use a command that should succeed
    let command_spec = CommandSpec::new("echo").arg("aggressive test");

    let output = executor.execute_with_retry(&command_spec).unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "aggressive test"
    );
}

#[test]
fn test_retry_logic_with_retries() {
    let options = ExecOptions::new()
        .with_retries(2)
        .with_retry_delay(Duration::from_millis(10)); // Fast retry for testing

    let executor = CommandExecutor::new(&options);

    // Command that always fails
    let command_spec = CommandSpec::new("false");

    let result = executor.execute_with_retry(&command_spec);
    assert!(result.is_err());

    // We can't easily test that it actually retried without more complex mocking,
    // but we can verify the final result is still an error
}

#[test]
fn test_retry_logic_eventual_success() {
    let options = ExecOptions::new()
        .with_retries(1)
        .with_retry_delay(Duration::from_millis(10));

    let executor = CommandExecutor::new(&options);

    // Use a command that should succeed
    let command_spec = CommandSpec::new("echo").arg("success");

    let output = executor.execute_with_retry(&command_spec).unwrap();
    assert!(output.status.success());
}

#[test]
fn test_temp_file_unique_names() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    let temp_dir = tempfile::tempdir().unwrap();
    let prefix = temp_dir.path().to_str().unwrap();

    // Create multiple temp files - they should have unique names
    let temp_file1 = executor.create_temp_file(prefix).unwrap();
    let temp_file2 = executor.create_temp_file(prefix).unwrap();
    let temp_file3 = executor.create_temp_file(prefix).unwrap();

    assert_ne!(temp_file1, temp_file2);
    assert_ne!(temp_file2, temp_file3);
    assert_ne!(temp_file1, temp_file3);

    // All should exist
    assert!(temp_file1.exists());
    assert!(temp_file2.exists());
    assert!(temp_file3.exists());

    // Clean up
    let _ = executor.cleanup_temp_file(&temp_file1);
    let _ = executor.cleanup_temp_file(&temp_file2);
    let _ = executor.cleanup_temp_file(&temp_file3);
}

#[test]
fn test_temp_file_directory_creation() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    // Use system temp directory which should always be writable
    let result = executor.create_temp_file("/tmp");
    assert!(result.is_ok());

    if let Ok(temp_file) = result {
        assert!(temp_file.exists());
        let _ = executor.cleanup_temp_file(&temp_file);
    }
}

#[test]
fn test_temp_file_content_isolation() {
    let options = ExecOptions::default();
    let executor = CommandExecutor::new(&options);

    let temp_dir = tempfile::tempdir().unwrap();
    let prefix = temp_dir.path().to_str().unwrap();

    let temp_file1 = executor.create_temp_file(prefix).unwrap();
    let temp_file2 = executor.create_temp_file(prefix).unwrap();

    // Write different content to each file
    fs::write(&temp_file1, "content1").unwrap();
    fs::write(&temp_file2, "content2").unwrap();

    // Verify content is isolated
    let content1 = fs::read_to_string(&temp_file1).unwrap();
    let content2 = fs::read_to_string(&temp_file2).unwrap();

    assert_eq!(content1, "content1");
    assert_eq!(content2, "content2");

    // Clean up
    let _ = executor.cleanup_temp_file(&temp_file1);
    let _ = executor.cleanup_temp_file(&temp_file2);
}

#[test]
fn test_executor_options_independence() {
    let options1 = ExecOptions::new().with_verbose(true);
    let options2 = ExecOptions::new().with_dry_run(true);

    let executor1 = CommandExecutor::new(&options1);
    let executor2 = CommandExecutor::new(&options2);

    assert!(executor1.is_verbose());
    assert!(!executor1.is_dry_run());

    assert!(!executor2.is_verbose());
    assert!(executor2.is_dry_run());
}

#[test]
fn test_mlxconfig_query_command_spec_execution() {
    let options = ExecOptions::new().with_retries(0); // No retries for faster test
    let _executor = CommandExecutor::new(&options);
    let builder = CommandBuilder::new("01:00.0", &options);

    let temp_dir = tempfile::tempdir().unwrap();
    let temp_file = temp_dir.path().join("test.json");
    let variables = vec!["TEST_VAR".to_string()];

    let command_spec = builder.build_query_command(&variables, &temp_file).unwrap();

    // We can't actually test mlxconfig execution (no hardware), but we can verify
    // the spec is properly constructed for execution
    assert_eq!(command_spec.program, "mlxconfig");
    assert!(command_spec.args.contains(&"-d".to_string()));
    assert!(command_spec.args.contains(&"01:00.0".to_string()));
    assert!(command_spec.args.contains(&"q".to_string()));
}

#[test]
fn test_mlxconfig_set_command_spec_execution() {
    let options = ExecOptions::new().with_retries(0).with_dry_run(true); // Dry run to avoid actual execution
    let executor = CommandExecutor::new(&options);
    let builder = CommandBuilder::new("01:00.0", &options);

    let assignments = vec!["SRIOV_EN=true".to_string()];
    let command_spec = builder.build_set_command(&assignments).unwrap();

    // Test dry run execution
    executor.execute_dry_run(&command_spec, "set");

    // Verify the spec is properly constructed
    assert_eq!(command_spec.program, "mlxconfig");
    assert!(command_spec.args.contains(&"--yes".to_string()));
    assert!(command_spec.args.contains(&"set".to_string()));
    assert!(command_spec.args.contains(&"SRIOV_EN=true".to_string()));
}

#[test]
fn test_command_spec_integration_with_builder() {
    let options = ExecOptions::default();
    let builder = CommandBuilder::new("02:00.0", &options);

    // Test that CommandBuilder properly creates CommandSpec objects
    let temp_file = Path::new("/tmp/integration_test.json");
    let variables = vec!["VAR1".to_string(), "VAR2".to_string()];

    let query_spec = builder.build_query_command(&variables, temp_file).unwrap();
    assert_eq!(query_spec.program, "mlxconfig");
    assert!(query_spec.args.contains(&"02:00.0".to_string()));

    let assignments = vec!["VAR1=value1".to_string()];
    let set_spec = builder.build_set_command(&assignments).unwrap();
    assert_eq!(set_spec.program, "mlxconfig");
    assert!(set_spec.args.contains(&"VAR1=value1".to_string()));
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_temp_file_lifecycle() {
        let options = ExecOptions::default();
        let executor = CommandExecutor::new(&options);

        let temp_dir = tempfile::tempdir().unwrap();
        let prefix = temp_dir.path().to_str().unwrap();

        // Full lifecycle test
        let temp_file = executor.create_temp_file(prefix).unwrap();

        // File should exist and be writable
        assert!(temp_file.exists());
        fs::write(&temp_file, "test data").unwrap();

        let content = fs::read_to_string(&temp_file).unwrap();
        assert_eq!(content, "test data");

        // Cleanup should remove file
        executor.cleanup_temp_file(&temp_file).unwrap();
        assert!(!temp_file.exists());
    }

    #[test]
    fn test_realistic_execution_options() {
        let production_options = ExecOptions::new()
            .with_timeout(Some(Duration::from_secs(30)))
            .with_retries(3)
            .with_retry_delay(Duration::from_millis(100))
            .with_verbose(false);

        let executor = CommandExecutor::new(&production_options);

        // Test with a command that should succeed
        let command_spec = CommandSpec::new("echo").arg("production test");

        let result = executor.execute_with_retry(&command_spec);
        assert!(result.is_ok());
    }

    #[test]
    fn test_timeout_with_retry() {
        // Test that timeout works correctly with retry logic
        let options = ExecOptions::new()
            .with_timeout(Some(Duration::from_millis(50))) // Very short timeout
            .with_retries(2)
            .with_retry_delay(Duration::from_millis(5)); // Fast retry

        let executor = CommandExecutor::new(&options);

        // Use sleep command that will consistently timeout
        let command_spec = CommandSpec::new("sleep").arg("1"); // Sleep for 1 second

        let start_time = std::time::Instant::now();
        let result = executor.execute_with_retry(&command_spec);
        let elapsed = start_time.elapsed();

        // Should fail with timeout
        assert!(result.is_err());

        // Should have attempted retries (3 total attempts with ~50ms timeout each)
        // Plus retry delays, should be at least 150ms but less than 1 second
        assert!(elapsed >= Duration::from_millis(150));
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn test_successful_command_with_timeout() {
        // Test that fast commands succeed even with timeouts
        let options = ExecOptions::new()
            .with_timeout(Some(Duration::from_secs(5))) // Generous timeout
            .with_retries(1);

        let executor = CommandExecutor::new(&options);

        // Use a command that should complete quickly
        let command_spec = CommandSpec::new("echo").arg("timeout test success");

        let output = executor.execute_with_retry(&command_spec).unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "timeout test success"
        );
    }

    #[test]
    fn test_exponential_backoff_timing() {
        // Test that retry delays actually follow exponential backoff pattern
        let options = ExecOptions::new()
            .with_retries(3)
            .with_retry_delay(Duration::from_millis(10))
            .with_max_retry_delay(Duration::from_millis(100))
            .with_retry_multiplier(2.0)
            .with_verbose(false); // Reduce noise in test output

        let executor = CommandExecutor::new(&options);

        // Use a command that will always fail to trigger retries
        let command_spec = CommandSpec::new("false");

        let start_time = std::time::Instant::now();
        let result = executor.execute_with_retry(&command_spec);
        let elapsed = start_time.elapsed();

        // Should fail after all retries
        assert!(result.is_err());

        // With exponential backoff starting at 10ms, multiplier 2.0:
        // Attempt 1: immediate
        // Delay 1: ~10ms
        // Attempt 2: immediate
        // Delay 2: ~20ms (2x)
        // Attempt 3: immediate
        // Delay 3: ~40ms (2x)
        // Attempt 4: immediate
        // Total should be roughly 70ms+ but allow for variance
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_secs(1)); // Sanity check
    }

    #[test]
    fn test_max_retry_delay_cap() {
        // Test that max_retry_delay properly caps the exponential growth
        let options = ExecOptions::new()
            .with_retries(5) // Many retries to test capping
            .with_retry_delay(Duration::from_millis(5))
            .with_max_retry_delay(Duration::from_millis(20)) // Low cap
            .with_retry_multiplier(10.0) // High multiplier that would exceed cap
            .with_verbose(false);

        let executor = CommandExecutor::new(&options);

        // Use a command that will always fail
        let command_spec = CommandSpec::new("false");

        let start_time = std::time::Instant::now();
        let result = executor.execute_with_retry(&command_spec);
        let elapsed = start_time.elapsed();

        // Should fail after all retries
        assert!(result.is_err());

        // Even with high multiplier (10x), delays should be capped at 20ms
        // So worst case: 5ms, 20ms, 20ms, 20ms, 20ms = ~85ms total
        // Allow some buffer but ensure it's not excessive
        assert!(elapsed >= Duration::from_millis(60));
        assert!(elapsed < Duration::from_millis(200));
    }

    #[test]
    fn test_builder_executor_integration() {
        // Test the full integration between CommandBuilder and CommandExecutor
        let options = ExecOptions::new().with_dry_run(true); // Dry run for safety
        let builder = CommandBuilder::new("01:00.0", &options);
        let executor = CommandExecutor::new(&options);

        // Test query command flow
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_file = temp_dir.path().join("integration.json");
        let variables = vec!["TEST_VAR".to_string()];

        let query_spec = builder.build_query_command(&variables, &temp_file).unwrap();
        executor.execute_dry_run(&query_spec, "query");

        // Test set command flow
        let assignments = vec!["TEST_VAR=test_value".to_string()];
        let set_spec = builder.build_set_command(&assignments).unwrap();
        executor.execute_dry_run(&set_spec, "set");

        // Both should complete without errors
    }

    #[test]
    fn test_different_multiplier_values() {
        // Test different multiplier values work correctly
        let test_cases = vec![
            (1.2, "conservative"),
            (2.0, "standard"),
            (3.0, "aggressive"),
        ];

        for (multiplier, test_name) in test_cases {
            let options = ExecOptions::new()
                .with_retries(1)
                .with_retry_delay(Duration::from_millis(10))
                .with_retry_multiplier(multiplier);

            let executor = CommandExecutor::new(&options);

            // Use a command that should succeed
            let command_spec = CommandSpec::new("echo").arg(format!("multiplier test {test_name}"));

            let output = executor.execute_with_retry(&command_spec).unwrap();
            assert!(output.status.success());
        }
    }
}

#[cfg(test)]
mod error_classification_tests {
    use super::*;

    #[test]
    fn test_all_permanent_errors() {
        let options = ExecOptions::default();
        let executor = CommandExecutor::new(&options);

        // Test all permanent error types
        let permanent_errors = vec![
            MlxRunnerError::VariableNotFound {
                variable_name: "TEST".to_string(),
            },
            MlxRunnerError::ArraySizeMismatch {
                variable_name: "TEST".to_string(),
                expected: 4,
                found: 6,
            },
            MlxRunnerError::ValueConversion {
                variable_name: "TEST".to_string(),
                value: "test".to_string(),
                error: mlxconfig_variables::MlxValueError::TypeMismatch {
                    expected: "int".to_string(),
                    got: "string".to_string(),
                },
            },
            MlxRunnerError::InvalidArrayIndex {
                variable_name: "TEST[invalid]".to_string(),
            },
            MlxRunnerError::DeviceMismatch {
                expected: "01:00.0".to_string(),
                actual: "02:00.0".to_string(),
            },
            MlxRunnerError::NoDeviceFound,
            MlxRunnerError::ConfirmationDeclined {
                variables: vec!["TEST".to_string()],
            },
            MlxRunnerError::JsonParsing {
                content: "{}".to_string(),
                error: serde_json::from_str::<serde_json::Value>("invalid json{").unwrap_err(),
            },
        ];

        for error in permanent_errors {
            assert!(
                !executor.should_retry_error(&error),
                "Error should be permanent: {error:?}"
            );
        }
    }

    #[test]
    fn test_all_transient_errors() {
        let options = ExecOptions::default();
        let executor = CommandExecutor::new(&options);

        // Test all transient error types
        let transient_errors = vec![
            MlxRunnerError::CommandExecution {
                command: "test".to_string(),
                exit_code: Some(1),
                stdout: "".to_string(),
                stderr: "error".to_string(),
            },
            MlxRunnerError::TempFileError {
                path: std::path::PathBuf::from("/tmp/test"),
                error: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test"),
            },
            MlxRunnerError::Timeout {
                command: "test".to_string(),
                duration: Duration::from_secs(1),
            },
            MlxRunnerError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "test",
            )),
        ];

        for error in transient_errors {
            assert!(
                executor.should_retry_error(&error),
                "Error should be transient: {error:?}"
            );
        }
    }

    #[test]
    fn test_edge_case_backoff_configurations() {
        // Test edge case configurations
        let edge_cases = vec![
            // No retries
            ExecOptions::new().with_retries(0),
            // Very fast initial delay
            ExecOptions::new().with_retry_delay(Duration::from_millis(1)),
            // Very high multiplier
            ExecOptions::new().with_retry_multiplier(100.0),
            // Very low multiplier (almost no growth)
            ExecOptions::new().with_retry_multiplier(1.01),
            // Max delay same as initial delay (no growth)
            ExecOptions::new()
                .with_retry_delay(Duration::from_millis(100))
                .with_max_retry_delay(Duration::from_millis(100)),
        ];

        for options in edge_cases {
            let executor = CommandExecutor::new(&options);

            // Test that all configurations work with a simple command
            let command_spec = CommandSpec::new("echo").arg("edge case test");

            let output = executor.execute_with_retry(&command_spec).unwrap();
            assert!(output.status.success());
        }
    }
}
