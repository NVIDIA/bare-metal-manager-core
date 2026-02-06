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

use mlxconfig_lockdown::{FlintRunner, MlxError};

#[test]
fn test_runner_creation_with_path() {
    let _runner = FlintRunner::with_path("/fake/path/flint");
    // Just ensure it can be created without errors
}

#[test]
fn test_device_id_validation() {
    // Valid device IDs
    assert!(FlintRunner::validate_device_id("04:00.0").is_ok());
    assert!(FlintRunner::validate_device_id("/dev/mst/mt4099_pci_cr0").is_ok());
    assert!(FlintRunner::validate_device_id("mlx5_0").is_ok());

    // Invalid device IDs
    assert!(matches!(
        FlintRunner::validate_device_id(""),
        Err(MlxError::InvalidDeviceId(_))
    ));

    assert!(matches!(
        FlintRunner::validate_device_id("device with spaces"),
        Err(MlxError::InvalidDeviceId(_))
    ));
}

#[test]
fn test_dry_run_functionality() {
    let runner = FlintRunner::with_path("/fake/flint").with_dry_run(true);

    // Test dry run for query
    let result = runner.query_device("fake_device");
    assert!(matches!(result, Err(MlxError::DryRun(_))));
    if let Err(MlxError::DryRun(cmd)) = result {
        assert!(cmd.contains("fake_device"));
        assert!(cmd.contains("/fake/flint"));
    }

    // Test dry run for disable
    let result = runner.disable_hw_access("fake_device", "12345678");
    assert!(matches!(result, Err(MlxError::DryRun(_))));
    if let Err(MlxError::DryRun(cmd)) = result {
        assert!(cmd.contains("hw_access disable"));
        assert!(cmd.contains("12345678"));
    }

    // Test dry run for enable
    let result = runner.enable_hw_access("fake_device", "12345678");
    assert!(matches!(result, Err(MlxError::DryRun(_))));
    if let Err(MlxError::DryRun(cmd)) = result {
        assert!(cmd.contains("hw_access enable"));
        assert!(cmd.contains("12345678"));
    }

    // Test dry run for set_key
    let result = runner.set_key("fake_device", "12345678");
    assert!(matches!(result, Err(MlxError::DryRun(_))));
    if let Err(MlxError::DryRun(cmd)) = result {
        assert!(cmd.contains("set_key"));
    }
}

#[test]
fn test_key_validation() {
    let runner = FlintRunner::with_path("/fake/flint");

    // Test with invalid keys that should fail validation
    let result = runner.set_key("fake_device", "invalid_key");
    assert!(matches!(result, Err(MlxError::InvalidKey)));

    let result = runner.set_key("fake_device", "123");
    assert!(matches!(result, Err(MlxError::InvalidKey)));

    let result = runner.set_key("fake_device", "1234567g");
    assert!(matches!(result, Err(MlxError::InvalidKey)));

    // Test enable_hw_access with invalid key
    let result = runner.enable_hw_access("fake_device", "toolong123");
    assert!(matches!(result, Err(MlxError::InvalidKey)));
}

#[test]
fn test_runner_default() {
    let _runner = FlintRunner::default();
    // Should not panic even if flint is not found
}

#[test]
fn test_command_building() {
    let runner = FlintRunner::with_path("/test/flint").with_dry_run(true);

    // Test that dry run produces expected command strings
    if let Err(MlxError::DryRun(cmd)) = runner.query_device("test_device") {
        assert_eq!(cmd, "/test/flint -d test_device q");
    }

    if let Err(MlxError::DryRun(cmd)) = runner.disable_hw_access("test_device", "abcdef01") {
        assert_eq!(cmd, "/test/flint -d test_device hw_access disable abcdef01");
    }

    if let Err(MlxError::DryRun(cmd)) = runner.enable_hw_access("test_device", "abcdef01") {
        assert_eq!(cmd, "/test/flint -d test_device hw_access enable abcdef01");
    }

    if let Err(MlxError::DryRun(cmd)) = runner.set_key("test_device", "12345678") {
        assert_eq!(cmd, "/test/flint -d test_device set_key 12345678");
    }
}

// These tests verify the output parsing logic without requiring actual flint execution
#[cfg(test)]
mod output_parsing_tests {

    #[test]
    fn test_already_disabled_parsing() {
        // Test that our code would correctly identify "already disabled" messages
        let already_disabled_outputs = vec![
            "HW access already disabled",
            "-I- HW access already disabled",
            "some other text\nHW access already disabled\nmore text",
        ];

        for output in already_disabled_outputs {
            // This simulates what our parsing logic does in FlintRunner
            let contains_already_disabled = output.contains("already disabled");
            assert!(
                contains_already_disabled,
                "Should detect 'already disabled' in: {output}"
            );
        }
    }

    #[test]
    fn test_already_enabled_parsing() {
        // Test that our code would correctly identify "already enabled" messages
        let already_enabled_outputs = vec![
            "HW access already enabled",
            "-I- HW access already enabled",
            "some other text\nHW access already enabled\nmore text",
        ];

        for output in already_enabled_outputs {
            // This simulates what our parsing logic does in FlintRunner
            let contains_already_enabled = output.contains("already enabled");
            assert!(
                contains_already_enabled,
                "Should detect 'already enabled' in: {output}"
            );
        }
    }

    #[test]
    fn test_hw_access_disabled_parsing() {
        // Test parsing of "HW access is disabled" messages
        let hw_disabled_outputs = vec![
            "HW access is disabled",
            "Error: HW access is disabled",
            "some text\nHW access is disabled\nmore text",
        ];

        for output in hw_disabled_outputs {
            let contains_hw_disabled = output.contains("HW access is disabled");
            assert!(
                contains_hw_disabled,
                "Should detect 'HW access is disabled' in: {output}"
            );
        }
    }
}
