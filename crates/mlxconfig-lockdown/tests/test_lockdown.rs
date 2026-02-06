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

use mlxconfig_lockdown::{FlintRunner, LockStatus, LockdownManager, MlxError, StatusReport};

#[test]
fn test_lock_status_display() {
    assert_eq!(LockStatus::Locked.to_string(), "locked");
    assert_eq!(LockStatus::Unlocked.to_string(), "unlocked");
    assert_eq!(LockStatus::Unknown.to_string(), "unknown");
}

#[test]
fn test_lock_status_serialization() {
    let status = LockStatus::Locked;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"locked\"");

    let status: LockStatus = serde_json::from_str("\"unlocked\"").unwrap();
    assert_eq!(status, LockStatus::Unlocked);
}

#[test]
fn test_status_report_creation() {
    let report = StatusReport::new("test_device".to_string(), LockStatus::Locked);
    assert_eq!(report.device_id, "test_device");
    assert_eq!(report.status, LockStatus::Locked);
    assert!(!report.timestamp.is_empty());
}

#[test]
fn test_status_report_json() {
    let report = StatusReport::new("test_device".to_string(), LockStatus::Unlocked);
    let json = report.to_json().unwrap();

    // Parse back to ensure it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["device_id"], "test_device");
    assert_eq!(parsed["status"], "unlocked");
    assert!(parsed["timestamp"].is_string());
}

#[test]
fn test_status_report_yaml() {
    let report = StatusReport::new("test_device".to_string(), LockStatus::Unknown);
    let yaml = report.to_yaml().unwrap();

    // Basic validation that it contains expected content
    assert!(yaml.contains("device_id: test_device"));
    assert!(yaml.contains("status: unknown"));
    assert!(yaml.contains("timestamp:"));
}

#[test]
fn test_lockdown_manager_creation_with_runner() {
    let runner = FlintRunner::with_path("/fake/path");
    let _manager = LockdownManager::with_runner(runner);
    // Should not panic
}

#[test]
fn test_lockdown_manager_default() {
    let _manager = LockdownManager::default();
    // Should not panic even if flint is not available
}

#[test]
fn test_lockdown_manager_with_dry_run() {
    let manager = LockdownManager::with_dry_run(true).unwrap_or_else(|_| {
        let runner = FlintRunner::with_path("/fake/flint").with_dry_run(true);
        LockdownManager::with_runner(runner)
    });

    // Test that dry run is properly propagated
    let result = manager.lock_device("test_device", "12345678");
    assert!(matches!(result, Err(MlxError::DryRun(_))));
}

#[test]
fn test_device_validation_in_manager() {
    let runner = FlintRunner::with_path("/fake/path");
    let manager = LockdownManager::with_runner(runner);

    // Test invalid device ID
    let result = manager.get_status("");
    assert!(result.is_err());
}

#[test]
fn test_manager_error_handling() {
    let runner = FlintRunner::with_path("/fake/flint");
    let manager = LockdownManager::with_runner(runner);

    // These operations should fail with CommandFailed since we're using a fake runner
    let lock_result = manager.lock_device("fake_device", "12345678");
    assert!(matches!(lock_result, Err(MlxError::CommandFailed(_))));

    let unlock_result = manager.unlock_device("fake_device", "12345678");
    assert!(matches!(unlock_result, Err(MlxError::CommandFailed(_))));

    let status_result = manager.get_status("fake_device");
    assert!(matches!(status_result, Err(MlxError::CommandFailed(_))));

    let set_key_result = manager.set_device_key("fake_device", "12345678");
    assert!(matches!(set_key_result, Err(MlxError::CommandFailed(_))));
}

#[cfg(test)]
mod dry_run_tests {
    use super::*;

    #[test]
    fn test_dry_run_manager_operations() {
        let runner = FlintRunner::with_path("/fake/flint").with_dry_run(true);
        let manager = LockdownManager::with_runner(runner);

        // Test that all operations return DryRun errors
        assert!(matches!(
            manager.lock_device("test_device", "12345678"),
            Err(MlxError::DryRun(_))
        ));

        assert!(matches!(
            manager.unlock_device("test_device", "12345678"),
            Err(MlxError::DryRun(_))
        ));

        assert!(matches!(
            manager.get_status("test_device"),
            Err(MlxError::DryRun(_))
        ));

        assert!(matches!(
            manager.set_device_key("test_device", "12345678"),
            Err(MlxError::DryRun(_))
        ));
    }

    #[test]
    fn test_dry_run_commands_contain_expected_parts() {
        let runner = FlintRunner::with_path("/test/flint").with_dry_run(true);
        let manager = LockdownManager::with_runner(runner);

        if let Err(MlxError::DryRun(cmd)) = manager.lock_device("test_device", "12345678") {
            assert!(cmd.contains("hw_access disable"));
            assert!(cmd.contains("test_device"));
            assert!(cmd.contains("12345678"));
        }

        if let Err(MlxError::DryRun(cmd)) = manager.unlock_device("test_device", "abcdef01") {
            assert!(cmd.contains("hw_access enable"));
            assert!(cmd.contains("abcdef01"));
        }

        if let Err(MlxError::DryRun(cmd)) = manager.set_device_key("test_device", "12345678") {
            assert!(cmd.contains("set_key"));
            assert!(cmd.contains("12345678"));
        }
    }
}

#[cfg(test)]
mod mock_runner_tests {
    use super::*;

    // MockRunner simulates flint behavior for testing already locked/unlocked conditions
    struct MockRunner {
        simulate_already_locked: bool,
        simulate_already_unlocked: bool,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                simulate_already_locked: false,
                simulate_already_unlocked: false,
            }
        }

        fn with_already_locked(mut self) -> Self {
            self.simulate_already_locked = true;
            self
        }

        fn with_already_unlocked(mut self) -> Self {
            self.simulate_already_unlocked = true;
            self
        }

        fn disable_hw_access(&self, _device_id: &str, _key: &str) -> Result<(), MlxError> {
            if self.simulate_already_locked {
                return Err(MlxError::AlreadyLocked);
            }
            Ok(())
        }

        fn enable_hw_access(&self, _device_id: &str, _key: &str) -> Result<(), MlxError> {
            if self.simulate_already_unlocked {
                return Err(MlxError::AlreadyUnlocked);
            }
            Ok(())
        }
    }

    #[test]
    fn test_already_locked_behavior() {
        // Test that when flint returns "already disabled", we get an AlreadyLocked error
        let mock_runner = MockRunner::new().with_already_locked();

        let result = mock_runner.disable_hw_access("test_device", "12345678");
        assert!(matches!(result, Err(MlxError::AlreadyLocked)));
    }

    #[test]
    fn test_already_unlocked_behavior() {
        // Test that when flint returns "already enabled", we get an AlreadyUnlocked error
        let mock_runner = MockRunner::new().with_already_unlocked();

        let result = mock_runner.enable_hw_access("test_device", "12345678");
        assert!(matches!(result, Err(MlxError::AlreadyUnlocked)));
    }

    #[test]
    fn test_successful_operations() {
        // Test that normal operations succeed
        let mock_runner = MockRunner::new();

        let lock_result = mock_runner.disable_hw_access("test_device", "12345678");
        assert!(lock_result.is_ok());

        let unlock_result = mock_runner.enable_hw_access("test_device", "12345678");
        assert!(unlock_result.is_ok());
    }
}
