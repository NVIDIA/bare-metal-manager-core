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

use std::process::{Command, Stdio};

use crate::error::{MlxError, MlxResult};

// FlintRunner is a wrapper for executing flint commands.
pub struct FlintRunner {
    // flint_path is the path to the flint executable.
    flint_path: String,
    // dry_run determines whether to perform dry-run operations.
    dry_run: bool,
}

impl FlintRunner {
    // new creates a new FlintRunner instance.
    pub fn new() -> MlxResult<Self> {
        let flint_path = Self::find_flint()?;
        Ok(Self {
            flint_path,
            dry_run: false,
        })
    }

    // with_path creates a new FlintRunner with a custom flint path.
    pub fn with_path<P: Into<String>>(path: P) -> Self {
        Self {
            flint_path: path.into(),
            dry_run: false,
        }
    }

    // with_dry_run creates a FlintRunner with dry-run enabled.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    // find_flint attempts to find the flint executable in common locations.
    fn find_flint() -> MlxResult<String> {
        let common_paths = [
            "flint",
            "/usr/bin/flint",
            "/usr/local/bin/flint",
            "/opt/mellanox/mft/bin/flint",
        ];

        for path in &common_paths {
            if let Ok(output) = Command::new(path)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                && output.success()
            {
                return Ok(path.to_string());
            }
        }

        Err(MlxError::FlintNotFound)
    }

    // build_command builds a command string for logging/dry-run purposes.
    fn build_command(&self, args: &[&str]) -> String {
        format!("{} {}", self.flint_path, args.join(" "))
    }

    // query_device queries device information and hardware access status.
    pub fn query_device(&self, device_id: &str) -> MlxResult<String> {
        let args = ["-d", device_id, "q"];

        if self.dry_run {
            return Err(MlxError::DryRun(self.build_command(&args)));
        }

        let output = Command::new(&self.flint_path)
            .args(args)
            .output()
            .map_err(|e| MlxError::CommandFailed(format!("Failed to execute query: {e}")))?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Check specific error conditions first.
            if stderr.contains("HW access is disabled") || stdout.contains("HW access is disabled")
            {
                return Ok("locked".to_string());
            } else if stderr.contains("Cannot open") || stdout.contains("Cannot open") {
                return Err(MlxError::DeviceNotFound(device_id.to_string()));
            } else if stderr.contains("Permission denied") || stdout.contains("Permission denied") {
                return Err(MlxError::PermissionDenied);
            }

            let error_msg = format!("stdout: {}\nstderr: {}", stdout.trim(), stderr.trim());
            return Err(MlxError::CommandFailed(error_msg));
        }

        Ok("unlocked".to_string())
    }

    // enable_hw_access enables hardware access with the provided key.
    pub fn enable_hw_access(&self, device_id: &str, key: &str) -> MlxResult<()> {
        // Validate key format (should be 8 hex digits for 64-bit key)
        if !Self::is_valid_key(key) {
            return Err(MlxError::InvalidKey);
        }

        let args = ["-d", device_id, "hw_access", "enable", key];

        if self.dry_run {
            return Err(MlxError::DryRun(self.build_command(&args)));
        }

        let output = Command::new(&self.flint_path)
            .args(args)
            .output()
            .map_err(|e| MlxError::CommandFailed(format!("Failed to execute enable: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check for "already enabled" even on success (exit code 0)
        if stderr.contains("already enabled") || stdout.contains("already enabled") {
            return Err(MlxError::AlreadyUnlocked);
        }

        if !output.status.success() {
            let error_msg = format!("stdout: {}\nstderr: {}", stdout.trim(), stderr.trim());
            return Err(MlxError::CommandFailed(error_msg));
        }

        Ok(())
    }

    // disable_hw_access disables hardware access with the provided key.
    pub fn disable_hw_access(&self, device_id: &str, key: &str) -> MlxResult<()> {
        // Validate key format (should be 8 hex digits for 64-bit key)
        if !Self::is_valid_key(key) {
            return Err(MlxError::InvalidKey);
        }

        let args = ["-d", device_id, "hw_access", "disable", key];

        if self.dry_run {
            return Err(MlxError::DryRun(self.build_command(&args)));
        }

        let output = Command::new(&self.flint_path)
            .args(args)
            .output()
            .map_err(|e| MlxError::CommandFailed(format!("Failed to execute disable: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check for "already disabled" even on success (exit code 0)
        if stderr.contains("already disabled") || stdout.contains("already disabled") {
            return Err(MlxError::AlreadyLocked);
        }

        if !output.status.success() {
            let error_msg = format!("stdout: {}\nstderr: {}", stdout.trim(), stderr.trim());
            return Err(MlxError::CommandFailed(error_msg));
        }

        Ok(())
    }

    // set_key sets a new hardware access key.
    pub fn set_key(&self, device_id: &str, key: &str) -> MlxResult<()> {
        if !Self::is_valid_key(key) {
            return Err(MlxError::InvalidKey);
        }

        let args = ["-d", device_id, "set_key", key];

        if self.dry_run {
            return Err(MlxError::DryRun(self.build_command(&args)));
        }

        let output = Command::new(&self.flint_path)
            .args(args)
            .output()
            .map_err(|e| MlxError::CommandFailed(format!("Failed to execute set_key: {e}")))?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error_msg = format!("stdout: {}\nstderr: {}", stdout.trim(), stderr.trim());
            return Err(MlxError::CommandFailed(error_msg));
        }

        Ok(())
    }

    // is_valid_key validates that the key is in the correct format (8 hex digits).
    fn is_valid_key(key: &str) -> bool {
        key.len() == 8 && key.chars().all(|c| c.is_ascii_hexdigit())
    }

    // validate_device_id validates device ID format.
    pub fn validate_device_id(device_id: &str) -> MlxResult<()> {
        // Accept various formats: PCI addresses (XX:XX.X), device paths, or names
        if device_id.is_empty() {
            return Err(MlxError::InvalidDeviceId(
                "Device ID cannot be empty".to_string(),
            ));
        }

        // Basic validation.
        // TODO(chet): Wire this in with the device module ID parsing; this
        // is basically just a placeholder for me to improve on later.
        if device_id.contains(' ') {
            return Err(MlxError::InvalidDeviceId(
                "Device ID cannot contain spaces".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for FlintRunner {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self::with_path("flint"))
    }
}
