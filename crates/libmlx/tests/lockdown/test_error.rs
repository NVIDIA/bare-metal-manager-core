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

use libmlx::lockdown::error::{MlxError, MlxResult};

#[test]
fn test_error_display() {
    let error = MlxError::DeviceNotFound("test_device".to_string());
    assert_eq!(error.to_string(), "Device not found: test_device");
}

#[test]
fn test_error_chain() {
    let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let mlx_error = MlxError::IoError(io_error);
    assert!(mlx_error.to_string().contains("file not found"));
}

#[test]
fn test_result_type() {
    fn test_function() -> MlxResult<i32> {
        Ok(42)
    }

    assert_eq!(test_function().unwrap(), 42);
}

#[test]
fn test_dry_run_error() {
    let cmd = "flint -d 04:00.0 q";
    let error = MlxError::DryRun(cmd.to_string());
    assert_eq!(
        error.to_string(),
        "Dry run - would have executed: flint -d 04:00.0 q"
    );
}

#[test]
fn test_all_error_variants() {
    let errors = vec![
        MlxError::CommandFailed("test".to_string()),
        MlxError::DeviceNotFound("device".to_string()),
        MlxError::InvalidDeviceId("invalid".to_string()),
        MlxError::AlreadyLocked,
        MlxError::AlreadyUnlocked,
        MlxError::InvalidKey,
        MlxError::PermissionDenied,
        MlxError::FlintNotFound,
        MlxError::ParseError("parse error".to_string()),
        MlxError::DryRun("cmd".to_string()),
    ];

    for error in errors {
        // Just ensure they can be displayed without panic
        let _ = error.to_string();
    }
}
