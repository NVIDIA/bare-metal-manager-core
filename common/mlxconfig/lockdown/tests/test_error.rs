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

use mlxconfig_lockdown::error::{MlxError, MlxResult};

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
