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

use carbide_test_support::value_scenarios;
use libmlx::lockdown::error::{MlxError, MlxResult};

// Every MlxError variant renders to an exact, contract-bearing string via its
// thiserror `#[error(...)]` Display impl. This one table is the single source of
// truth for that mapping -- it folds the old per-variant display tests (the
// DeviceNotFound and DryRun spot-checks, the IoError chain check) and subsumes the
// old "can every variant be displayed without panic" loop, since asserting the
// exact text exercises Display for each variant. The IoError row pins the full
// rendered string rather than the old `.contains` check -- a strictly stronger
// assertion. (SerializationError is omitted: constructing a serde_json::Error
// inline is awkward and the old loop didn't cover it either.)
#[test]
fn error_variants_display_their_contract_strings() {
    value_scenarios!(
        run = |error| error.to_string();
        "CommandFailed" {
            MlxError::CommandFailed("test".to_string()) => "Command execution failed: test".to_string(),
        }

        "DeviceNotFound" {
            MlxError::DeviceNotFound("test_device".to_string()) => "Device not found: test_device".to_string(),
        }

        "InvalidDeviceId" {
            MlxError::InvalidDeviceId("invalid".to_string()) => "Invalid device ID format: invalid".to_string(),
        }

        "AlreadyLocked" {
            MlxError::AlreadyLocked => "Hardware access is already disabled".to_string(),
        }

        "AlreadyUnlocked" {
            MlxError::AlreadyUnlocked => "Hardware access is already enabled".to_string(),
        }

        "InvalidKey" {
            MlxError::InvalidKey => "Invalid key format or length".to_string(),
        }

        "PermissionDenied" {
            MlxError::PermissionDenied => "Permission denied - requires root privileges".to_string(),
        }

        "FlintNotFound" {
            MlxError::FlintNotFound => "flint tool not found or not executable".to_string(),
        }

        "ParseError" {
            MlxError::ParseError("parse error".to_string()) => "Failed to parse command output: parse error".to_string(),
        }

        "DryRun" {
            MlxError::DryRun("flint -d 04:00.0 q".to_string()) => "Dry run - would have executed: flint -d 04:00.0 q".to_string(),
        }

        "IoError wraps the inner message" {
            MlxError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            )) => "I/O error: file not found".to_string(),
        }
    );
}

// The MlxResult<T> alias is just Result<T, MlxError> -- this keeps a standalone
// guard that an Ok flows through it unchanged.
#[test]
fn test_result_type() {
    fn test_function() -> MlxResult<i32> {
        Ok(42)
    }

    assert_eq!(test_function().unwrap(), 42);
}
