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

use carbide_test_support::{Check, check_values};
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
    check_values(
        [
            Check {
                scenario: "CommandFailed",
                input: MlxError::CommandFailed("test".to_string()),
                expect: "Command execution failed: test".to_string(),
            },
            Check {
                scenario: "DeviceNotFound",
                input: MlxError::DeviceNotFound("test_device".to_string()),
                expect: "Device not found: test_device".to_string(),
            },
            Check {
                scenario: "InvalidDeviceId",
                input: MlxError::InvalidDeviceId("invalid".to_string()),
                expect: "Invalid device ID format: invalid".to_string(),
            },
            Check {
                scenario: "AlreadyLocked",
                input: MlxError::AlreadyLocked,
                expect: "Hardware access is already disabled".to_string(),
            },
            Check {
                scenario: "AlreadyUnlocked",
                input: MlxError::AlreadyUnlocked,
                expect: "Hardware access is already enabled".to_string(),
            },
            Check {
                scenario: "InvalidKey",
                input: MlxError::InvalidKey,
                expect: "Invalid key format or length".to_string(),
            },
            Check {
                scenario: "PermissionDenied",
                input: MlxError::PermissionDenied,
                expect: "Permission denied - requires root privileges".to_string(),
            },
            Check {
                scenario: "FlintNotFound",
                input: MlxError::FlintNotFound,
                expect: "flint tool not found or not executable".to_string(),
            },
            Check {
                scenario: "ParseError",
                input: MlxError::ParseError("parse error".to_string()),
                expect: "Failed to parse command output: parse error".to_string(),
            },
            Check {
                scenario: "DryRun",
                input: MlxError::DryRun("flint -d 04:00.0 q".to_string()),
                expect: "Dry run - would have executed: flint -d 04:00.0 q".to_string(),
            },
            Check {
                scenario: "IoError wraps the inner message",
                input: MlxError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "file not found",
                )),
                expect: "I/O error: file not found".to_string(),
            },
        ],
        |error| error.to_string(),
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
