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

use carbide_test_support::Outcome::*;
use carbide_test_support::{scenarios, value_scenarios};
use libmlx::lockdown::error::MlxError;
use libmlx::lockdown::runner::FlintRunner;

// validate_device_id accepts PCI addresses, device paths, and names, and rejects
// the empty string and anything with spaces. MlxError isn't PartialEq, so each row
// pins the rejection by its variant name rather than the whole error.
#[test]
fn test_device_id_validation() {
    fn validated(device_id: &str) -> Result<(), &'static str> {
        FlintRunner::validate_device_id(device_id).map_err(|e| match e {
            MlxError::InvalidDeviceId(_) => "InvalidDeviceId",
            _ => "other",
        })
    }

    scenarios!(
        run = validated;
        "PCI address" {
            "04:00.0" => Yields(()),
        }

        "device path" {
            "/dev/mst/mt4099_pci_cr0" => Yields(()),
        }

        "device name" {
            "mlx5_0" => Yields(()),
        }

        "empty string is rejected" {
            "" => FailsWith("InvalidDeviceId"),
        }

        "spaces are rejected" {
            "device with spaces" => FailsWith("InvalidDeviceId"),
        }
    );
}

// With dry-run enabled, every mutating/querying call returns DryRun(cmd) instead of
// shelling out; this checks the command string each one would have run. The exact
// string is the contract, so each row pins it; `dry_run_cmd` pulls the string out
// of the DryRun error (and panics loudly if a call unexpectedly didn't dry-run).
#[test]
fn test_dry_run_command_strings() {
    let runner = FlintRunner::with_path("/test/flint").with_dry_run(true);

    fn dry_run_cmd<T: std::fmt::Debug>(result: Result<T, MlxError>) -> String {
        match result {
            Err(MlxError::DryRun(cmd)) => cmd,
            other => panic!("expected DryRun, got {other:?}"),
        }
    }

    value_scenarios!(
        run = |cmd| cmd;
        "query" {
            dry_run_cmd(runner.query_device("test_device")) => "/test/flint -d test_device q".to_string(),
        }

        "disable hw_access" {
            dry_run_cmd(runner.disable_hw_access("test_device", "abcdef01")) => "/test/flint -d test_device hw_access disable abcdef01".to_string(),
        }

        "enable hw_access" {
            dry_run_cmd(runner.enable_hw_access("test_device", "abcdef01")) => "/test/flint -d test_device hw_access enable abcdef01".to_string(),
        }

        "set_key" {
            dry_run_cmd(runner.set_key("test_device", "12345678")) => "/test/flint -d test_device set_key 12345678".to_string(),
        }
    );
}

// Keys must be exactly 8 hex digits; set_key and enable_hw_access both reject a
// malformed key with InvalidKey before any command is built. MlxError isn't
// PartialEq, so each row pins the rejection by variant name.
#[test]
fn test_key_validation() {
    let runner = FlintRunner::with_path("/fake/flint");

    fn key_error(result: Result<(), MlxError>) -> Result<(), &'static str> {
        result.map_err(|e| match e {
            MlxError::InvalidKey => "InvalidKey",
            _ => "other",
        })
    }

    scenarios!(
        run = |result| result;
        "set_key with non-hex key" {
            key_error(runner.set_key("fake_device", "invalid_key")) => FailsWith("InvalidKey"),
        }

        "set_key with too-short key" {
            key_error(runner.set_key("fake_device", "123")) => FailsWith("InvalidKey"),
        }

        "set_key with a non-hex digit" {
            key_error(runner.set_key("fake_device", "1234567g")) => FailsWith("InvalidKey"),
        }

        "enable_hw_access with too-long key" {
            key_error(runner.enable_hw_access("fake_device", "toolong123")) => FailsWith("InvalidKey"),
        }
    );
}
