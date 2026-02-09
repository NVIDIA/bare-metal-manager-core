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

use ::rpc::protos::mlx_device::{LockStatus as LockStatusPb, StatusReport as StatusReportPb};
use chrono;
use serde::{Deserialize, Serialize};

use crate::error::{MlxError, MlxResult};
use crate::runner::FlintRunner;

// LockStatus represents the current lock status of a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockStatus {
    Locked,
    Unlocked,
    Unknown,
}

impl std::fmt::Display for LockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockStatus::Locked => write!(f, "locked"),
            LockStatus::Unlocked => write!(f, "unlocked"),
            LockStatus::Unknown => write!(f, "unknown"),
        }
    }
}

// LockdownManager is the main interface for managing device
// lockdown operations.
//
// Just to have this documented somewhere, it's important to call out
// a few notes around the behavior(s) with locking and unlocking cards.
//
// Behind the scenes, there's:
// - hw_access disable <device> <key>, which locks a card with a given key.
// - set_key disable <device> <key>, which does the exact same thing.
// - hw_access enable <device> <key>, which unlocks the card with the key.
//
// Originally I thought you had to set_key, and then you could lock at
// will, and had to unlock with the key. But it turns out that set_key
// and hw_access disable both appear to do the same thing now. If you try
// to call hw_access disable after set_key, it just tells you access
// is already disabled.
//
// I also thought you had to reboot/power cycle the card after changing
// the key, but based on testing, that also seems to not be the case
// either. Once you hw_access enable, it clears the key, and you need
// to either hw_access disable or set_key again (and can do it with a
// different key). This is actually nice, because I don't need to power
// cycle in between tenants (granted we will anyway, but it's one less
// power cycle to worry about).
//
// But fwiw, that behavior may also be card specific. I'm testing on
// a BF3 SuperNIC, and it's letting me do things as I described above.
pub struct LockdownManager {
    // runner is the flint command runner.
    runner: FlintRunner,
}

impl LockdownManager {
    // new creates a new LockdownManager instance.
    pub fn new() -> MlxResult<Self> {
        let runner = FlintRunner::new()?;
        Ok(Self { runner })
    }

    // with_dry_run creates a new LockdownManager with dry-run support.
    pub fn with_dry_run(dry_run: bool) -> MlxResult<Self> {
        let runner = if dry_run {
            // For dry-run, just explicitly set a path to skip the
            // discovery of the flint binary. The problem is on the
            // build machine, it doesn't have flint installed (which
            // is expected), so the CLI parsing tests fail, since it
            // tries to discover the location of the flint binary.
            // And I mean, tbh, it's not really needed anyway, but I
            // like having this subcommand stuff I can import, so I
            // kind of want to keep it maintained and tested.
            FlintRunner::with_path("flint").with_dry_run(true)
        } else {
            FlintRunner::new()?
        };
        Ok(Self { runner })
    }

    // with_runner creates a new LockdownManager with a custom runner.
    pub fn with_runner(runner: FlintRunner) -> Self {
        Self { runner }
    }

    // lock_device locks hardware access on the specified device with the provided key.
    pub fn lock_device(&self, device_id: &str, key: &str) -> MlxResult<LockStatus> {
        FlintRunner::validate_device_id(device_id)?;

        // This will now return an error if already locked instead of silently succeeding
        self.runner.disable_hw_access(device_id, key)?;
        Ok(LockStatus::Locked)
    }

    // unlock_device unlocks hardware access on the specified device with the provided key.
    pub fn unlock_device(&self, device_id: &str, key: &str) -> MlxResult<LockStatus> {
        FlintRunner::validate_device_id(device_id)?;

        // This will now return an error if already unlocked instead of silently succeeding
        self.runner.enable_hw_access(device_id, key)?;
        Ok(LockStatus::Unlocked)
    }

    // get_status gets the current lock status of the specified device.
    pub fn get_status(&self, device_id: &str) -> MlxResult<LockStatus> {
        FlintRunner::validate_device_id(device_id)?;

        match self.runner.query_device(device_id) {
            Ok(status_str) => match status_str.as_str() {
                "locked" => Ok(LockStatus::Locked),
                "unlocked" => Ok(LockStatus::Unlocked),
                _ => Ok(LockStatus::Unknown),
            },
            Err(e) => {
                // If we can't query, it might be locked
                match e {
                    MlxError::CommandFailed(ref msg) if msg.contains("HW access is disabled") => {
                        Ok(LockStatus::Locked)
                    }
                    _ => Err(e),
                }
            }
        }
    }

    // set_device_key sets a new hardware access key for the device.
    pub fn set_device_key(&self, device_id: &str, key: &str) -> MlxResult<()> {
        FlintRunner::validate_device_id(device_id)?;
        self.runner.set_key(device_id, key)
    }
}

impl Default for LockdownManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self::with_runner(FlintRunner::default()))
    }
}

// StatusReport is a structured status report for serialization.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReport {
    // device_id is the device identifier.
    pub device_id: String,
    // status is the current lock status.
    pub status: LockStatus,
    // timestamp is when the status was checked.
    pub timestamp: String,
}

impl StatusReport {
    // new creates a new status report.
    pub fn new(device_id: String, status: LockStatus) -> Self {
        Self {
            device_id,
            status,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // to_json serializes the status report to JSON.
    pub fn to_json(&self) -> MlxResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| e.into())
    }

    // to_yaml serializes the status report to YAML.
    pub fn to_yaml(&self) -> MlxResult<String> {
        serde_yaml::to_string(self).map_err(|e| MlxError::ParseError(e.to_string()))
    }
}

impl From<LockStatus> for LockStatusPb {
    fn from(status: LockStatus) -> Self {
        match status {
            LockStatus::Locked => LockStatusPb::Locked,
            LockStatus::Unlocked => LockStatusPb::Unlocked,
            LockStatus::Unknown => LockStatusPb::Unknown,
        }
    }
}

impl From<LockStatusPb> for LockStatus {
    fn from(pb: LockStatusPb) -> Self {
        match pb {
            LockStatusPb::Locked => LockStatus::Locked,
            LockStatusPb::Unlocked => LockStatus::Unlocked,
            LockStatusPb::Unknown => LockStatus::Unknown,
        }
    }
}

impl From<StatusReport> for StatusReportPb {
    fn from(report: StatusReport) -> Self {
        StatusReportPb {
            device_id: report.device_id,
            status: LockStatusPb::from(report.status) as i32,
            timestamp: report.timestamp,
        }
    }
}

impl From<StatusReportPb> for StatusReport {
    fn from(pb: StatusReportPb) -> Self {
        let status = LockStatusPb::try_from(pb.status)
            .map(LockStatus::from)
            .unwrap_or(LockStatus::Unknown);

        StatusReport {
            device_id: pb.device_id,
            status,
            timestamp: pb.timestamp,
        }
    }
}
