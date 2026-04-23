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

use carbide_uuid::machine::MachineId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

const MAX_FAILURE_DETAILS: usize = 10;

#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum NvSwitchComponentArg {
    Bmc,
    Cpld,
    Bios,
    Nvos,
}

impl From<NvSwitchComponentArg> for rpc::forge::NvSwitchComponent {
    fn from(component: NvSwitchComponentArg) -> Self {
        match component {
            NvSwitchComponentArg::Bmc => Self::Bmc,
            NvSwitchComponentArg::Cpld => Self::Cpld,
            NvSwitchComponentArg::Bios => Self::Bios,
            NvSwitchComponentArg::Nvos => Self::Nvos,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum PowerShelfComponentArg {
    Pmc,
    Psu,
}

impl From<PowerShelfComponentArg> for rpc::forge::PowerShelfComponent {
    fn from(component: PowerShelfComponentArg) -> Self {
        match component {
            PowerShelfComponentArg::Pmc => Self::Pmc,
            PowerShelfComponentArg::Psu => Self::Psu,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum ComputeTrayComponentArg {
    Bmc,
    Bios,
}

impl From<ComputeTrayComponentArg> for rpc::forge::ComputeTrayComponent {
    fn from(component: ComputeTrayComponentArg) -> Self {
        match component {
            ComputeTrayComponentArg::Bmc => Self::Bmc,
            ComputeTrayComponentArg::Bios => Self::Bios,
        }
    }
}

#[derive(ClapArgs, Debug)]
pub struct SwitchTargetArgs {
    #[clap(
        long = "switch-id",
        required = true,
        num_args = 1..,
        value_delimiter = ',',
        help = "Switch IDs to target"
    )]
    pub switch_ids: Vec<SwitchId>,
}

impl From<SwitchTargetArgs> for rpc::forge::SwitchIdList {
    fn from(args: SwitchTargetArgs) -> Self {
        Self {
            ids: args.switch_ids,
        }
    }
}

#[derive(ClapArgs, Debug)]
pub struct PowerShelfTargetArgs {
    #[clap(
        long = "power-shelf-id",
        required = true,
        num_args = 1..,
        value_delimiter = ',',
        help = "Power shelf IDs to target"
    )]
    pub power_shelf_ids: Vec<PowerShelfId>,
}

impl From<PowerShelfTargetArgs> for rpc::forge::PowerShelfIdList {
    fn from(args: PowerShelfTargetArgs) -> Self {
        Self {
            ids: args.power_shelf_ids,
        }
    }
}

#[derive(ClapArgs, Debug)]
pub struct MachineTargetArgs {
    #[clap(
        long = "machine-id",
        required = true,
        num_args = 1..,
        value_delimiter = ',',
        help = "Machine IDs to target"
    )]
    pub machine_ids: Vec<MachineId>,
}

impl From<MachineTargetArgs> for rpc::common::MachineIdList {
    fn from(args: MachineTargetArgs) -> Self {
        Self {
            machine_ids: args.machine_ids,
        }
    }
}

#[derive(ClapArgs, Debug)]
pub struct RackTargetArgs {
    #[clap(
        long = "rack-id",
        required = true,
        num_args = 1..,
        value_delimiter = ',',
        help = "Rack IDs to target"
    )]
    pub rack_ids: Vec<RackId>,
}

impl From<RackTargetArgs> for rpc::forge::RackIdList {
    fn from(args: RackTargetArgs) -> Self {
        Self {
            rack_ids: args.rack_ids,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum DeviceTargetArgs {
    #[clap(about = "Target NVLink switches")]
    Switch(SwitchTargetArgs),

    #[clap(about = "Target power shelves")]
    PowerShelf(PowerShelfTargetArgs),

    #[clap(about = "Target compute trays")]
    ComputeTray(MachineTargetArgs),

    #[clap(about = "Target racks")]
    Rack(RackTargetArgs),
}

pub fn component_result_status_name(status: i32) -> &'static str {
    match rpc::forge::ComponentManagerStatusCode::try_from(status) {
        Ok(rpc::forge::ComponentManagerStatusCode::Success) => "success",
        Ok(rpc::forge::ComponentManagerStatusCode::InvalidArgument) => "invalid-argument",
        Ok(rpc::forge::ComponentManagerStatusCode::InternalError) => "internal-error",
        Ok(rpc::forge::ComponentManagerStatusCode::NotFound) => "not-found",
        Ok(rpc::forge::ComponentManagerStatusCode::AlreadyExists) => "already-exists",
        Ok(rpc::forge::ComponentManagerStatusCode::Unavailable) => "unavailable",
        Err(_) => "unknown",
    }
}

pub fn firmware_state_name(state: i32) -> &'static str {
    match rpc::forge::FirmwareUpdateState::try_from(state) {
        Ok(rpc::forge::FirmwareUpdateState::FwStateUnknown) => "unknown",
        Ok(rpc::forge::FirmwareUpdateState::FwStateQueued) => "queued",
        Ok(rpc::forge::FirmwareUpdateState::FwStateInProgress) => "in-progress",
        Ok(rpc::forge::FirmwareUpdateState::FwStateVerifying) => "verifying",
        Ok(rpc::forge::FirmwareUpdateState::FwStateCompleted) => "completed",
        Ok(rpc::forge::FirmwareUpdateState::FwStateFailed) => "failed",
        Ok(rpc::forge::FirmwareUpdateState::FwStateCancelled) => "cancelled",
        Err(_) => "unknown",
    }
}

pub fn component_result_failed(result: Option<&rpc::forge::ComponentResult>) -> bool {
    result
        .map(|r| r.status != rpc::forge::ComponentManagerStatusCode::Success as i32)
        .unwrap_or(true)
}

pub fn component_failure_count_and_summary<'a>(
    results: impl IntoIterator<Item = Option<&'a rpc::forge::ComponentResult>>,
) -> (usize, String) {
    let mut failures = 0;
    let mut details = Vec::new();

    for result in results {
        if !component_result_failed(result) {
            continue;
        }

        failures += 1;
        if details.len() < MAX_FAILURE_DETAILS {
            details.push(component_failure_detail(result));
        }
    }

    if details.is_empty() {
        return (failures, String::new());
    }

    let mut summary = format!(": {}", details.join("; "));
    let omitted = failures.saturating_sub(details.len());
    if omitted > 0 {
        summary.push_str(&format!("; ... and {omitted} more"));
    }

    (failures, summary)
}

fn component_failure_detail(result: Option<&rpc::forge::ComponentResult>) -> String {
    let Some(result) = result else {
        return "unknown=missing-result".to_string();
    };

    let component_id = display_or_dash(&result.component_id);
    let status = component_result_status_name(result.status);
    if result.error.is_empty() {
        format!("{component_id}={status}({})", result.status)
    } else {
        format!(
            "{component_id}={status}({}): {}",
            result.status, result.error
        )
    }
}

pub fn component_result_fields(
    result: Option<&rpc::forge::ComponentResult>,
) -> (String, String, String) {
    match result {
        Some(result) => (
            display_or_dash(&result.component_id),
            component_result_status_name(result.status).to_string(),
            display_or_dash(&result.error),
        ),
        None => (
            "-".to_string(),
            "missing-result".to_string(),
            "-".to_string(),
        ),
    }
}

pub fn component_result_json(result: Option<&rpc::forge::ComponentResult>) -> serde_json::Value {
    match result {
        Some(result) => serde_json::json!({
            "component_id": result.component_id,
            "status": component_result_status_name(result.status),
            "status_code": result.status,
            "error": result.error,
        }),
        None => serde_json::Value::Null,
    }
}

pub fn timestamp_string(timestamp: Option<&rpc::Timestamp>) -> String {
    let Some(timestamp) = timestamp else {
        return "-".to_string();
    };
    let Ok(nanos) = u32::try_from(timestamp.nanos) else {
        return timestamp.seconds.to_string();
    };

    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp.seconds, nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| timestamp.seconds.to_string())
}

pub fn timestamp_json(timestamp: Option<&rpc::Timestamp>) -> serde_json::Value {
    match timestamp {
        Some(timestamp) => serde_json::json!({
            "seconds": timestamp.seconds,
            "nanos": timestamp.nanos,
            "rfc3339": timestamp_string(Some(timestamp)),
        }),
        None => serde_json::Value::Null,
    }
}

pub fn display_or_dash(value: &str) -> String {
    if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

pub fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}
