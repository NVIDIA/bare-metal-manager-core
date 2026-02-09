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

// config/args.rs
// Command-line argument definitions for config commands.

use carbide_uuid::machine::MachineId;
use clap::Parser;
use rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use rpc::protos::mlx_device as mlx_device_pb;

// ConfigCommand are the config subcommands.
#[derive(Parser, Debug)]
pub enum ConfigCommand {
    #[clap(about = "Query device configuration values")]
    Query(ConfigQueryCommand),

    #[clap(about = "Set device configuration values")]
    Set(ConfigSetCommand),

    #[clap(about = "Synchronize configuration values to a device")]
    Sync(ConfigSyncCommand),

    #[clap(about = "Compare device configuration against expected values")]
    Compare(ConfigCompareCommand),
}

// ConfigQueryCommand queries device configuration values.
#[derive(Parser, Debug)]
pub struct ConfigQueryCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,

    // registry_name is the registry to use.
    #[arg(help = "Backing variable registry to query against")]
    pub registry_name: String,
    // variables are optional specific variables to query.
    #[arg(help = "Variables to query, all if unset.", value_delimiter = ',')]
    pub variables: Vec<String>,
}

// ConfigSetCommand sets device configuration values.
#[derive(Parser, Debug)]
pub struct ConfigSetCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,

    // registry_name is the registry to use.
    pub registry_name: String,
    // assignments are variable=value assignments.
    #[arg(value_delimiter = ',')]
    pub assignments: Vec<String>,
}

// ConfigSyncCommand synchronizes configuration values to a device.
#[derive(Parser, Debug)]
pub struct ConfigSyncCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,

    // registry_name is the registry to use.
    pub registry_name: String,
    // assignments are variable=value assignments.
    #[arg(value_delimiter = ',')]
    pub assignments: Vec<String>,
}

// ConfigCompareCommand compares device configuration against expected values.
#[derive(Parser, Debug)]
pub struct ConfigCompareCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,

    // registry_name is the registry to use.
    pub registry_name: String,
    // assignments are variable=value assignments.
    #[arg(value_delimiter = ',')]
    pub assignments: Vec<String>,
}

impl From<ConfigQueryCommand> for mlx_device_pb::MlxAdminConfigQueryRequest {
    fn from(cmd: ConfigQueryCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
            registry_name: cmd.registry_name,
            variables: cmd.variables,
        }
    }
}

impl TryFrom<ConfigSetCommand> for mlx_device_pb::MlxAdminConfigSetRequest {
    type Error = CarbideCliError;

    fn try_from(cmd: ConfigSetCommand) -> Result<Self, Self::Error> {
        let parsed_assignments = parse_assignments(&cmd.assignments)?;
        Ok(Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
            registry_name: cmd.registry_name,
            assignments: parsed_assignments,
        })
    }
}

impl TryFrom<ConfigSyncCommand> for mlx_device_pb::MlxAdminConfigSyncRequest {
    type Error = CarbideCliError;

    fn try_from(cmd: ConfigSyncCommand) -> Result<Self, Self::Error> {
        let parsed_assignments = parse_assignments(&cmd.assignments)?;
        Ok(Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
            registry_name: cmd.registry_name,
            assignments: parsed_assignments,
        })
    }
}

impl TryFrom<ConfigCompareCommand> for mlx_device_pb::MlxAdminConfigCompareRequest {
    type Error = CarbideCliError;

    fn try_from(cmd: ConfigCompareCommand) -> Result<Self, Self::Error> {
        let parsed_assignments = parse_assignments(&cmd.assignments)?;
        Ok(Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
            registry_name: cmd.registry_name,
            assignments: parsed_assignments,
        })
    }
}

// parse_assignments is a helper to parse "var=value" assignments.
fn parse_assignments(
    assignments: &[String],
) -> CarbideCliResult<Vec<mlx_device_pb::VariableAssignment>> {
    let mut result = Vec::new();

    for assignment in assignments {
        let parts: Vec<&str> = assignment.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(CarbideCliError::GenericError(format!(
                "invalid assignment format: {assignment} (expected: variable=value)"
            )));
        }

        result.push(mlx_device_pb::VariableAssignment {
            variable_name: parts[0].to_string(),
            value: parts[1].to_string(),
        });
    }

    Ok(result)
}
