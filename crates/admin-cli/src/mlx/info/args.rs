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

// info/args.rs
// Command-line argument definitions for info commands.

use carbide_uuid::machine::MachineId;
use clap::Parser;
use rpc::protos::mlx_device as mlx_device_pb;

// InfoCommand are the info subcommands.
#[derive(Parser, Debug)]
pub enum InfoCommand {
    #[clap(about = "Get MlxDeviceInfo for a device on a machine")]
    Device(InfoDeviceCommand),

    #[clap(about = "Get an MlxDeviceReport for a machine")]
    Machine(InfoMachineCommand),
}

// InfoDeviceCommand shows device information.
#[derive(Parser, Debug)]
pub struct InfoDeviceCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,
}

// InfoMachineCommand shows machine information.
#[derive(Parser, Debug)]
pub struct InfoMachineCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,
}

impl From<InfoDeviceCommand> for mlx_device_pb::MlxAdminDeviceInfoRequest {
    fn from(cmd: InfoDeviceCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
        }
    }
}

impl From<InfoMachineCommand> for mlx_device_pb::MlxAdminDeviceReportRequest {
    fn from(cmd: InfoMachineCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
        }
    }
}
