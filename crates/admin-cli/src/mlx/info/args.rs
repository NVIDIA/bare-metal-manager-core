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
