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

// connections/args.rs
// Command-line argument definitions for mlx connections commands.

use carbide_uuid::machine::MachineId;
use clap::Parser;
use rpc::protos::forge as forge_pb;

// ConnectionsCommand are the connections subcommands.
#[derive(Parser, Debug)]
pub enum ConnectionsCommand {
    #[clap(about = "Show all active scout stream connections")]
    Show(ConnectionsShowCommand),
    #[clap(about = "Disconnect a scout stream connection")]
    Disconnect(ConnectionsDisconnectCommand),
}

// ConnectionsShowCommand shows all active scout stream connections.
#[derive(Parser, Debug)]
pub struct ConnectionsShowCommand {}

// ConnectionsDisconnectCommand disconnects a machine based on machine ID.
#[derive(Parser, Debug)]
pub struct ConnectionsDisconnectCommand {
    pub machine_id: MachineId,
}

impl From<ConnectionsDisconnectCommand> for forge_pb::ScoutStreamDisconnectRequest {
    fn from(cmd: ConnectionsDisconnectCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
        }
    }
}
