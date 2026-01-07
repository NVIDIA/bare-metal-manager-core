/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::machine::MachineInterfaceId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "List of all Machine interfaces")]
    Show(ShowMachineInterfaces),
    #[clap(about = "Delete Machine interface.")]
    Delete(DeleteMachineInterfaces),
}

#[derive(Parser, Debug)]
pub struct ShowMachineInterfaces {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "interface_id",
        help = "Show all machine interfaces (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(None),
        help = "The interface ID to query, leave empty for all (default)"
    )]
    pub interface_id: Option<MachineInterfaceId>,

    #[clap(long, action)]
    pub more: bool,
}

#[derive(Parser, Debug)]
pub struct DeleteMachineInterfaces {
    #[clap(help = "The interface ID to delete. Redeploy kea after deleting machine interfaces.")]
    pub interface_id: MachineInterfaceId,
}
