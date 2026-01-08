/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    Get(BootOverride),
    Set(BootOverrideSet),
    Clear(BootOverride),
}

#[derive(Parser, Debug, Clone)]
pub struct BootOverride {
    pub interface_id: MachineInterfaceId,
}

#[derive(Parser, Debug, Clone)]
pub struct BootOverrideSet {
    pub interface_id: MachineInterfaceId,
    #[clap(short = 'p', long)]
    pub custom_pxe: Option<String>,
    #[clap(short = 'u', long)]
    pub custom_user_data: Option<String>,
}
