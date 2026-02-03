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

pub mod args;
pub mod cmds;

#[cfg(test)]
mod tests;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Inventory => cmds::inventory(&ctx.rms_client).await,
            Cmd::AddNode(args) => cmds::add_node(args, &ctx.rms_client).await,
            Cmd::RemoveNode(args) => cmds::remove_node(args, &ctx.rms_client).await,
            Cmd::PoweronOrder(args) => cmds::poweron_order(args, &ctx.rms_client).await,
            Cmd::PowerState(args) => cmds::power_state(args, &ctx.rms_client).await,
            Cmd::FirmwareInventory(args) => cmds::firmware_inventory(args, &ctx.rms_client).await,
            Cmd::AvailableFwImages(args) => cmds::available_fw_images(args, &ctx.rms_client).await,
            Cmd::BkcFiles => cmds::bkc_files(&ctx.rms_client).await,
            Cmd::CheckBkcCompliance => cmds::check_bkc_compliance(&ctx.rms_client).await,
        }
    }
}
