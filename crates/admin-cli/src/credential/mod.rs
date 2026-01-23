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
            Cmd::AddUFM(args) => cmds::add_ufm(args, &ctx.api_client).await,
            Cmd::DeleteUFM(args) => cmds::delete_ufm(args, &ctx.api_client).await,
            Cmd::GenerateUFMCert(args) => cmds::generate_ufm_cert(args, &ctx.api_client).await,
            Cmd::AddBMC(args) => cmds::add_bmc(args, &ctx.api_client).await,
            Cmd::DeleteBMC(args) => cmds::delete_bmc(args, &ctx.api_client).await,
            Cmd::AddUefi(args) => cmds::add_uefi(args, &ctx.api_client).await,
            Cmd::AddHostFactoryDefault(args) => {
                cmds::add_host_factory_default(args, &ctx.api_client).await
            }
            Cmd::AddDpuFactoryDefault(args) => {
                cmds::add_dpu_factory_default(args, &ctx.api_client).await
            }
            Cmd::AddNmxM(args) => cmds::add_nmxm(args, &ctx.api_client).await,
            Cmd::DeleteNmxM(args) => cmds::delete_nmxm(args, &ctx.api_client).await,
        }
    }
}
