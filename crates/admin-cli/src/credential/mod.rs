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
