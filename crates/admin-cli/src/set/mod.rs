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
            Cmd::LogFilter(opts) => cmds::log_filter(opts, &ctx.api_client).await,
            Cmd::CreateMachines(opts) => cmds::create_machines(opts, &ctx.api_client).await,
            Cmd::BmcProxy(opts) => cmds::bmc_proxy(opts, &ctx.api_client).await,
            Cmd::TracingEnabled { value } => cmds::tracing_enabled(value, &ctx.api_client).await,
        }
    }
}
