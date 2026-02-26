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
pub mod cmd;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Args;

use crate::cfg::run::Run;
use crate::cfg::runtime::RuntimeContext;

impl Run for Args {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        if let Err(e) = self.validate() {
            eprintln!("{e}");
            return Ok(());
        }
        ctx.api_client
            .patch_expected_machine(
                self.bmc_mac_address,
                self.bmc_username,
                self.bmc_password,
                self.chassis_serial_number,
                self.fallback_dpu_serial_numbers,
                self.meta_name,
                self.meta_description,
                self.labels,
                self.sku_id,
                self.rack_id,
                self.default_pause_ingestion_and_poweron,
                self.dpf_enabled,
            )
            .await?;
        Ok(())
    }
}
