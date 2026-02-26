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

use std::path::Path;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Args;

use crate::cfg::run::Run;
use crate::cfg::runtime::RuntimeContext;
use crate::expected_machines::common::ExpectedMachineJson;

impl Run for Args {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        let json_file_path = Path::new(&self.filename);
        let file_content = std::fs::read_to_string(json_file_path)?;
        let expected_machine: ExpectedMachineJson = serde_json::from_str(&file_content)?;

        let metadata = expected_machine.metadata.unwrap_or_default();

        // Use patch API but provide all fields from JSON for full replacement
        ctx.api_client
            .patch_expected_machine(
                expected_machine.bmc_mac_address,
                Some(expected_machine.bmc_username),
                Some(expected_machine.bmc_password),
                Some(expected_machine.chassis_serial_number),
                expected_machine.fallback_dpu_serial_numbers,
                Some(metadata.name),
                Some(metadata.description),
                Some(
                    metadata
                        .labels
                        .into_iter()
                        .map(|label| {
                            if let Some(value) = label.value {
                                format!("{}:{}", label.key, value)
                            } else {
                                label.key
                            }
                        })
                        .collect(),
                ),
                expected_machine.sku_id,
                expected_machine.rack_id,
                expected_machine.default_pause_ingestion_and_poweron,
                expected_machine.dpf_enabled,
            )
            .await?;
        Ok(())
    }
}
