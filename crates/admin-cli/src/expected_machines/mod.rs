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

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;
use serde::{Deserialize, Serialize};

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(query) => {
                cmds::show_expected_machines(
                    &query,
                    &ctx.api_client,
                    ctx.config.format,
                    &mut ctx.output_file,
                )
                .await?;
                Ok(())
            }
            Cmd::Add(expected_machine_data) => {
                if expected_machine_data.has_duplicate_dpu_serials() {
                    eprintln!("Duplicate values not allowed for --fallback-dpu-serial-number");
                    return Ok(());
                }
                let expected_machine: rpc::forge::ExpectedMachine =
                    expected_machine_data.try_into()?;
                ctx.api_client
                    .0
                    .add_expected_machine(expected_machine)
                    .await?;
                Ok(())
            }
            Cmd::Delete(query) => {
                ctx.api_client
                    .0
                    .delete_expected_machine(::rpc::forge::ExpectedMachineRequest {
                        bmc_mac_address: query.bmc_mac_address.to_string(),
                        id: None,
                    })
                    .await?;
                Ok(())
            }
            Cmd::Patch(expected_machine_data) => {
                if let Err(e) = expected_machine_data.validate() {
                    eprintln!("{e}");
                    return Ok(());
                }
                ctx.api_client
                    .patch_expected_machine(
                        expected_machine_data.bmc_mac_address,
                        expected_machine_data.bmc_username,
                        expected_machine_data.bmc_password,
                        expected_machine_data.chassis_serial_number,
                        expected_machine_data.fallback_dpu_serial_numbers,
                        expected_machine_data.meta_name,
                        expected_machine_data.meta_description,
                        expected_machine_data.labels,
                        expected_machine_data.sku_id,
                        expected_machine_data.rack_id,
                        expected_machine_data.default_pause_ingestion_and_poweron,
                        expected_machine_data.dpf_enabled,
                    )
                    .await?;
                Ok(())
            }
            Cmd::Update(request) => {
                let json_file_path = Path::new(&request.filename);
                let file_content = std::fs::read_to_string(json_file_path)?;
                let expected_machine: args::ExpectedMachineJson =
                    serde_json::from_str(&file_content)?;

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
            Cmd::ReplaceAll(request) => {
                let json_file_path = Path::new(&request.filename);
                let reader = BufReader::new(File::open(json_file_path)?);
                #[derive(Debug, Serialize, Deserialize)]
                struct ExpectedMachineList {
                    expected_machines: Vec<args::ExpectedMachineJson>,
                    expected_machines_count: Option<usize>,
                }
                let expected_machine_list: ExpectedMachineList = serde_json::from_reader(reader)?;

                if expected_machine_list
                    .expected_machines_count
                    .is_some_and(|c| c != expected_machine_list.expected_machines.len())
                {
                    eprintln!(
                        "WARNING: expected_machines_count does not match actual number of entries"
                    );
                }

                ctx.api_client
                    .replace_all_expected_machines(expected_machine_list.expected_machines)
                    .await?;
                Ok(())
            }
            Cmd::Erase => {
                ctx.api_client.0.delete_all_expected_machines().await?;
                Ok(())
            }
        }
    }
}
