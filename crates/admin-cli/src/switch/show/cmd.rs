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

use std::str::FromStr;

use carbide_uuid::switch::SwitchId;
use color_eyre::Result;
use prettytable::{Table, row};
use rpc::admin_cli::{CarbideCliResult, OutputFormat};
use rpc::forge::Switch;

use super::args::Args;
use crate::cfg::runtime::RuntimeConfig;
use crate::rpc::ApiClient;

pub fn show_switches(switches: Vec<Switch>, output_format: OutputFormat) -> Result<()> {
    match output_format {
        OutputFormat::AsciiTable => {
            let mut table = Table::new();
            table.set_titles(row![
                "ID",
                "Name",
                "Metadata Name",
                "Slot",
                "Tray",
                "Power State",
                "Health",
                "State"
            ]);

            for switch in &switches {
                let id = switch
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let name = switch
                    .config
                    .as_ref()
                    .map(|config| config.name.as_str())
                    .unwrap_or("N/A");

                let metadata_name = switch
                    .metadata
                    .as_ref()
                    .map(|m| m.name.as_str())
                    .unwrap_or("N/A");

                let slot_number = switch
                    .placement_in_rack
                    .as_ref()
                    .and_then(|p| p.slot_number)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let tray_index = switch
                    .placement_in_rack
                    .as_ref()
                    .and_then(|p| p.tray_index)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let power_state = switch
                    .status
                    .as_ref()
                    .and_then(|status| status.power_state.as_deref())
                    .unwrap_or("N/A");

                let health = switch
                    .status
                    .as_ref()
                    .and_then(|status| status.health_status.as_deref())
                    .unwrap_or("N/A");

                table.add_row(row![
                    id,
                    name,
                    metadata_name,
                    slot_number,
                    tray_index,
                    power_state,
                    health,
                    switch.controller_state,
                ]);
            }

            table.printstd();
        }
        OutputFormat::Json => {
            println!("JSON output not supported for Switch (protobuf type)");
            println!("Use ASCII table format instead.");
        }
        OutputFormat::Yaml => {
            println!("YAML output not supported for Switch (protobuf type)");
            println!("Use ASCII table format instead.");
        }
        OutputFormat::Csv => {
            let mut table = Table::new();
            table.set_titles(row![
                "ID",
                "Name",
                "Metadata Name",
                "Slot",
                "Tray",
                "Power State",
                "Health",
                "State"
            ]);

            for switch in &switches {
                let id = switch
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let name = switch
                    .config
                    .as_ref()
                    .map(|config| config.name.as_str())
                    .unwrap_or("N/A");

                let metadata_name = switch
                    .metadata
                    .as_ref()
                    .map(|m| m.name.as_str())
                    .unwrap_or("N/A");

                let slot_number = switch
                    .placement_in_rack
                    .as_ref()
                    .and_then(|p| p.slot_number)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let tray_index = switch
                    .placement_in_rack
                    .as_ref()
                    .and_then(|p| p.tray_index)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let power_state = switch
                    .status
                    .as_ref()
                    .and_then(|status| status.power_state.as_deref())
                    .unwrap_or("N/A");

                let health = switch
                    .status
                    .as_ref()
                    .and_then(|status| status.health_status.as_deref())
                    .unwrap_or("N/A");

                table.add_row(row![
                    id,
                    name,
                    metadata_name,
                    slot_number,
                    tray_index,
                    power_state,
                    health,
                    switch.controller_state,
                ]);
            }

            table.to_csv(std::io::stdout()).ok();
        }
    }

    Ok(())
}

pub async fn handle_show(
    args: Args,
    api_client: &ApiClient,
    config: &RuntimeConfig,
) -> CarbideCliResult<()> {
    let switches = match args.identifier {
        Some(id) if !id.is_empty() => match SwitchId::from_str(&id) {
            Ok(switch_id) => api_client.get_one_switch(switch_id).await?.switches,
            Err(_) => {
                // Fall back to name-based lookup
                let query = rpc::forge::SwitchQuery {
                    name: Some(id),
                    switch_id: None,
                };
                api_client.0.find_switches(query).await?.switches
            }
        },
        _ => {
            let filter = rpc::forge::SwitchSearchFilter::default();
            api_client
                .get_all_switches(filter, config.page_size)
                .await?
                .switches
        }
    };

    show_switches(switches, config.format).ok();
    Ok(())
}
