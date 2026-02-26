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

use std::borrow::Cow;
use std::str::FromStr;

use carbide_uuid::switch::SwitchId;
use color_eyre::Result;
use rpc::admin_cli::{CarbideCliResult, OutputFormat};
use rpc::forge::Switch;

use super::args::Args;
use crate::rpc::ApiClient;

pub fn show_switches(switches: Vec<Switch>, output_format: OutputFormat) -> Result<()> {
    match output_format {
        OutputFormat::AsciiTable => {
            println!("Switches:");
            println!(
                "{:<36} {:<20} {:<10} {:<10} {:<15} {:<10}",
                "ID", "Name", "Location", "Power State", "Health", "State"
            );
            println!("{:-<120}", "");

            for switch in &switches {
                let id = switch
                    .id
                    .as_ref()
                    .map(|id| Cow::Owned(id.to_string()))
                    .unwrap_or_else(|| Cow::Borrowed("N/A"));

                let name = switch
                    .config
                    .as_ref()
                    .map(|config| config.name.as_str())
                    .unwrap_or_else(|| "N/A");

                let location = switch
                    .config
                    .as_ref()
                    .and_then(|config| config.location.as_deref())
                    .unwrap_or("N/A");

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

                let controller_state = &switch.controller_state;

                println!(
                    "{:<36} {:<20} {:<10} {:<10} {:<15} {:<10}",
                    id, name, location, power_state, health, controller_state
                );
            }
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
            println!("ID,Name,Location,Power State,Health,State");
            for switch in &switches {
                let id = switch
                    .id
                    .as_ref()
                    .map(|id| Cow::Owned(id.to_string()))
                    .unwrap_or_else(|| Cow::Borrowed("N/A"));

                let name = switch
                    .config
                    .as_ref()
                    .map(|config| config.name.as_str())
                    .unwrap_or_else(|| "N/A");

                let location = switch
                    .config
                    .as_ref()
                    .and_then(|config| config.location.as_deref())
                    .unwrap_or("N/A");

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

                let controller_state = switch.controller_state.as_str();

                println!(
                    "{},{},{},{},{},{}",
                    id, name, location, power_state, health, controller_state
                );
            }
        }
    }

    Ok(())
}

pub async fn handle_show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let query = match args.identifier {
        Some(id) if !id.is_empty() => {
            // Try to parse as SwitchId, otherwise treat as name
            match SwitchId::from_str(&id) {
                Ok(switch_id) => rpc::forge::SwitchQuery {
                    name: None,
                    switch_id: Some(switch_id),
                },
                Err(_) => rpc::forge::SwitchQuery {
                    name: Some(id),
                    switch_id: None,
                },
            }
        }
        _ => {
            // No identifier provided, list all
            rpc::forge::SwitchQuery {
                name: None,
                switch_id: None,
            }
        }
    };

    let response = api_client.0.find_switches(query).await?;
    let switches = response.switches;

    show_switches(switches, output_format).ok();
    Ok(())
}
