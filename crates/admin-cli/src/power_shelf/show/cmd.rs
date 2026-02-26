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

use carbide_uuid::power_shelf::PowerShelfId;
use color_eyre::Result;
use rpc::admin_cli::{CarbideCliResult, OutputFormat};
use rpc::forge::PowerShelf;

use super::args::Args;
use crate::rpc::ApiClient;

pub fn show_power_shelves(
    power_shelves: Vec<PowerShelf>,
    output_format: OutputFormat,
) -> Result<()> {
    match output_format {
        OutputFormat::AsciiTable => {
            println!("Power Shelves:");
            println!(
                "{:<36} {:<20} {:<10} {:<10} {:<15} {:<10} {:<10} {:<10}",
                "ID",
                "Name",
                "Capacity(W)",
                "Voltage(V)",
                "Location",
                "Power State",
                "Health",
                "State"
            );
            println!("{:-<120}", "");

            for shelf in power_shelves {
                let id = shelf
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let name = shelf
                    .config
                    .as_ref()
                    .map(|config| config.name.as_str())
                    .unwrap_or_else(|| "N/A");

                let capacity = shelf
                    .config
                    .as_ref()
                    .and_then(|config| config.capacity)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let voltage = shelf
                    .config
                    .as_ref()
                    .and_then(|config| config.voltage)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let location = shelf
                    .config
                    .as_ref()
                    .and_then(|config| config.location.as_deref())
                    .unwrap_or("N/A");

                let power_state = shelf
                    .status
                    .as_ref()
                    .and_then(|status| status.power_state.as_deref())
                    .unwrap_or("N/A");

                let health = shelf
                    .status
                    .as_ref()
                    .and_then(|status| status.health_status.as_deref())
                    .unwrap_or("N/A");

                let controller_state = shelf.controller_state.as_str();

                println!(
                    "{:<36} {:<20} {:<10} {:<10} {:<15} {:<10} {:<10} {:<25}",
                    id, name, capacity, voltage, location, power_state, health, controller_state
                );
            }
        }
        OutputFormat::Json => {
            println!("JSON output not supported for PowerShelf (protobuf type)");
            println!("Use ASCII table format instead.");
        }
        OutputFormat::Yaml => {
            println!("YAML output not supported for PowerShelf (protobuf type)");
            println!("Use ASCII table format instead.");
        }
        OutputFormat::Csv => {
            println!("ID,Name,Capacity(W),Voltage(V),Location,Power State,Health");
            for shelf in &power_shelves {
                let id = shelf
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let name = shelf
                    .config
                    .as_ref()
                    .map(|config| config.name.as_str())
                    .unwrap_or_else(|| "N/A");

                let capacity = shelf
                    .config
                    .as_ref()
                    .and_then(|config| config.capacity)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let voltage = shelf
                    .config
                    .as_ref()
                    .and_then(|config| config.voltage)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string());

                let location = shelf
                    .config
                    .as_ref()
                    .and_then(|config| config.location.as_deref())
                    .unwrap_or("N/A");

                let power_state = shelf
                    .status
                    .as_ref()
                    .and_then(|status| status.power_state.as_deref())
                    .unwrap_or("N/A");

                let health = shelf
                    .status
                    .as_ref()
                    .and_then(|status| status.health_status.as_deref())
                    .unwrap_or("N/A");

                let controller_state = shelf.controller_state.as_str();

                println!(
                    "{},{},{},{},{},{},{},{}",
                    id, name, capacity, voltage, location, power_state, health, controller_state
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
            // Try to parse as PowerShelfId, otherwise treat as name.
            match PowerShelfId::from_str(&id) {
                Ok(power_shelf_id) => rpc::forge::PowerShelfQuery {
                    name: None,
                    power_shelf_id: Some(power_shelf_id),
                },
                Err(_) => rpc::forge::PowerShelfQuery {
                    name: Some(id),
                    power_shelf_id: None,
                },
            }
        }
        _ => {
            // No identifier provided, list all
            rpc::forge::PowerShelfQuery {
                name: None,
                power_shelf_id: None,
            }
        }
    };

    let response = api_client.0.find_power_shelves(query).await?;
    let power_shelves = response.power_shelves;

    show_power_shelves(power_shelves, output_format).ok();
    Ok(())
}
