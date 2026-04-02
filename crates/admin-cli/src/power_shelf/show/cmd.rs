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

use color_eyre::Result;
use prettytable::{Table, row};
use rpc::admin_cli::{CarbideCliResult, OutputFormat};
use rpc::forge::PowerShelf;

use super::args::Args;
use crate::rpc::ApiClient;

pub fn show_power_shelves(
    power_shelves: Vec<PowerShelf>,
    output_format: OutputFormat,
) -> Result<()> {
    let build_table = |shelves: &[PowerShelf]| -> Table {
        let mut table = Table::new();
        table.set_titles(row![
            "ID",
            "Name",
            "Metadata Name",
            "Capacity(W)",
            "Voltage(V)",
            "Location",
            "Power State",
            "Health",
            "State"
        ]);

        for shelf in shelves {
            let metadata_name = shelf
                .metadata
                .as_ref()
                .map(|m| m.name.as_str())
                .unwrap_or("N/A");

            table.add_row(row![
                shelf
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                shelf
                    .config
                    .as_ref()
                    .map(|c| c.name.as_str())
                    .unwrap_or("N/A"),
                metadata_name,
                shelf
                    .config
                    .as_ref()
                    .and_then(|c| c.capacity)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                shelf
                    .config
                    .as_ref()
                    .and_then(|c| c.voltage)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                shelf
                    .config
                    .as_ref()
                    .and_then(|c| c.location.as_deref())
                    .unwrap_or("N/A"),
                shelf
                    .status
                    .as_ref()
                    .and_then(|s| s.power_state.as_deref())
                    .unwrap_or("N/A"),
                shelf
                    .status
                    .as_ref()
                    .and_then(|s| s.health_status.as_deref())
                    .unwrap_or("N/A"),
                shelf.controller_state,
            ]);
        }

        table
    };

    match output_format {
        OutputFormat::AsciiTable => {
            build_table(&power_shelves).printstd();
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
            build_table(&power_shelves).to_csv(std::io::stdout()).ok();
        }
    }

    Ok(())
}

pub async fn handle_show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let response = api_client.0.find_power_shelves(args).await?;
    let power_shelves = response.power_shelves;

    show_power_shelves(power_shelves, output_format).ok();
    Ok(())
}
