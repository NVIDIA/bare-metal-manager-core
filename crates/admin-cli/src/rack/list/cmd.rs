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
use prettytable::{Cell, Row, Table};
use rpc::admin_cli::OutputFormat;

use crate::rpc::ApiClient;

pub async fn list_racks(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::GetRackRequest { id: None };
    let response = api_client.0.get_rack(query).await?;
    let racks = response.rack;
    if racks.is_empty() {
        println!("No racks found");
        return Ok(());
    }

    let format = OutputFormat::AsciiTable;
    match format {
        OutputFormat::AsciiTable => {
            let mut table = Table::new();
            let headers = vec![
                "Rack ID",
                "Rack State",
                "Expected Compute Trays",
                "Current Compute Tray IDs",
                "Expected Power Shelves",
                "Current Power Shelf IDs",
                "Expected NVLink Switches",
                "Current NVLink Switch IDs",
            ];
            table.set_titles(Row::new(
                headers.into_iter().map(Cell::new).collect::<Vec<Cell>>(),
            ));
            for r in racks {
                let expected_compute_trays = r.expected_compute_trays.join("\n");
                let current_compute_trays: String = r
                    .compute_trays
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let expected_power_shelves = r.expected_power_shelves.join("\n");
                let current_power_shelves: String = r
                    .power_shelves
                    .iter()
                    .map(|ps| ps.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let expected_nvlink_switches = r.expected_nvlink_switches.join("\n");
                table.add_row(prettytable::row![
                    r.id.map(|id| id.to_string()).unwrap_or_default(),
                    r.rack_state.as_str(),
                    expected_compute_trays,
                    current_compute_trays,
                    expected_power_shelves,
                    current_power_shelves,
                    expected_nvlink_switches,
                    "",
                ]);
            }
            table.printstd();
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&racks)?);
        }
        _ => {
            println!("output format not supported for Rack");
        }
    }
    Ok(())
}
