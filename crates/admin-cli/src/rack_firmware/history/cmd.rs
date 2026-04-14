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

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};
use prettytable::{Cell, Row, Table};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn history(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let result = api_client.0.get_rack_firmware_history(opts).await?;

    if format == OutputFormat::Json {
        // Flatten to map<rack_id, Vec<record>> for serialization
        let json_histories: std::collections::HashMap<
            &str,
            Vec<&rpc::forge::RackFirmwareHistoryRecord>,
        > = result
            .histories
            .iter()
            .map(|(rack_id, records)| (rack_id.as_str(), records.records.iter().collect()))
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_histories)?);
    } else if result.histories.is_empty() {
        println!("No rack firmware apply history found.");
    } else {
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("Rack ID"),
            Cell::new("Firmware ID"),
            Cell::new("Hardware Type"),
            Cell::new("Firmware Type"),
            Cell::new("Applied At"),
            Cell::new("Available"),
        ]));

        for (rack_id, records) in &result.histories {
            for record in &records.records {
                let hw_type = record
                    .rack_hardware_type
                    .as_ref()
                    .map(|t| t.value.as_str())
                    .unwrap_or("N/A");
                table.add_row(Row::new(vec![
                    Cell::new(rack_id),
                    Cell::new(&record.firmware_id),
                    Cell::new(hw_type),
                    Cell::new(&record.firmware_type),
                    Cell::new(&record.applied_at),
                    Cell::new(&record.firmware_available.to_string()),
                ]));
            }
        }

        table.printstd();
    }

    Ok(())
}
