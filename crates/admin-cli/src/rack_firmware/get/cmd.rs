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

pub async fn get(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let id = opts.id;
    let request = rpc::forge::RackFirmwareGetRequest { id: id.clone() };

    let result = match api_client.0.get_rack_firmware(request).await {
        Ok(response) => response,
        Err(status) if status.code() == tonic::Code::NotFound => {
            return Err(CarbideCliError::GenericError(format!(
                "Rack firmware configuration not found: {}",
                id
            )));
        }
        Err(err) => return Err(CarbideCliError::from(err)),
    };

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Rack Firmware Configuration:");
        println!("  ID: {}", result.id);
        println!("  Available: {}", result.available);
        println!("  Created: {}", result.created);
        println!("  Updated: {}", result.updated);

        // Display parsed firmware components
        if !result.parsed_components.is_empty() && result.parsed_components != "{}" {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&result.parsed_components)
                && let Some(devices) = parsed.get("devices").and_then(|d| d.as_object())
            {
                for (device_type, components) in devices {
                    println!("\n[{}]", device_type);

                    let mut component_table = Table::new();
                    component_table.set_titles(Row::new(vec![
                        Cell::new("Component"),
                        Cell::new("Type"),
                        Cell::new("Bundle"),
                        Cell::new("Target"),
                    ]));

                    // Collect components with their subcomponents for display
                    let mut component_subcomps: Vec<(String, &[serde_json::Value])> = Vec::new();

                    if let Some(comp_map) = components.as_object() {
                        for (_key, entry) in comp_map {
                            let component = entry
                                .get("component")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let bundle =
                                entry.get("bundle").and_then(|v| v.as_str()).unwrap_or("-");
                            let fw_type = entry
                                .get("firmware_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let target =
                                entry.get("target").and_then(|v| v.as_str()).unwrap_or("-");

                            component_table.add_row(Row::new(vec![
                                Cell::new(component),
                                Cell::new(&fw_type.to_uppercase()),
                                Cell::new(bundle),
                                Cell::new(target),
                            ]));

                            // Collect subcomponents for later display
                            if let Some(subcomps) =
                                entry.get("subcomponents").and_then(|s| s.as_array())
                                && !subcomps.is_empty()
                            {
                                component_subcomps.push((component.to_string(), subcomps));
                            }
                        }
                    }

                    component_table.printstd();

                    // Print subcomponents for each component
                    for (comp_name, subcomps) in component_subcomps {
                        println!("\n  {} Subcomponents:", comp_name);

                        let mut sub_table = Table::new();
                        sub_table.set_titles(Row::new(vec![
                            Cell::new("Component"),
                            Cell::new("Version"),
                            Cell::new("SKUID"),
                        ]));

                        for subcomp in subcomps {
                            let sub_name = subcomp
                                .get("component")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let sub_version = subcomp
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let sub_skuid =
                                subcomp.get("skuid").and_then(|v| v.as_str()).unwrap_or("-");

                            sub_table.add_row(Row::new(vec![
                                Cell::new(sub_name),
                                Cell::new(sub_version),
                                Cell::new(sub_skuid),
                            ]));
                        }

                        // Indent the table output
                        let table_str = sub_table.to_string();
                        for line in table_str.lines() {
                            println!("  {}", line);
                        }
                    }
                }
            }
        } else {
            println!("\nFirmware Components: (not yet downloaded)");
        }
    }

    Ok(())
}
