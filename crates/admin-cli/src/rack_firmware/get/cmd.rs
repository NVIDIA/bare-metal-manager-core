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

use std::collections::BTreeMap;

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};
use prettytable::{Cell, Row, Table, row};
use serde::Deserialize;

use super::args::Args;
use crate::rpc::ApiClient;

#[derive(Debug, Deserialize, Default)]
struct ParsedFirmwareLookupTable {
    #[serde(default)]
    devices: BTreeMap<String, BTreeMap<String, FirmwareLookupEntry>>,
    #[serde(default)]
    switch_system_images: BTreeMap<String, BTreeMap<String, SwitchSystemImageLookupEntry>>,
}

#[derive(Debug, Deserialize, Default)]
struct FirmwareLookupEntry {
    #[serde(default)]
    component: String,
    #[serde(default)]
    bundle: String,
    #[serde(default)]
    firmware_type: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    subcomponents: Vec<FirmwareSubcomponent>,
}

#[derive(Debug, Deserialize, Default)]
struct FirmwareSubcomponent {
    #[serde(default)]
    component: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    skuid: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SwitchSystemImageLookupEntry {
    #[serde(default)]
    component: String,
    #[serde(default)]
    package_name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    image_filename: String,
    #[serde(default)]
    location_type: String,
    #[serde(default)]
    firmware_type: String,
}

pub async fn get(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let id = opts.id.clone();

    let result = match api_client.0.get_rack_firmware(opts).await {
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
        let mut table = Table::new();
        table.add_row(row!["ID", result.id]);
        let hw_type = result
            .rack_hardware_type
            .as_ref()
            .map(|t| t.value.as_str())
            .unwrap_or("N/A");
        table.add_row(row!["Hardware Type", hw_type]);
        table.add_row(row!["Default", result.is_default]);
        table.add_row(row!["Available", result.available]);
        table.add_row(row!["Created", result.created]);
        table.add_row(row!["Updated", result.updated]);
        table.printstd();

        // Display parsed firmware components.
        if should_show_not_downloaded(&result.parsed_components) {
            println!("\nFirmware Components: (not yet downloaded)");
        } else {
            match serde_json::from_str::<ParsedFirmwareLookupTable>(&result.parsed_components) {
                Ok(parsed) if print_parsed_components(&parsed) => {}
                _ => println!("\nFirmware Components: (not yet downloaded)"),
            }
        }
    }

    Ok(())
}

fn should_show_not_downloaded(parsed_components: &str) -> bool {
    parsed_components.is_empty() || parsed_components == "{}"
}

fn print_parsed_components(parsed: &ParsedFirmwareLookupTable) -> bool {
    let mut printed = false;

    for (device_type, components) in &parsed.devices {
        printed = true;
        println!("\n[{}]", device_type);

        let mut component_table = Table::new();
        component_table.set_titles(Row::new(vec![
            Cell::new("Component"),
            Cell::new("Type"),
            Cell::new("Bundle"),
            Cell::new("Target"),
        ]));

        let mut component_subcomps: Vec<(&str, &[FirmwareSubcomponent])> = Vec::new();

        for entry in components.values() {
            component_table.add_row(Row::new(vec![
                Cell::new(display_value(&entry.component)),
                Cell::new(&display_value(&entry.firmware_type).to_uppercase()),
                Cell::new(display_value(&entry.bundle)),
                Cell::new(display_value(&entry.target)),
            ]));

            if !entry.subcomponents.is_empty() {
                component_subcomps.push((display_value(&entry.component), &entry.subcomponents));
            }
        }

        component_table.printstd();

        for (comp_name, subcomps) in component_subcomps {
            println!("\n  {} Subcomponents:", comp_name);

            let mut sub_table = Table::new();
            sub_table.set_titles(Row::new(vec![
                Cell::new("Component"),
                Cell::new("Version"),
                Cell::new("SKUID"),
            ]));

            for subcomp in subcomps {
                let sub_skuid = subcomp.skuid.as_deref().unwrap_or("-");

                sub_table.add_row(Row::new(vec![
                    Cell::new(display_value(&subcomp.component)),
                    Cell::new(display_value(&subcomp.version)),
                    Cell::new(display_value(sub_skuid)),
                ]));
            }

            let table_str = sub_table.to_string();
            for line in table_str.lines() {
                println!("  {}", line);
            }
        }
    }

    for (device_type, images) in &parsed.switch_system_images {
        printed = true;
        println!("\n[Switch System Images: {}]", device_type);

        let mut image_table = Table::new();
        image_table.set_titles(Row::new(vec![
            Cell::new("Component"),
            Cell::new("Type"),
            Cell::new("Package"),
            Cell::new("Image Filename"),
            Cell::new("Version"),
            Cell::new("Location Type"),
        ]));

        for entry in images.values() {
            image_table.add_row(Row::new(vec![
                Cell::new(display_value(&entry.component)),
                Cell::new(&display_value(&entry.firmware_type).to_uppercase()),
                Cell::new(display_value(&entry.package_name)),
                Cell::new(display_value(&entry.image_filename)),
                Cell::new(display_value(&entry.version)),
                Cell::new(display_value(&entry.location_type)),
            ]));
        }

        image_table.printstd();
    }

    printed
}

fn display_value(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}
