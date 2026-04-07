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
use rpc::admin_cli::OutputFormat;
use rpc::forge::Rack;
use serde::Serialize;

use super::args::Args;
use crate::cfg::runtime::RuntimeConfig;
use crate::rpc::ApiClient;

#[derive(Serialize)]
struct RackOutput {
    id: String,
    name: String,
    state: String,
    version: String,
    expected_compute_tray_bmcs: Vec<String>,
    current_compute_trays: Vec<String>,
    expected_power_shelf_bmcs: Vec<String>,
    current_power_shelves: Vec<String>,
    expected_nvlink_switch_bmcs: Vec<String>,
    current_nvlink_switches: Vec<String>,
}

impl From<&Rack> for RackOutput {
    fn from(r: &Rack) -> Self {
        Self {
            id: r.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            name: r
                .metadata
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_default(),
            state: r.rack_state.clone(),
            version: r.version.clone(),
            expected_compute_tray_bmcs: r.expected_compute_trays.clone(),
            current_compute_trays: r.compute_trays.iter().map(|id| id.to_string()).collect(),
            expected_power_shelf_bmcs: r.expected_power_shelves.clone(),
            current_power_shelves: r.power_shelves.iter().map(|id| id.to_string()).collect(),
            expected_nvlink_switch_bmcs: r.expected_nvlink_switches.clone(),
            current_nvlink_switches: r.switches.iter().map(|id| id.to_string()).collect(),
        }
    }
}

pub async fn show_rack(api_client: &ApiClient, args: Args, config: &RuntimeConfig) -> Result<()> {
    let format = config.format;
    match args.rack {
        Some(rack_id) => {
            let racks = api_client.get_one_rack(rack_id).await?.racks;
            match racks.first() {
                Some(r) => show_single(r, format)?,
                None => println!("No rack found"),
            }
        }
        None => {
            let racks = api_client.get_all_racks(config.page_size).await?.racks;
            if racks.is_empty() {
                println!("No racks found");
            } else {
                show_list(&racks, format)?;
            }
        }
    }

    Ok(())
}

fn show_single(r: &Rack, format: OutputFormat) -> Result<()> {
    let output = RackOutput::from(r);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&output)?),
        _ => show_detail(r),
    }
    Ok(())
}

fn show_list(racks: &[Rack], format: OutputFormat) -> Result<()> {
    let outputs: Vec<RackOutput> = racks.iter().map(RackOutput::from).collect();
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&outputs)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&outputs)?),
        OutputFormat::Csv => {
            show_table_csv(racks);
        }
        _ => show_table(racks),
    }
    Ok(())
}

fn show_detail(r: &Rack) {
    let id = r.id.as_ref().map(|id| id.to_string()).unwrap_or_default();
    let name = r
        .metadata
        .as_ref()
        .map(|m| m.name.as_str())
        .unwrap_or("N/A");

    let mut table = Table::new();
    table.add_row(row!["ID", id]);
    table.add_row(row!["Name", name]);
    table.add_row(row!["State", r.rack_state]);
    table.add_row(row!["Version", r.version]);
    table.add_row(row![
        "Expected Compute Tray BMCs",
        if r.expected_compute_trays.is_empty() {
            "N/A".to_string()
        } else {
            r.expected_compute_trays.join("\n")
        }
    ]);
    table.add_row(row![
        "Current Compute Trays",
        if r.compute_trays.is_empty() {
            "N/A".to_string()
        } else {
            r.compute_trays
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        }
    ]);
    table.add_row(row![
        "Expected Power Shelf BMCs",
        if r.expected_power_shelves.is_empty() {
            "N/A".to_string()
        } else {
            r.expected_power_shelves.join("\n")
        }
    ]);
    table.add_row(row![
        "Current Power Shelves",
        if r.power_shelves.is_empty() {
            "N/A".to_string()
        } else {
            r.power_shelves
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        }
    ]);
    table.add_row(row![
        "Expected NVLink Switch BMCs",
        if r.expected_nvlink_switches.is_empty() {
            "N/A".to_string()
        } else {
            r.expected_nvlink_switches.join("\n")
        }
    ]);
    table.add_row(row![
        "Current NVLink Switches",
        if r.switches.is_empty() {
            "N/A".to_string()
        } else {
            r.switches
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        }
    ]);
    table.printstd();
}

fn show_table(racks: &[Rack]) {
    let mut table = Table::new();
    table.set_titles(row![
        "ID",
        "Name",
        "State",
        "Compute Trays",
        "Power Shelves",
        "Switches",
    ]);

    for r in racks {
        let name = r
            .metadata
            .as_ref()
            .map(|m| m.name.as_str())
            .unwrap_or("N/A");

        table.add_row(row![
            r.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            name,
            r.rack_state,
            format!(
                "{} / {}",
                r.compute_trays.len(),
                r.expected_compute_trays.len()
            ),
            format!(
                "{} / {}",
                r.power_shelves.len(),
                r.expected_power_shelves.len()
            ),
            format!(
                "{} / {}",
                r.switches.len(),
                r.expected_nvlink_switches.len()
            ),
        ]);
    }

    table.printstd();
}

fn show_table_csv(racks: &[Rack]) {
    let mut table = Table::new();
    table.set_titles(row![
        "ID",
        "Name",
        "State",
        "Compute Trays",
        "Power Shelves",
        "Switches",
    ]);

    for r in racks {
        let name = r
            .metadata
            .as_ref()
            .map(|m| m.name.as_str())
            .unwrap_or("N/A");

        table.add_row(row![
            r.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            name,
            r.rack_state,
            format!(
                "{} / {}",
                r.compute_trays.len(),
                r.expected_compute_trays.len()
            ),
            format!(
                "{} / {}",
                r.power_shelves.len(),
                r.expected_power_shelves.len()
            ),
            format!(
                "{} / {}",
                r.switches.len(),
                r.expected_nvlink_switches.len()
            ),
        ]);
    }

    table.to_csv(std::io::stdout()).ok();
}
