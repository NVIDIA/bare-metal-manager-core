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

use super::args::Args;
use crate::cfg::runtime::RuntimeConfig;
use crate::rpc::ApiClient;

pub async fn show_rack(api_client: &ApiClient, args: Args, config: &RuntimeConfig) -> Result<()> {
    let racks = match args.rack {
        Some(rack_id) => api_client.get_one_rack(rack_id).await?,
        None => api_client.get_all_racks(config.page_size).await?,
    }
    .racks;

    if racks.is_empty() {
        println!("No racks found");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_titles(row![
        "ID",
        "State",
        "Expected Compute Trays",
        "Expected Power Shelves",
        "Expected NVLink Switches",
        "Current Compute Trays",
        "Current Power Shelves"
    ]);

    for r in racks {
        table.add_row(row![
            r.id.map(|id| id.to_string()).unwrap_or_default(),
            r.rack_state,
            if r.expected_compute_trays.is_empty() {
                "N/A".to_string()
            } else {
                r.expected_compute_trays.join(", ")
            },
            if r.expected_power_shelves.is_empty() {
                "N/A".to_string()
            } else {
                r.expected_power_shelves.join(", ")
            },
            if r.expected_nvlink_switches.is_empty() {
                "N/A".to_string()
            } else {
                r.expected_nvlink_switches.join(", ")
            },
            if r.compute_trays.is_empty() {
                "N/A".to_string()
            } else {
                r.compute_trays
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if r.power_shelves.is_empty() {
                "N/A".to_string()
            } else {
                r.power_shelves
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ]);
    }

    table.printstd();
    Ok(())
}
