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

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn show_rack(api_client: &ApiClient, show_opts: Args) -> Result<()> {
    let query = rpc::forge::GetRackRequest {
        id: show_opts.identifier,
    };
    let response = api_client.0.get_rack(query).await?;
    let racks = response.rack;
    if racks.is_empty() {
        println!("No racks found");
        return Ok(());
    }

    for r in racks {
        println!("ID: {}", r.id.map(|id| id.to_string()).unwrap_or_default());
        println!("State: {}", r.rack_state);
        println!("Expected Compute Tray BMCs:");
        for mac_address in r.expected_compute_trays {
            println!("  {}", mac_address);
        }
        println!("Expected Power Shelves:");
        for mac_address in r.expected_power_shelves {
            println!("  {}", mac_address);
        }
        println!("Expected NVLink Switches:");
        for mac_address in r.expected_nvlink_switches {
            println!("  {}", mac_address);
        }
        println!("Current Compute Trays");
        for machine_id in r.compute_trays {
            println!("  {}", machine_id);
        }
        println!("Current Power Shelves");
        for ps_id in r.power_shelves {
            println!("  {}", ps_id);
        }
        println!("Current NVLink Switches");
    }
    Ok(())
}
