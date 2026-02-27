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

use color_eyre::Result;

use crate::rpc::ApiClient;

pub async fn list_switches(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::SwitchQuery {
        name: None,
        switch_id: None,
    };

    let response = api_client.0.find_switches(query).await?;

    let switches = response.switches;

    if switches.is_empty() {
        println!("No switches found.");
        return Ok(());
    }

    println!("Found {} switch(es):", switches.len());

    for (i, switch) in switches.iter().enumerate() {
        let name = switch
            .config
            .as_ref()
            .map(|config| config.name.as_str())
            .unwrap_or_else(|| "Unnamed");

        let id = switch
            .id
            .as_ref()
            .map(|id| Cow::Owned(id.to_string()))
            .unwrap_or_else(|| Cow::Borrowed("N/A"));

        let power_state = switch
            .status
            .as_ref()
            .and_then(|status| status.power_state.as_deref())
            .unwrap_or("Unknown");

        let health = switch
            .status
            .as_ref()
            .and_then(|status| status.health_status.as_deref())
            .unwrap_or("Unknown");

        let controller_state = switch.controller_state.as_str();

        println!(
            "{}. {} (ID: {}) - Power: {}, Health: {}, State: {}",
            i + 1,
            name,
            id,
            power_state,
            health,
            controller_state
        );
    }

    Ok(())
}
