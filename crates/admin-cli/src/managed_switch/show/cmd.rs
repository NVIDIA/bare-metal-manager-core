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
use std::collections::HashMap;
use std::fmt::Write;

use carbide_uuid::switch::SwitchId;
use rpc::admin_cli::{CarbideCliResult, OutputFormat};
use rpc::forge::{LinkedExpectedSwitch, MachineInterface, Switch};
use serde::Serialize;

use super::args::Args;
use crate::rpc::ApiClient;

const UNKNOWN: &str = "Unknown";

#[derive(Serialize)]
struct ManagedSwitchOutput {
    switch_id: Option<String>,
    name: String,
    serial_number: String,
    bmc_mac: String,
    bmc_ip: Option<String>,
    nvos_mac_addresses: Vec<String>,
    controller_state: String,
    power_state: Option<String>,
    health_status: Option<String>,
    expected_switch_id: Option<String>,
    explored_endpoint: Option<String>,
    rack_id: Option<String>,
    location: Option<String>,
    state_reason: Option<String>,
}

/// Build a map from SwitchId -> list of NVOS MAC addresses by filtering
/// machine interfaces that have a switch_id foreign key set.
fn build_nvos_mac_map(interfaces: &[MachineInterface]) -> HashMap<SwitchId, Vec<String>> {
    let mut map: HashMap<SwitchId, Vec<String>> = HashMap::new();
    for mi in interfaces {
        if let Some(switch_id) = mi.switch_id {
            map.entry(switch_id)
                .or_default()
                .push(mi.mac_address.clone());
        }
    }
    map
}

fn build_managed_switch_outputs(
    switches: Vec<Switch>,
    linked: Vec<LinkedExpectedSwitch>,
    nvos_mac_map: &HashMap<SwitchId, Vec<String>>,
) -> Vec<ManagedSwitchOutput> {
    let switch_map: HashMap<String, &Switch> = switches
        .iter()
        .filter_map(|s| s.id.as_ref().map(|id| (id.to_string(), s)))
        .collect();

    let mut outputs: Vec<ManagedSwitchOutput> = Vec::new();
    let mut seen_switch_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for linked_switch in &linked {
        let switch = linked_switch
            .switch_id
            .as_ref()
            .and_then(|id| switch_map.get(&id.to_string()));

        let switch_id_str = linked_switch.switch_id.as_ref().map(|id| id.to_string());

        if let Some(ref id) = switch_id_str {
            seen_switch_ids.insert(id.clone());
        }

        let nvos_macs = linked_switch
            .switch_id
            .as_ref()
            .and_then(|id| nvos_mac_map.get(id).cloned())
            .unwrap_or_default();

        outputs.push(ManagedSwitchOutput {
            switch_id: switch_id_str,
            name: switch
                .and_then(|s| s.config.as_ref().map(|c| c.name.clone()))
                .unwrap_or_else(|| linked_switch.switch_serial_number.clone()),
            serial_number: linked_switch.switch_serial_number.clone(),
            bmc_mac: linked_switch.bmc_mac_address.clone(),
            bmc_ip: linked_switch.explored_endpoint_address.clone(),
            nvos_mac_addresses: nvos_macs,
            controller_state: switch
                .map(|s| s.controller_state.clone())
                .unwrap_or_else(|| "NotCreated".to_string()),
            power_state: switch.and_then(|s| {
                s.status
                    .as_ref()
                    .and_then(|st| st.power_state.as_ref().cloned())
            }),
            health_status: switch.and_then(|s| {
                s.status
                    .as_ref()
                    .and_then(|st| st.health_status.as_ref().cloned())
            }),
            expected_switch_id: linked_switch
                .expected_switch_id
                .as_ref()
                .map(|id| id.value.clone()),
            explored_endpoint: linked_switch.explored_endpoint_address.clone(),
            rack_id: linked_switch.rack_id.as_ref().map(|id| id.to_string()),
            location: switch
                .and_then(|s| s.config.as_ref().and_then(|c| c.location.as_ref().cloned())),
            state_reason: switch.and_then(|s| {
                s.status
                    .as_ref()
                    .and_then(|st| st.state_reason.as_ref().and_then(|r| r.outcome_msg.clone()))
            }),
        });
    }

    for switch in &switches {
        let id_str = switch.id.as_ref().map(|id| id.to_string());
        if let Some(ref id) = id_str
            && !seen_switch_ids.contains(id)
        {
            continue;
        }

        let nvos_macs = switch
            .id
            .as_ref()
            .and_then(|id| nvos_mac_map.get(id).cloned())
            .unwrap_or_default();

        outputs.push(ManagedSwitchOutput {
            switch_id: id_str,
            name: switch
                .config
                .as_ref()
                .map(|c| c.name.clone())
                .unwrap_or_default(),
            serial_number: String::new(),
            bmc_mac: switch
                .bmc_info
                .as_ref()
                .and_then(|b| b.mac.clone())
                .unwrap_or_default(),
            bmc_ip: switch.bmc_info.as_ref().and_then(|b| b.ip.clone()),
            nvos_mac_addresses: nvos_macs,
            controller_state: switch.controller_state.clone(),
            power_state: switch.status.as_ref().and_then(|st| st.power_state.clone()),
            health_status: switch
                .status
                .as_ref()
                .and_then(|st| st.health_status.clone()),
            expected_switch_id: None,
            explored_endpoint: None,
            rack_id: None,
            location: switch.config.as_ref().and_then(|c| c.location.clone()),
            state_reason: switch
                .status
                .as_ref()
                .and_then(|st| st.state_reason.as_ref().and_then(|r| r.outcome_msg.clone())),
        });
    }

    outputs
}

fn show_detail_view(m: &ManagedSwitchOutput) -> CarbideCliResult<()> {
    let width = 27;
    let mut lines = String::new();

    writeln!(&mut lines, "{:<width$}: {}", "Name", m.name)?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "Switch ID",
        m.switch_id.as_deref().unwrap_or(UNKNOWN)
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "Controller State", m.controller_state
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "Serial Number",
        if m.serial_number.is_empty() {
            UNKNOWN
        } else {
            &m.serial_number
        }
    )?;

    writeln!(&mut lines, "\nBMC:\n{}", "-".repeat(40))?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  IP",
        m.bmc_ip.as_deref().unwrap_or(UNKNOWN)
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  MAC",
        if m.bmc_mac.is_empty() {
            UNKNOWN
        } else {
            &m.bmc_mac
        }
    )?;

    writeln!(&mut lines, "\nNVOS:\n{}", "-".repeat(40))?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  MAC Addresses",
        if m.nvos_mac_addresses.is_empty() {
            "N/A".to_string()
        } else {
            m.nvos_mac_addresses.join(", ")
        }
    )?;

    writeln!(&mut lines, "\nStatus:\n{}", "-".repeat(40))?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  Power State",
        m.power_state.as_deref().unwrap_or(UNKNOWN)
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  Health",
        m.health_status.as_deref().unwrap_or(UNKNOWN)
    )?;
    if let Some(ref reason) = m.state_reason {
        writeln!(&mut lines, "{:<width$}: {}", "  State Reason", reason)?;
    }

    writeln!(&mut lines, "\nInventory:\n{}", "-".repeat(40))?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  Expected Switch ID",
        m.expected_switch_id.as_deref().unwrap_or("N/A")
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  Explored Endpoint",
        m.explored_endpoint.as_deref().unwrap_or("N/A")
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  Rack ID",
        m.rack_id.as_deref().unwrap_or("N/A")
    )?;
    writeln!(
        &mut lines,
        "{:<width$}: {}",
        "  Location",
        m.location.as_deref().unwrap_or(UNKNOWN)
    )?;

    println!("{lines}");
    Ok(())
}

fn show_table_view(outputs: &[ManagedSwitchOutput]) {
    println!(
        "{:<36} {:<20} {:<18} {:<18} {:<20} {:<10} {:<10} {:<15}",
        "Switch ID", "Name", "Serial", "BMC MAC", "NVOS MAC", "Power", "Health", "State"
    );
    println!("{:-<160}", "");

    for m in outputs {
        let id = m
            .switch_id
            .as_ref()
            .map(|s| Cow::Borrowed(s.as_str()))
            .unwrap_or(Cow::Borrowed("N/A"));

        let name = if m.name.len() > 18 {
            Cow::Owned(format!("{}…", &m.name[..17]))
        } else {
            Cow::Borrowed(m.name.as_str())
        };

        let serial = if m.serial_number.len() > 16 {
            Cow::Owned(format!("{}…", &m.serial_number[..15]))
        } else if m.serial_number.is_empty() {
            Cow::Borrowed("N/A")
        } else {
            Cow::Borrowed(m.serial_number.as_str())
        };

        let bmc_mac = if m.bmc_mac.is_empty() {
            Cow::Borrowed("N/A")
        } else {
            Cow::Borrowed(m.bmc_mac.as_str())
        };

        let nvos_mac: Cow<str> = if m.nvos_mac_addresses.is_empty() {
            Cow::Borrowed("N/A")
        } else {
            Cow::Borrowed(m.nvos_mac_addresses[0].as_str())
        };

        println!(
            "{:<36} {:<20} {:<18} {:<18} {:<20} {:<10} {:<10} {:<15}",
            id,
            name,
            serial,
            bmc_mac,
            nvos_mac,
            m.power_state.as_deref().unwrap_or("N/A"),
            m.health_status.as_deref().unwrap_or("N/A"),
            m.controller_state,
        );
    }
}

fn show_csv(outputs: &[ManagedSwitchOutput]) {
    println!(
        "Switch ID,Name,Serial Number,BMC MAC,NVOS MAC,BMC IP,Power State,Health,State,Expected Switch ID,Rack ID"
    );
    for m in outputs {
        println!(
            "{},{},{},{},{},{},{},{},{},{},{}",
            m.switch_id.as_deref().unwrap_or(""),
            m.name,
            m.serial_number,
            m.bmc_mac,
            m.nvos_mac_addresses.join(";"),
            m.bmc_ip.as_deref().unwrap_or(""),
            m.power_state.as_deref().unwrap_or(""),
            m.health_status.as_deref().unwrap_or(""),
            m.controller_state,
            m.expected_switch_id.as_deref().unwrap_or(""),
            m.rack_id.as_deref().unwrap_or(""),
        );
    }
}

pub async fn handle_show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let (switch_id, name) = args.parse_identifier();
    let is_single = switch_id.is_some() || name.is_some();

    let query = rpc::forge::SwitchQuery { name, switch_id };
    let switches = api_client.0.find_switches(query).await?.switches;
    let linked = api_client
        .0
        .get_all_expected_switches_linked()
        .await?
        .expected_switches;
    let all_interfaces = api_client.get_all_machines_interfaces(None).await?;
    let nvos_mac_map = build_nvos_mac_map(&all_interfaces.interfaces);

    let outputs = build_managed_switch_outputs(switches, linked, &nvos_mac_map);

    match output_format {
        OutputFormat::Json => {
            if is_single {
                if let Some(first) = outputs.first() {
                    println!("{}", serde_json::to_string_pretty(first)?);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&outputs)?);
            }
        }
        OutputFormat::Yaml => {
            if is_single {
                if let Some(first) = outputs.first() {
                    println!("{}", serde_yaml::to_string(first)?);
                }
            } else {
                println!("{}", serde_yaml::to_string(&outputs)?);
            }
        }
        OutputFormat::Csv => {
            show_csv(&outputs);
        }
        _ => {
            if is_single {
                if let Some(first) = outputs.first() {
                    show_detail_view(first)?;
                } else {
                    println!("No managed switch found.");
                }
            } else if outputs.is_empty() {
                println!("No managed switches found.");
            } else {
                println!("Managed Switches ({}):", outputs.len());
                show_table_view(&outputs);
            }
        }
    }

    Ok(())
}
