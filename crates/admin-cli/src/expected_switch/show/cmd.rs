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

use std::collections::HashMap;

use mac_address::MacAddress;
use prettytable::{Table, row};
use rpc::admin_cli::{CarbideCliResult, OutputFormat};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn show(
    query: &Args,
    api_client: &ApiClient,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    if let Some(bmc_mac_address) = query.bmc_mac_address {
        let expected_switch = api_client
            .0
            .get_expected_switch(bmc_mac_address.to_string())
            .await?;
        println!("{:#?}", expected_switch);
        return Ok(());
    }

    let expected_switches = api_client.0.get_all_expected_switches().await?;
    if output_format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&expected_switches)?);
    }

    let all_mi = api_client.get_all_machines_interfaces(None).await?;
    let expected_macs = expected_switches
        .expected_switches
        .iter()
        .filter_map(|x| x.bmc_mac_address.parse().ok())
        .collect::<Vec<MacAddress>>();

    let expected_mi: HashMap<MacAddress, ::rpc::forge::MachineInterface> =
        HashMap::from_iter(all_mi.interfaces.into_iter().filter_map(|x| {
            let mac = x.mac_address.parse().ok()?;
            if expected_macs.contains(&mac) {
                Some((mac, x))
            } else {
                None
            }
        }));

    let bmc_ips = expected_mi
        .iter()
        .filter_map(|(_mac, interface)| {
            let ip = interface.address.first()?;
            Some(ip.clone())
        })
        .collect::<Vec<_>>();

    let expected_bmc_ip_vs_ids = HashMap::from_iter(
        api_client
            .0
            .find_machine_ids_by_bmc_ips(bmc_ips)
            .await?
            .pairs
            .into_iter()
            .map(|x| {
                (
                    x.bmc_ip,
                    x.machine_id
                        .map(|x| x.to_string())
                        .unwrap_or("Unlinked".to_string()),
                )
            }),
    );

    convert_and_print_into_nice_table(&expected_switches, &expected_bmc_ip_vs_ids, &expected_mi)?;

    Ok(())
}

fn convert_and_print_into_nice_table(
    expected_switches: &::rpc::forge::ExpectedSwitchList,
    expected_discovered_machine_ids: &HashMap<String, String>,
    expected_discovered_machine_interfaces: &HashMap<MacAddress, ::rpc::forge::MachineInterface>,
) -> CarbideCliResult<()> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Serial Number",
        "BMC Mac",
        "Interface IP",
        "Associated Machine",
        "Name",
        "Description",
        "Labels",
        "NVOS Username",
        "NVOS Password"
    ]);

    for expected_switch in &expected_switches.expected_switches {
        let machine_interface = expected_switch
            .bmc_mac_address
            .parse()
            .ok()
            .and_then(|mac| expected_discovered_machine_interfaces.get(&mac));
        let machine_id = expected_discovered_machine_ids
            .get(
                machine_interface
                    .and_then(|x| x.address.first().map(String::as_str))
                    .unwrap_or("unknown"),
            )
            .map(String::as_str);

        let labels = expected_switch
            .metadata
            .as_ref()
            .map(|m| {
                m.labels
                    .iter()
                    .map(|label| {
                        let key = &label.key;
                        let value = label.value.as_deref().unwrap_or_default();
                        format!("\"{}:{}\"", key, value)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        table.add_row(row![
            expected_switch.switch_serial_number,
            expected_switch.bmc_mac_address,
            machine_interface
                .map(|x| x.address.join("\n"))
                .unwrap_or("Undiscovered".to_string()),
            machine_id.unwrap_or("Unlinked"),
            expected_switch
                .metadata
                .as_ref()
                .map(|m| m.name.as_str())
                .unwrap_or_default(),
            expected_switch
                .metadata
                .as_ref()
                .map(|m| m.description.as_str())
                .unwrap_or_default(),
            labels.join(", "),
            expected_switch.nvos_username.as_deref().unwrap_or_default(),
            expected_switch
                .nvos_password
                .as_ref()
                .map(|_| "***")
                .unwrap_or_default()
        ]);
    }

    table.printstd();

    Ok(())
}
