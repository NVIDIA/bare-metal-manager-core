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
use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
use mac_address::MacAddress;
use prettytable::{Table, row};

use super::args::Args;
use crate::async_write;
use crate::rpc::ApiClient;

pub async fn show_expected_machines(
    expected_machine_query: &Args,
    api_client: &ApiClient,
    output_format: OutputFormat,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
) -> CarbideCliResult<()> {
    if let Some(bmc_mac_address) = expected_machine_query.bmc_mac_address {
        let req = ::rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
            id: None,
        };
        let expected_machine = api_client.0.get_expected_machine(req).await?;
        if output_format == OutputFormat::Json {
            async_write!(
                output,
                "{}",
                serde_json::ser::to_string_pretty(&expected_machine)?
            )?;
        } else {
            async_write!(output, "{:#?}", expected_machine)?;
        }
        return Ok(());
    }

    let expected_machines = api_client.0.get_all_expected_machines().await?;
    if output_format == OutputFormat::Json {
        async_write!(
            output,
            "{}",
            serde_json::to_string_pretty(&expected_machines)?
        )?;
        return Ok(());
    }

    // TODO: This should be optimised. `find_interfaces` should accept a list of macs also and
    // return related interfaces details.
    let all_mi = api_client.get_all_machines_interfaces(None).await?;
    let expected_macs = expected_machines
        .expected_machines
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

    convert_and_print_into_nice_table(
        output,
        &expected_machines,
        &expected_bmc_ip_vs_ids,
        &expected_mi,
    )
    .await?;

    Ok(())
}

async fn convert_and_print_into_nice_table(
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    expected_machines: &::rpc::forge::ExpectedMachineList,
    expected_discovered_machine_ids: &HashMap<String, String>,
    expected_discovered_machine_interfaces: &HashMap<MacAddress, ::rpc::forge::MachineInterface>,
) -> CarbideCliResult<()> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Serial Number",
        "BMC Mac",
        "Interface IP",
        "Fallback DPUs",
        "Associated Machine",
        "Name",
        "Description",
        "Labels",
        "SKU ID",
        "Pause On Ingestion",
        "DPF State",
    ]);

    for expected_machine in &expected_machines.expected_machines {
        let default_pause_ingestion_and_poweron =
            expected_machine.default_pause_ingestion_and_poweron();

        let machine_interface = expected_machine
            .bmc_mac_address
            .parse::<MacAddress>()
            .ok()
            .and_then(|m| expected_discovered_machine_interfaces.get(&m));
        let machine_id = expected_discovered_machine_ids
            .get(
                machine_interface
                    .and_then(|x| x.address.first().map(String::as_str))
                    .unwrap_or("unknown"),
            )
            .map(String::as_str);

        let labels = expected_machine
            .metadata
            .as_ref()
            .map(|m| {
                m.labels
                    .iter()
                    .map(|label| {
                        let key = label.key.as_str();
                        let value = label.value.as_deref().unwrap_or_default();
                        format!("\"{key}:{value}\"")
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        table.add_row(row![
            expected_machine.chassis_serial_number,
            expected_machine.bmc_mac_address,
            machine_interface
                .map(|x| x.address.join("\n"))
                .unwrap_or("Undiscovered".to_string()),
            expected_machine.fallback_dpu_serial_numbers.join("\n"),
            machine_id.unwrap_or("Unlinked"),
            expected_machine
                .metadata
                .as_ref()
                .map(|m| m.name.as_str())
                .unwrap_or_default(),
            expected_machine
                .metadata
                .as_ref()
                .map(|m| m.description.as_str())
                .unwrap_or_default(),
            labels.join(", "),
            expected_machine.sku_id.as_deref().unwrap_or_default(),
            default_pause_ingestion_and_poweron,
            expected_machine.dpf_enabled.to_string(),
        ]);
    }

    async_write!(output, "{}", table)?;

    Ok(())
}
