/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
use prettytable::{Table, row};

use super::args::ShowExpectedMachineQuery;
use crate::async_write;
use crate::rpc::ApiClient;

pub async fn show_expected_machines(
    expected_machine_query: &ShowExpectedMachineQuery,
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
        .map(|x| x.bmc_mac_address.clone().to_lowercase())
        .collect::<Vec<String>>();

    let expected_mi: HashMap<String, ::rpc::forge::MachineInterface> =
        HashMap::from_iter(all_mi.interfaces.iter().filter_map(|x| {
            if expected_macs.contains(&x.mac_address.to_lowercase()) {
                Some((x.mac_address.clone().to_lowercase(), x.clone()))
            } else {
                None
            }
        }));

    let bmc_ips = expected_mi
        .iter()
        .filter_map(|x| {
            let ip = x.1.address.first()?;
            Some(ip.clone())
        })
        .collect::<Vec<_>>();

    let expected_bmc_ip_vs_ids = HashMap::from_iter(
        api_client
            .0
            .find_machine_ids_by_bmc_ips(bmc_ips)
            .await?
            .pairs
            .iter()
            .map(|x| {
                (
                    x.bmc_ip.clone(),
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
    expected_discovered_machine_interfaces: &HashMap<String, ::rpc::forge::MachineInterface>,
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
        "Pause On Ingestion"
    ]);

    for expected_machine in &expected_machines.expected_machines {
        let machine_interface = expected_discovered_machine_interfaces
            .get(&expected_machine.bmc_mac_address.to_lowercase());
        let machine_id = expected_discovered_machine_ids
            .get(
                &machine_interface
                    .and_then(|x| x.address.first().cloned())
                    .unwrap_or("unknown".to_string()),
            )
            .cloned();

        let metadata = expected_machine.metadata.clone().unwrap_or_default();
        let labels = metadata
            .labels
            .iter()
            .map(|label| {
                let key = &label.key;
                let value = label.value.clone().unwrap_or_default();
                format!("\"{key}:{value}\"")
            })
            .collect::<Vec<_>>();

        table.add_row(row![
            expected_machine.chassis_serial_number,
            expected_machine.bmc_mac_address,
            machine_interface
                .map(|x| x.address.join("\n"))
                .unwrap_or("Undiscovered".to_string()),
            expected_machine.fallback_dpu_serial_numbers.join("\n"),
            machine_id.unwrap_or("Unlinked".to_string()),
            metadata.name,
            metadata.description,
            labels.join(", "),
            expected_machine
                .sku_id
                .as_ref()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            expected_machine.default_pause_ingestion_and_poweron(),
        ]);
    }

    async_write!(output, "{}", table)?;

    Ok(())
}
