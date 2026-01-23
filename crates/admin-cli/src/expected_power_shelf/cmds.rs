/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use prettytable::{Table, row};
use rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use serde::{Deserialize, Serialize};

use super::args::{
    AddExpectedPowerShelf, DeleteExpectedPowerShelf, ExpectedPowerShelfJson,
    ReplaceAllExpectedPowerShelf, ShowExpectedPowerShelfQuery, UpdateExpectedPowerShelf,
};
use crate::rpc::ApiClient;

pub async fn show(
    query: &ShowExpectedPowerShelfQuery,
    api_client: &ApiClient,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    if let Some(bmc_mac_address) = query.bmc_mac_address {
        let expected_power_shelf = api_client
            .0
            .get_expected_power_shelf(bmc_mac_address.to_string())
            .await?;
        println!("{:#?}", expected_power_shelf);
        return Ok(());
    }

    let expected_power_shelves = api_client.0.get_all_expected_power_shelves().await?;
    if output_format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&expected_power_shelves)?);
    }

    // TODO: This should be optimised. `find_interfaces` should accept a list of macs also and
    // return related interfaces details.
    let all_mi = api_client.get_all_machines_interfaces(None).await?;
    let expected_macs = expected_power_shelves
        .expected_power_shelves
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
        &expected_power_shelves,
        &expected_bmc_ip_vs_ids,
        &expected_mi,
    )?;

    Ok(())
}

fn convert_and_print_into_nice_table(
    expected_power_shelves: &::rpc::forge::ExpectedPowerShelfList,
    expected_discovered_machine_ids: &HashMap<String, String>,
    expected_discovered_machine_interfaces: &HashMap<String, ::rpc::forge::MachineInterface>,
) -> CarbideCliResult<()> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Serial Number",
        "BMC Mac",
        "Interface IP",
        "Associated Machine",
        "Name",
        "Description",
        "Labels"
    ]);

    for expected_power_shelf in &expected_power_shelves.expected_power_shelves {
        let machine_interface = expected_discovered_machine_interfaces
            .get(&expected_power_shelf.bmc_mac_address.to_lowercase());
        let machine_id = expected_discovered_machine_ids
            .get(
                &machine_interface
                    .and_then(|x| x.address.first().cloned())
                    .unwrap_or("unknown".to_string()),
            )
            .cloned();

        let metadata = expected_power_shelf.metadata.clone().unwrap_or_default();
        let labels = metadata
            .labels
            .iter()
            .map(|label| {
                let key = &label.key;
                let value = label.value.clone().unwrap_or_default();
                format!("\"{}:{}\"", key, value)
            })
            .collect::<Vec<_>>();

        table.add_row(row![
            expected_power_shelf.shelf_serial_number,
            expected_power_shelf.bmc_mac_address,
            machine_interface
                .map(|x| x.address.join("\n"))
                .unwrap_or("Undiscovered".to_string()),
            machine_id.unwrap_or("Unlinked".to_string()),
            metadata.name,
            metadata.description,
            labels.join(", ")
        ]);
    }

    table.printstd();

    Ok(())
}

pub async fn add(data: &AddExpectedPowerShelf, api_client: &ApiClient) -> color_eyre::Result<()> {
    let metadata = data.metadata()?;
    api_client
        .add_expected_power_shelf(
            data.bmc_mac_address,
            data.bmc_username.clone(),
            data.bmc_password.clone(),
            data.shelf_serial_number.clone(),
            metadata,
            data.rack_id.clone(),
            data.ip_address.clone(),
        )
        .await?;
    Ok(())
}

pub async fn delete(
    query: &DeleteExpectedPowerShelf,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_expected_power_shelf(query.bmc_mac_address.to_string())
        .await?;
    Ok(())
}

pub async fn update(
    data: &UpdateExpectedPowerShelf,
    api_client: &ApiClient,
) -> color_eyre::Result<()> {
    if let Err(e) = data.validate() {
        eprintln!("{e}");
        return Ok(());
    }
    let metadata = data.metadata()?;
    api_client
        .update_expected_power_shelf(
            data.bmc_mac_address,
            data.bmc_username.clone(),
            data.bmc_password.clone(),
            data.shelf_serial_number.clone(),
            metadata,
            data.rack_id.clone(),
            data.ip_address.clone(),
        )
        .await?;
    Ok(())
}

pub async fn replace_all(
    request: &ReplaceAllExpectedPowerShelf,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let json_file_path = Path::new(&request.filename);
    let reader = BufReader::new(File::open(json_file_path)?);

    #[derive(Debug, Serialize, Deserialize)]
    struct ExpectedPowerShelfList {
        expected_power_shelves: Vec<ExpectedPowerShelfJson>,
        expected_power_shelves_count: Option<usize>,
    }

    let expected_power_shelf_list: ExpectedPowerShelfList = serde_json::from_reader(reader)?;

    if expected_power_shelf_list
        .expected_power_shelves_count
        .is_some_and(|count| count != expected_power_shelf_list.expected_power_shelves.len())
    {
        return Err(CarbideCliError::GenericError(format!(
            "Json File specified an invalid count: {:#?}; actual count: {}",
            expected_power_shelf_list
                .expected_power_shelves_count
                .unwrap_or_default(),
            expected_power_shelf_list.expected_power_shelves.len()
        )));
    }

    api_client
        .replace_all_expected_power_shelves(expected_power_shelf_list.expected_power_shelves)
        .await?;
    Ok(())
}

pub async fn erase(api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client.0.delete_all_expected_power_shelves().await?;
    Ok(())
}
