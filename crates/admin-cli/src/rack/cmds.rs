/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use color_eyre::Result;
use prettytable::{Cell, Row, Table};
use rpc::admin_cli::OutputFormat;

use super::args::{DeleteRack, ShowRack};
use crate::cfg::cli_options::AddNode;
use crate::rms::args::{AvailableFwImages, FirmwareInventory, PowerState, RemoveNode};
use crate::rpc::{ApiClient, RmsApiClient};

pub async fn show_rack(api_client: &ApiClient, show_opts: ShowRack) -> Result<()> {
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
        println!("ID: {}", r.id);
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

pub async fn list_racks(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::GetRackRequest { id: None };
    let response = api_client.0.get_rack(query).await?;
    let racks = response.rack;
    if racks.is_empty() {
        println!("No racks found");
        return Ok(());
    }

    let format = OutputFormat::AsciiTable;
    match format {
        OutputFormat::AsciiTable => {
            let mut table = Table::new();
            let headers = vec![
                "Rack ID",
                "Rack State",
                "Expected Compute Trays",
                "Current Compute Tray IDs",
                "Expected Power Shelves",
                "Current Power Shelf IDs",
                "Expected NVLink Switches",
                "Current NVLink Switch IDs",
            ];
            table.set_titles(Row::new(
                headers.into_iter().map(Cell::new).collect::<Vec<Cell>>(),
            ));
            for r in racks {
                let expected_compute_trays = r.expected_compute_trays.join("\n");
                let current_compute_trays: String = r
                    .compute_trays
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let expected_power_shelves = r.expected_power_shelves.join("\n");
                let current_power_shelves: String = r
                    .power_shelves
                    .iter()
                    .map(|ps| ps.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let expected_nvlink_switches = r.expected_nvlink_switches.join("\n");
                table.add_row(prettytable::row![
                    r.id.as_str(),
                    r.rack_state.as_str(),
                    expected_compute_trays,
                    current_compute_trays,
                    expected_power_shelves,
                    current_power_shelves,
                    expected_nvlink_switches,
                    "",
                ]);
            }
            table.printstd();
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&racks)?);
        }
        _ => {
            println!("output format not supported for Rack");
        }
    }
    Ok(())
}

pub async fn delete_rack(api_client: &ApiClient, delete_opts: DeleteRack) -> Result<()> {
    let query = rpc::forge::DeleteRackRequest {
        id: delete_opts.identifier,
    };
    api_client.0.delete_rack(query).await?;
    Ok(())
}

pub async fn get_inventory(rms_client: &RmsApiClient) -> Result<()> {
    let response = rms_client.inventory_get().await?;
    println!("{:#?}", response);
    Ok(())
}

#[allow(dead_code)]
pub async fn add_node(rms_client: &RmsApiClient, add_node_opts: AddNode) -> Result<()> {
    let new_node = ::rpc::protos::rack_manager::NewNodeInfo {
        node_id: add_node_opts.node_id,
        mac_address: add_node_opts.mac_address,
        ip_address: add_node_opts.ip_address,
        port: add_node_opts.port,
        username: None,
        password: None,
        r#type: add_node_opts.node_type,
    };
    let new_nodes = vec![new_node];
    let response = rms_client.add_node(new_nodes).await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn remove_node(rms_client: &RmsApiClient, remove_node_opts: RemoveNode) -> Result<()> {
    let response = rms_client.remove_node(remove_node_opts.node_id).await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn get_poweron_order(rms_client: &RmsApiClient) -> Result<()> {
    let response = rms_client.get_poweron_order().await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn get_power_state(
    rms_client: &RmsApiClient,
    power_state_opts: PowerState,
) -> Result<()> {
    let response = rms_client.get_power_state(power_state_opts.node_id).await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn get_firmware_inventory(
    rms_client: &RmsApiClient,
    firmware_inventory_opts: FirmwareInventory,
) -> Result<()> {
    let response = rms_client
        .get_firmware_inventory(firmware_inventory_opts.node_id)
        .await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn get_available_fw_images(
    rms_client: &RmsApiClient,
    available_fw_images_opts: AvailableFwImages,
) -> Result<()> {
    let response = rms_client
        .get_available_fw_images(available_fw_images_opts.node_id)
        .await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn get_bkc_files(rms_client: &RmsApiClient) -> Result<()> {
    let response = rms_client.get_bkc_files().await?;
    println!("{:#?}", response);
    Ok(())
}

pub async fn check_bkc_compliance(rms_client: &RmsApiClient) -> Result<()> {
    let response = rms_client.check_bkc_compliance().await?;
    println!("{:#?}", response);
    Ok(())
}
