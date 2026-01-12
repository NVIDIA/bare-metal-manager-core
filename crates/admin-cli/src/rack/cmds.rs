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
use crate::rms::args::{AvailableFwImages, FirmwareInventory, PowerState, RemoveNode};
use crate::rpc::ApiClient;

pub async fn show_rack(api_client: &ApiClient, show_opts: &ShowRack) -> Result<()> {
    let query = rpc::forge::GetRackRequest {
        id: show_opts.identifier.clone(),
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
                    r.id.clone(),
                    r.rack_state.clone(),
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

pub async fn delete_rack(api_client: &ApiClient, delete_opts: &DeleteRack) -> Result<()> {
    let query = rpc::forge::DeleteRackRequest {
        id: delete_opts.identifier.clone(),
    };
    api_client.0.delete_rack(query).await?;
    Ok(())
}

pub async fn get_inventory(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::InventoryGet.into(),
        node_id: None,
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn remove_node(api_client: &ApiClient, remove_node_opts: &RemoveNode) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::RemoveNode.into(),
        node_id: Some(remove_node_opts.node_id.clone()),
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn get_poweron_order(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::GetPoweronOrder.into(),
        node_id: None,
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn get_power_state(api_client: &ApiClient, power_state_opts: &PowerState) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::GetPowerState.into(),
        node_id: Some(power_state_opts.node_id.clone()),
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn get_firmware_inventory(
    api_client: &ApiClient,
    firmware_inventory_opts: &FirmwareInventory,
) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::GetFirmwareInventory.into(),
        node_id: Some(firmware_inventory_opts.node_id.clone()),
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn get_available_fw_images(
    api_client: &ApiClient,
    available_fw_images_opts: &AvailableFwImages,
) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::GetAvailableFwImages.into(),
        node_id: Some(available_fw_images_opts.node_id.clone()),
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn get_bkc_files(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::GetBkcFiles.into(),
        node_id: None,
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}

pub async fn check_bkc_compliance(api_client: &ApiClient) -> Result<()> {
    let query = rpc::forge::RackManagerForgeRequest {
        cmd: rpc::forge::RackManagerForgeCmd::CheckBkcCompliance.into(),
        node_id: None,
    };
    let response = api_client.0.rack_manager_call(query).await?;
    let inventory = response.json_result;
    println!("{}", inventory.unwrap());
    Ok(())
}
