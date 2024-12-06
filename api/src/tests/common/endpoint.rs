/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use sqlx::{Postgres, Transaction};

use crate::{
    db::{explored_endpoints::DbExploredEndpoint, DatabaseError},
    model::site_explorer::{
        Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport, EndpointType,
        Inventory, PowerState, Service,
    },
};
use forge_uuid::machine::MachineId;

pub async fn insert_endpoint_version(
    txn: &mut Transaction<'_, Postgres>,
    addr: &str,
    version: &str,
) -> Result<(), DatabaseError> {
    insert_endpoint(
        txn,
        addr,
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
        "Dell",
        "R750",
        version,
    )
    .await
}

async fn insert_endpoint(
    txn: &mut Transaction<'_, Postgres>,
    addr: &str,
    machine_id_str: &str,
    vendor: &str,
    model: &str,
    bmc_version: &str,
) -> Result<(), DatabaseError> {
    DbExploredEndpoint::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &build_exploration_report(vendor, model, bmc_version, machine_id_str),
        txn,
    )
    .await
}

fn build_exploration_report(
    vendor: &str,
    model: &str,
    bmc_version: &str,
    machine_id_str: &str,
) -> EndpointExplorationReport {
    let machine_id = if machine_id_str.is_empty() {
        None
    } else {
        Some(MachineId::from_str(machine_id_str).unwrap())
    };

    EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        vendor: Some(bmc_vendor::BMCVendor::Dell),
        last_exploration_error: None,
        last_exploration_latency: None,
        managers: vec![],
        systems: vec![ComputerSystem {
            model: Some(model.to_string()),
            ethernet_interfaces: vec![],
            id: "".to_string(),
            manufacturer: Some(vendor.to_string()),
            serial_number: None,
            attributes: ComputerSystemAttributes {
                nic_mode: None,
                http_dev1_interface: Some("NIC.Slot.5-1".to_string()),
                is_infinite_boot_enabled: Some(true),
            },
            pcie_devices: vec![],
            base_mac: None,
            power_state: PowerState::On,
            sku: None,
        }],
        chassis: vec![Chassis {
            model: Some(model.to_string()),
            id: "".to_string(),
            manufacturer: Some(vendor.to_string()),
            part_number: None,
            serial_number: None,
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "".to_string(),
            inventories: vec![Inventory {
                id: "idrac_blah".to_string(),
                description: None,
                version: Some(bmc_version.to_string()),
                release_date: None,
            }],
        }],
        machine_id,
        versions: HashMap::default(),
        model: None,
    }
}
