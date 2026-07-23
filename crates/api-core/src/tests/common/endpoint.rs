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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use carbide_uuid::machine::MachineId;
use db::{self, DatabaseError};
use model::firmware::FirmwareComponentType;
use model::site_explorer::{
    Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport, EndpointType,
    EthernetInterface, Inventory, Manager, PowerState, Service,
};
use sqlx::PgConnection;

pub async fn insert_endpoint_version(
    txn: &mut PgConnection,
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

pub async fn insert_endpoint_with_firmware_versions(
    txn: &mut PgConnection,
    addr: &str,
    versions: HashMap<FirmwareComponentType, String>,
) -> Result<(), DatabaseError> {
    let mut report = build_exploration_report(
        "Dell",
        "R750",
        "1.0",
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
    );
    report.versions = versions;
    db::explored_endpoints::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &report,
        false,
        txn,
    )
    .await
}

fn ethernet_interface(id: &str, mac: mac_address::MacAddress) -> EthernetInterface {
    EthernetInterface {
        description: None,
        id: Some(id.to_string()),
        interface_enabled: Some(true),
        mac_address: Some(mac),
        link_status: None,
        uefi_device_path: None,
    }
}

/// Seed an explored endpoint whose BMC (Redfish Manager) advertises `mac`, so it is
/// discoverable by `find_by_mac_address`. No live machine is created, modelling the
/// leftover-record state that `erase-metadata` cleans up.
pub async fn insert_endpoint_with_bmc_mac(
    txn: &mut PgConnection,
    addr: &str,
    mac: mac_address::MacAddress,
) -> Result<(), DatabaseError> {
    let mut report = build_exploration_report("Dell", "R750", "1.0", "");
    report.managers.push(Manager {
        ethernet_interfaces: vec![ethernet_interface("BMC.1", mac)],
        id: "BMC".to_string(),
        ipmi_port: None,
    });
    db::explored_endpoints::insert(IpAddr::from_str(addr).unwrap(), &report, false, txn).await
}

/// Seed an explored endpoint whose BMC (Manager) advertises `bmc_mac` but whose host
/// *system* NIC advertises `system_mac`. `find_by_mac_address(system_mac)` matches it,
/// yet the endpoint belongs to `bmc_mac` -- used to prove `erase-metadata` protects an
/// endpoint owned by a different BMC.
pub async fn insert_endpoint_system_mac_other_bmc(
    txn: &mut PgConnection,
    addr: &str,
    system_mac: mac_address::MacAddress,
    bmc_mac: mac_address::MacAddress,
) -> Result<(), DatabaseError> {
    let mut report = build_exploration_report("Dell", "R750", "1.0", "");
    report.systems[0]
        .ethernet_interfaces
        .push(ethernet_interface("NIC.1", system_mac));
    report.managers.push(Manager {
        ethernet_interfaces: vec![ethernet_interface("BMC.1", bmc_mac)],
        id: "BMC".to_string(),
        ipmi_port: None,
    });
    db::explored_endpoints::insert(IpAddr::from_str(addr).unwrap(), &report, false, txn).await
}

async fn insert_endpoint(
    txn: &mut PgConnection,
    addr: &str,
    machine_id_str: &str,
    vendor: &str,
    model: &str,
    bmc_version: &str,
) -> Result<(), DatabaseError> {
    db::explored_endpoints::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &build_exploration_report(vendor, model, bmc_version, machine_id_str),
        false,
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
                is_infinite_boot_enabled: Some(true),
            },
            pcie_devices: vec![],
            base_mac: None,
            power_state: PowerState::On,
            sku: None,
            boot_order: None,
        }],
        chassis: vec![Chassis {
            model: Some(model.to_string()),
            id: "".to_string(),
            manufacturer: Some(vendor.to_string()),
            part_number: None,
            serial_number: None,
            network_adapters: vec![],
            compute_tray_index: None,
            physical_slot_number: None,
            revision_id: None,
            topology_id: None,
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
        machine_setup_status: None,
        secure_boot_status: None,
        lockdown_status: None,
        power_shelf_id: None,
        switch_id: None,
        compute_tray_index: None,
        physical_slot_number: None,
        revision_id: None,
        topology_id: None,
        remediation_error: None,
    }
}
