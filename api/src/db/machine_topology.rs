/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::prelude::*;
use itertools::Itertools;
use serde::Deserialize;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};

use rpc::DiscoveryData;
use rpc::MachineDiscoveryInfo;
use rpc::NetworkInterface;

use crate::db::constants::ADMIN_DPU_NETWORK_INTERFACE;
use crate::db::dpu_machine::DpuMachine;
use crate::db::machine::Machine;
use crate::db::vpc_resource_leaf::NewVpcResourceLeaf;
use crate::kubernetes::VpcResourceActions;
use crate::vpc_resources::leaf;
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Deserialize)]
pub struct MachineTopology {
    machine_id: uuid::Uuid,
    topology: Value,
    created: DateTime<Utc>,
    _updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for MachineTopology {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineTopology {
            machine_id: row.try_get("machine_id")?,
            topology: row.try_get("topology")?,
            created: row.try_get("created")?,
            _updated: row.try_get("updated")?,
        })
    }
}

fn does_attributes_contain_dpu_pci_ids(
    dpu_pci_ids: &HashSet<&str>,
    interfaces: &[NetworkInterface],
) -> bool {
    interfaces.iter().any(|interface| {
        log::info!("Interface Info: {:?}", interface);
        let mac_address = interface.mac_address.as_str();
        match &interface.pci_properties {
            None => {
                log::info!(
                    "Unable to find PCI PROPERTIES for interface {}",
                    mac_address
                );
            }
            Some(pci_property) => {
                log::info!("Network interface {} contains necessary information for examination. Checking if this is a DPU.", mac_address);
                // If for some reason there is no vendor/device in pci_properties
                // set to 0'
                let vendor = pci_property.vendor.as_str();
                let device = pci_property.device.as_str();

                let pci_id = format!("{}:{}", vendor, device);

                if dpu_pci_ids.contains(pci_id.as_str()) {
                    log::info!(
                        "VENDOR AND DEVICE INFORMATION MATCHES - PCI_ID {} and MAC_ADDRESS: {}",
                        pci_id,
                        mac_address
                    );
                    return true;
                }

                log::info!("VENDOR AND DEVICE INFORMATION DOES NOT MATCH, INTERFACE {} IS NOT A DPU", mac_address);
            }
        }
        false
    })
}

// Object({"machine_id": Object({"value": String("0c005a38-dc1c-4a98-938e-6ce39a84840e")}),
// "discovery_data": Object({"InfoV0": Object({"network_interfaces":
// Array([Object({"mac_address": String("52:54:00:12:34:56"), "pci_properties": Object({"vendor": String("0x1af4"),
// "device": String("0x1000"), "path": String("/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4"),
// "numa_node": Number(2147483647), "description": String("Virtio network device")})})]),
// "cpus": Array([Object({"frequency": String("3187.200"), "number": Number(0),
// "model": String("12th Gen Intel(R) Core(TM) i9-12900K"), "vendor": String("GenuineIntel"), "core": Number(0), "node": Number(0), "socket": Number(0)})]),
// "block_devices": Array([Object({"serial": String("QM00003"), "model": String("QEMU_DVD-ROM"), "revision": String("2.5+")}),
// Object({"serial": String("NO_SERIAL"), "model": String("NO_MODEL"), "revision": String("NO_REVISION")})])})})})
impl MachineTopology {
    pub fn is_dpu(discovery: &rpc::forge::MachineDiscoveryInfo) -> CarbideResult<bool> {
        let discovery_data = if let Some(DiscoveryData::Info(data)) = &discovery.discovery_data {
            data
        } else {
            return Err(CarbideError::GenericError(
                "Discovery data is missing.".to_string(),
            ));
        };

        let network_interfaces = &discovery_data.network_interfaces;
        let machine_type = &discovery_data.machine_type;

        const ARM_TYPE: &str = "aarch64";
        if machine_type != ARM_TYPE {
            return Ok(false);
        }

        if network_interfaces.is_empty() {
            return Ok(false); // has no network interfaces/attribute
        }

        log::debug!("Interfaces Hash found");
        log::debug!(
            "Looking for attributes on interface: {:?}",
            network_interfaces
        );

        // Update list with id's we care about
        let dpu_pci_ids = HashSet::from(["0x15b3:0xa2d6", "0x1af4:0x1000"]);
        Ok(does_attributes_contain_dpu_pci_ids(
            &dpu_pci_ids,
            &network_interfaces[..],
        ))
    }

    pub async fn discovered(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
    ) -> CarbideResult<bool> {
        let res = sqlx::query("SELECT * from machine_topologies WHERE machine_id=$1::uuid")
            .bind(&machine_id)
            .fetch_optional(&mut *txn)
            .await?;

        match res {
            None => {
                log::info!("We have never seen this discovery and machine data before");
                Ok(false)
            }
            Some(_pg_row) => {
                log::info!("Discovery data for machine already exists");
                Ok(true)
            }
        }
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
        discovery: &MachineDiscoveryInfo,
    ) -> CarbideResult<Option<Self>> {
        if Self::discovered(&mut *txn, machine_id).await? {
            log::info!("Discovery data for machine {} already exists", machine_id);
            Ok(None)
        } else {
            let json = serde_json::to_string(&discovery).map_err(CarbideError::from)?;
            let res = sqlx::query_as(
                "INSERT INTO machine_topologies VALUES ($1::uuid, $2::json) RETURNING *",
            )
            .bind(&machine_id)
            .bind(&json)
            .fetch_one(&mut *txn)
            .await?;

            if Self::is_dpu(discovery)? {
                let new_leaf = NewVpcResourceLeaf::new().persist(&mut *txn).await?;

                log::info!("Generating new leaf id {}", new_leaf.id());

                let machine_dpu =
                    Machine::associate_vpc_leaf_id(&mut *txn, *machine_id, *new_leaf.id()).await?;

                if let Some(machine) = Machine::find_one(&mut *txn, *machine_dpu.id()).await? {
                    log::info!("Machine with ID: {} found", machine.id());
                    for mut interface in machine.interfaces().iter().cloned() {
                        if machine.vpc_leaf_id().is_some() {
                            log::info!("Machine VPC_LEAF_ID: {:?}", machine.vpc_leaf_id());
                            interface
                                .associate_interface_with_dpu_machine(&mut *txn, machine.id())
                                .await?;
                        }
                    }
                }
                let dpu = DpuMachine::find_by_machine_id(&mut *txn, machine_dpu.id()).await?;

                let leaf_spec = leaf::Leaf::new(
                    &new_leaf.id().to_string(),
                    leaf::LeafSpec {
                        control: Some(leaf::LeafControl {
                            maintenance_mode: Some(false),
                            management_ip: Some(dpu.address().ip().to_string()),
                            vendor: Some("DPU".to_string()),
                        }),
                        host_admin_i_ps: Some(BTreeMap::from([(
                            ADMIN_DPU_NETWORK_INTERFACE.to_string(),
                            "".to_string(),
                        )])),
                        host_interfaces: None,
                    },
                );

                log::info!("Leafspec sent to kubernetes: {:?}", leaf_spec);

                let db_conn = txn.acquire().await?;

                VpcResourceActions::CreateLeaf(leaf_spec)
                    .reconcile(db_conn)
                    .await?;
            }
            Ok(Some(res))
        }
    }

    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[uuid::Uuid],
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        let query = "SELECT * FROM machine_topologies WHERE machine_id=ANY($1);";
        let topologies = sqlx::query_as(query)
            .bind(machine_ids)
            .fetch_all(&mut *txn)
            .await?
            .into_iter()
            .into_group_map_by(|t: &Self| t.machine_id);
        Ok(topologies)
    }

    #[allow(dead_code)]
    pub fn topology(&self) -> &serde_json::Value {
        &self.topology
    }

    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }
}
