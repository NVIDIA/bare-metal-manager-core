use std::collections::{BTreeMap, HashSet};

use chrono::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};

use crate::db::dpu_machine::DpuMachine;
use crate::db::machine::Machine;
use crate::db::vpc_resource_leaf::NewVpcResourceLeaf;
use crate::kubernetes::VpcResourceActions;
use crate::vpc_resources::leaf;
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Deserialize)]
pub struct MachineTopology {
    _machine_id: uuid::Uuid,
    _topology: Value,
    _created: DateTime<Utc>,
    _updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for MachineTopology {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineTopology {
            _machine_id: row.try_get("machine_id")?,
            _topology: row.try_get("topology")?,
            _created: row.try_get("created")?,
            _updated: row.try_get("updated")?,
        })
    }
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
    pub async fn is_dpu(discovery: &str) -> CarbideResult<bool> {
        let data: Value = serde_json::from_str(discovery)?;
        let arm_type = "aarch64";

        // Update list with id's we care about
        let dpu_ids = HashSet::from(["0x15b3:0xa2d6", "0x1af4:0x1000"]);

        // TODO - unwrap_or() instead of expect()

        let network_interfaces = data["discovery_data"]["InfoV0"].get("network_interfaces");
        let machine_type_val = data["discovery_data"]["InfoV0"].get("machine_type");

        let mut res = false;
        if let Some(interface) = network_interfaces {
            log::debug!("Interfaces Hash found");
            if let Some(attributes) = Some(interface) {
                log::debug!("Looking for attributes on interface: {}", interface);
                if let Some(attribute) = attributes.as_array() {
                    for a in attribute {
                        log::info!("Interface Info: {}", a);
                        let mac_address =
                            if let Some(mac_address) = a.get("mac_address").unwrap().as_str() {
                                mac_address
                            } else {
                                "FF:FF:FF:FF:FF:FF"
                            };
                        match a.get("pci_properties") {
                            None => {
                                log::info!(
                                    "Unable to find PCI PROPERTIES for interface {}",
                                    mac_address
                                );
                            }
                            Some(x) => {
                                log::info!("Network interface {} contains necessary information for examination. Checking if this is a DPU.", mac_address);
                                // If for some reason there is no vendor/device in pci_properties
                                // set to 0'
                                let vendor = x["vendor"].as_str().unwrap_or("0x0000");
                                let device = x["device"].as_str().unwrap_or("0x0000");

                                let dpu_pci_id = vec![vendor, device].join(":");

                                let submitted_discovery_data = HashSet::from([dpu_pci_id.as_str()]);

                                // Compare contents of
                                let dpu_count: HashSet<_> =
                                    submitted_discovery_data.intersection(&dpu_ids).collect();

                                match dpu_count.len() {
                                    0 => {
                                        log::info!("VENDOR AND DEVICE INFORMATION DOES NOT MATCH, INTERFACE {} IS NOT A DPU", mac_address);
                                        res = false;
                                    }
                                    _ => {
                                        log::info!("VENDOR AND DEVICE INFORMATION MATCHES - PCI_ID {} and MAC_ADDRESS: {}", mac_address, dpu_pci_id);
                                        res = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if res {
            if let Some(machine_type) = machine_type_val {
                res = arm_type
                    == machine_type.as_str().ok_or_else(|| {
                        CarbideError::GenericError("Machine type parsing failed.".to_string())
                    })?;
            } else {
                return Err(CarbideError::GenericError(
                    "Machine Type field is missing.".to_string(),
                ));
            }
        }

        Ok(res)
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
        discovery: String,
    ) -> CarbideResult<Option<Self>> {
        if Self::discovered(&mut *txn, machine_id).await? {
            log::info!("Discovery data for machine {} already exists", machine_id);
            Ok(None)
        } else {
            let res = sqlx::query_as(
                "INSERT INTO machine_topologies VALUES ($1::uuid, $2::json) RETURNING *",
            )
            .bind(&machine_id)
            .bind(&discovery)
            .fetch_one(&mut *txn)
            .await?;

            if Self::is_dpu(&discovery).await? {
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
                            "pf0hpf".to_string(),
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

                //  VpcResourceActions::CreateLeaf(leaf_spec)
                //     .reconcile(&mut *txn)
                //     .await?;

                //let machine = Machine::find_one(&mut *txn, *machine_id).await?.unwrap();
                // let foo = machine.associate_vpc_leaf_id();

                // forge-prov -> leafSpec
                // name = leaf.id()
                // call to NewVpcResourceLeaf.persist() that returns UUID of new leaf
                // machine.find machine_id
                // machine.associate_vpc_leaf_id(leaf_id)
                // machine.interfaces.mac_address
                // machine.interfaces.address - management_ip = dpu_mgmt ip
                //
                //VpcResourceActions::CreateLeaf()

                // forge-prov -> leafSpec
                // name = leaf.id()
                // management_ip = machine_interface_address
                // vendor = DPU
                // host_admin_i_ps = "leaf.uuid=interface"
                // host_interfaces = "interface.mac_address=leafUuid"
            }
            Ok(Some(res))
        }
    }
}
