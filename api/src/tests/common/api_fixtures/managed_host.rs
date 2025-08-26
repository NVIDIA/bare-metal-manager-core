/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    iter,
    str::FromStr,
    sync::Arc,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::db::managed_host::LoadSnapshotOptions;
use crate::{
    api::Api,
    model::{
        hardware_info::{HardwareInfo, NetworkInterface, PciDeviceProperties, TpmEkCertificate},
        machine::{
            InstanceState, Machine, ManagedHostState, ManagedHostStateSnapshot, ReprovisionState,
        },
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport,
            EndpointType, EthernetInterface, Inventory, Manager, NetworkAdapter, PowerState,
            Service, UefiDevicePath,
        },
    },
    tests::common::{api_fixtures::instance::TestInstanceBuilder, ib_guid_pool},
};

use forge_uuid::instance::InstanceId;
use forge_uuid::machine::MachineId;
use forge_uuid::machine::MachineInterfaceId;
use itertools::Itertools;
use libredfish::{OData, PCIeDevice};
use mac_address::MacAddress;
use rpc::forge::MachineArchitecture;
use rpc::forge::PxeInstructions;
use rpc::forge::forge_server::Forge;
use std::collections::HashMap;
use tonic::Request;

use super::create_random_self_signed_cert;
use crate::tests::common::{
    api_fixtures::{
        TestEnv, dpu::DpuConfig, host::X86_INFO_JSON, instance::delete_instance, network_configured,
    },
    mac_address_pool,
};

static NEXT_HOST_SERIAL: AtomicU32 = AtomicU32::new(1);
const REQUIRED_IB_GUIDS: usize = 6;

/// Describes a Managed Host
#[derive(Debug, Clone)]
pub struct ManagedHostConfig {
    pub serial: String,
    pub bmc_mac_address: MacAddress,
    pub tpm_ek_cert: TpmEkCertificate,
    pub dpus: Vec<DpuConfig>,
    pub non_dpu_macs: Vec<MacAddress>,
    pub expected_state: ManagedHostState,
    pub ib_guids: Vec<String>,
}

impl ManagedHostConfig {
    pub fn with_serial(serial: String) -> Self {
        Self {
            serial,
            ..Default::default()
        }
    }

    pub fn with_dpus(dpus: Vec<DpuConfig>) -> Self {
        Self {
            dpus,
            ..Default::default()
        }
    }

    pub fn with_expected_state(expected_state: ManagedHostState) -> Self {
        Self {
            expected_state,
            ..Default::default()
        }
    }

    pub fn dhcp_mac_address(&self) -> MacAddress {
        if let Some(dpu) = self.dpus.first() {
            dpu.host_mac_address
        } else if let Some(non_dpu_mac) = self.non_dpu_macs.first() {
            *non_dpu_mac
        } else {
            panic!("No DPUs or non-DPU NICs on MockHost")
        }
    }

    pub fn get_and_assert_single_dpu(&self) -> &DpuConfig {
        let (1, Some(single_dpu)) = (self.dpus.len(), self.dpus.first()) else {
            panic!("Expected a single-DPU host, got {} DPUs", self.dpus.len());
        };
        single_dpu
    }
}

impl Default for ManagedHostConfig {
    fn default() -> Self {
        let random_cert = create_random_self_signed_cert();
        Self {
            serial: format!(
                "VVG1{:05X}",
                NEXT_HOST_SERIAL.fetch_add(1, Ordering::Relaxed)
            ),
            bmc_mac_address: mac_address_pool::HOST_BMC_MAC_ADDRESS_POOL.allocate(),
            tpm_ek_cert: TpmEkCertificate::from(random_cert),
            dpus: vec![DpuConfig::default()],
            non_dpu_macs: vec![mac_address_pool::HOST_NON_DPU_MAC_ADDRESS_POOL.allocate()],
            expected_state: ManagedHostState::Ready,
            // Create 6 IB GUIDs - which is what is required by x86_info.json
            ib_guids: std::iter::repeat_with(|| ib_guid_pool::IB_GUID_POOL.allocate())
                .take(6)
                .collect(),
        }
    }
}

impl From<&ManagedHostConfig> for HardwareInfo {
    fn from(config: &ManagedHostConfig) -> Self {
        let mut info = serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap();
        info.tpm_ek_certificate = Some(config.tpm_ek_cert.clone());
        info.dmi_data.as_mut().unwrap().product_serial = config.serial.clone();
        info.dmi_data.as_mut().unwrap().chassis_serial = config.serial.clone();
        info.network_interfaces = config
            .dpus
            .iter()
            .map(|d| NetworkInterface {
                mac_address: d.host_mac_address,
                pci_properties: Some(PciDeviceProperties {
                    vendor: "mellanox".to_string(),
                    device: "DPU1".to_string(),
                    path: "/x/y/z".to_string(),
                    numa_node: 1,
                    description: None,
                    slot: None,
                }),
            })
            .chain(config.non_dpu_macs.iter().map(|m| NetworkInterface {
                mac_address: *m,
                pci_properties: None,
            }))
            .collect();
        // Generate a unique GUID for each InfiniBand interface in the template
        // For the moment this only supports hosts with a fixed amount of 6 interfaces
        assert_eq!(
            config.ib_guids.len(),
            REQUIRED_IB_GUIDS,
            "The amount of {} IB GUIDs passed to the config does not match the {} GUIDs required by the test_data template",
            config.ib_guids.len(),
            REQUIRED_IB_GUIDS
        );
        for (ib_interface, guid) in info
            .infiniband_interfaces
            .iter_mut()
            .zip(config.ib_guids.iter())
        {
            ib_interface.guid = guid.clone();
        }
        info
    }
}

impl From<ManagedHostConfig> for EndpointExplorationReport {
    fn from(value: ManagedHostConfig) -> Self {
        let next_nic_index = value.dpus.len() + 1;

        let network_adapters = value
            .dpus
            .iter()
            .enumerate()
            .map(|(index, dpu)| NetworkAdapter {
                id: format!("slot-{}", index + 1),
                manufacturer: Some("MLNX".to_string()),
                model: Some("BlueField-3 P-Series DPU 200GbE/".to_string()),
                part_number: Some("900-9D3B6-00CV-A".to_string()),
                serial_number: Some(dpu.serial.clone()),
            })
            .chain(iter::once(NetworkAdapter {
                id: format!("slot-{next_nic_index}"),
                manufacturer: Some("Broadcom Limited".to_string()),
                model: Some("5720".to_string()),
                part_number: Some("SN30L21970".to_string()),
                serial_number: Some("L2NV97J018G".to_string()),
            }))
            .collect();

        let pcie_devices = value
            .dpus
            .iter()
            .map(|dpu| PCIeDevice {
                odata: OData {
                    odata_id: "odata_id".to_string(),
                    odata_type: "odata_type".to_string(),
                    odata_etag: None,
                    odata_context: None,
                },
                description: None,
                firmware_version: None,
                id: None,
                manufacturer: None,
                gpu_vendor: None,
                name: None,
                part_number: Some("900-9D3B6-00CV-A".to_string()),
                serial_number: Some(dpu.serial.clone()),
                status: None,
                slot: None,
                pcie_functions: None,
            })
            .collect::<Vec<_>>();

        let systems_ethernet_interfaces = value
            .non_dpu_macs
            .iter()
            .enumerate()
            .map(|(index, mac)| {
                let port = index + 1;
                EthernetInterface {
                    id: Some(format!("NIC.Embedded.{port}-1-1")),
                    description: Some(format!("Embedded NIC 1 Port {port} Partition 1")),
                    interface_enabled: Some(true),
                    mac_address: Some(*mac),
                    uefi_device_path: None,
                }
            })
            .chain(value.dpus.iter().enumerate().map(|(index, dpu)| {
                let slot = index + 5; // DPUs start with 5....
                EthernetInterface {
                    id: Some(format!("NIC.Slot.{slot}-1")),
                    description: Some(format!("NIC in Slot {slot} Port 1")),
                    interface_enabled: Some(true),
                    mac_address: Some(dpu.host_mac_address),
                    uefi_device_path: Some(
                        dpu.override_hosts_uefi_device_path.clone().unwrap_or(
                            UefiDevicePath::from_str(&format!(
                                "PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x{:x})/MAC({},0x1)",
                                index + 1,
                                dpu.host_mac_address.to_string().replace(':', ""),
                            ))
                            .unwrap(),
                        ),
                    ),
                }
            }))
            .collect_vec();

        Self {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Dell),
            managers: vec![Manager {
                id: "iDRAC.Embedded.1".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("NIC.1".to_string()),
                    description: Some("Management Network Interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some(value.bmc_mac_address),
                    uefi_device_path: None,
                }],
            }],
            systems: vec![ComputerSystem {
                id: "System.Embedded.1".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                model: Some("PowerEdge R750".to_string()),
                serial_number: Some(value.serial.clone()),
                ethernet_interfaces: systems_ethernet_interfaces,
                attributes: ComputerSystemAttributes::default(),
                pcie_devices: pcie_devices.into_iter().map(Into::into).collect(),
                base_mac: None,
                power_state: PowerState::On,
                sku: None,
                boot_order: None,
            }],
            chassis: vec![Chassis {
                id: "System.Embedded.1".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                model: Some("PowerEdge R750".to_string()),
                part_number: Some("SB27A42862".to_string()),
                serial_number: Some(value.serial),
                network_adapters,
            }],
            service: vec![Service {
                id: "FirmwareInventory".to_string(),
                inventories: vec![
                    Inventory {
                        id: "Installed-__iDRACz".to_string(),
                        description: Some("The information of BMC (Primary) firmware.".to_string()),
                        version: Some("5.10.20".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "Current-159-1.13.2__BIOS.Setup.1-1".to_string(),
                        description: Some("The information of Firmware firmware.".to_string()),
                        version: Some("1.12.0".to_string()),
                        release_date: None,
                    },
                ],
            }],
            machine_id: None,
            versions: Default::default(),
            model: None,
            forge_setup_status: None,
            secure_boot_status: None,
        }
    }
}

pub struct ManagedHost {
    pub id: MachineId,
    pub dpu_ids: Vec<MachineId>,
    pub api: Arc<Api>,
}

impl From<ManagedHost> for (MachineId, MachineId) {
    fn from(mut v: ManagedHost) -> Self {
        (v.id, v.dpu_ids.remove(0))
    }
}

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

impl ManagedHost {
    pub fn into_host(self) -> MachineId {
        self.id
    }

    pub fn into_dpu(mut self) -> MachineId {
        self.dpu_ids.remove(0)
    }

    pub fn dpu(&self) -> TestMachine {
        TestMachine {
            id: self.dpu_ids[0],
            api: self.api.clone(),
        }
    }

    pub fn dpu_n(&self, n: usize) -> TestMachine {
        assert!(n < self.dpu_ids.len());
        TestMachine {
            id: self.dpu_ids[n],
            api: self.api.clone(),
        }
    }

    pub fn host(&self) -> TestMachine {
        TestMachine {
            id: self.id,
            api: self.api.clone(),
        }
    }

    pub async fn snapshot(&self, txn: &mut Txn<'_>) -> ManagedHostStateSnapshot {
        crate::db::managed_host::load_snapshot(txn, &self.id, Default::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn dpu_db_machines(&self, txn: &mut Txn<'_>) -> Vec<Machine> {
        crate::db::machine::find_dpus_by_host_machine_id(txn, &self.id)
            .await
            .unwrap()
    }

    pub fn new_dpu_reprovision_state(&self, state: ReprovisionState) -> ManagedHostState {
        ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(*self.dpu().machine_id(), state)]),
            },
        }
    }

    pub fn new_dpus_reprovision_state(&self, states: &[&ReprovisionState]) -> ManagedHostState {
        assert_eq!(states.len(), self.dpu_ids.len());
        ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: self
                    .dpu_ids
                    .iter()
                    .zip(states.iter())
                    .map(|(id, state)| (*id, (*state).clone()))
                    .collect(),
            },
        }
    }

    pub fn new_dpu_assigned_reprovision_state(&self, state: ReprovisionState) -> ManagedHostState {
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(*self.dpu().machine_id(), state)]),
                },
            },
        }
    }

    pub async fn network_configured(&self, test_env: &TestEnv) {
        network_configured(test_env, &self.dpu_ids).await
    }

    pub fn instance_builer<'a, 'b>(&'b self, test_env: &'a TestEnv) -> TestInstanceBuilder<'a, 'b> {
        TestInstanceBuilder::new(test_env, self)
    }

    pub async fn delete_instance(&self, env: &TestEnv, instance_id: InstanceId) {
        delete_instance(env, instance_id, self).await
    }
}

pub(crate) trait ManagedHostSnapshots {
    async fn snapshots(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        load_options: LoadSnapshotOptions,
    ) -> HashMap<MachineId, ManagedHostStateSnapshot>;
}

impl ManagedHostSnapshots for Vec<ManagedHost> {
    async fn snapshots(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        load_options: LoadSnapshotOptions,
    ) -> HashMap<MachineId, ManagedHostStateSnapshot> {
        crate::db::managed_host::load_by_machine_ids(
            txn,
            &self.iter().map(|m| m.id).collect::<Vec<_>>(),
            load_options,
        )
        .await
        .unwrap()
    }
}

pub struct TestMachine {
    id: MachineId,
    api: Arc<Api>,
}

impl TestMachine {
    pub fn machine_id(&self) -> &MachineId {
        &self.id
    }

    pub async fn rpc_machine(&self) -> rpc::Machine {
        self.api
            .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
                search_config: Some(rpc::forge::MachineSearchConfig {
                    include_dpus: false,
                    include_history: true,
                    ..Default::default()
                }),
                id: self.id.into(),
                fqdn: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .machines
            .remove(0)
    }

    pub async fn next_iteration_machine(&self, env: &TestEnv) -> Machine {
        env.run_machine_state_controller_iteration().await;
        let mut txn = env.pool.begin().await.unwrap();
        let dpu = self.db_machine(&mut txn).await;
        txn.commit().await.unwrap();
        dpu
    }

    pub async fn db_machine(&self, txn: &mut Txn<'_>) -> Machine {
        crate::db::machine::find_one(txn, &self.id, Default::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn first_interface_id(&self, txn: &mut Txn<'_>) -> MachineInterfaceId {
        crate::db::machine_interface::find_by_machine_ids(txn, &[self.id])
            .await
            .unwrap()
            .get(&self.id)
            .unwrap()[0]
            .id
    }

    pub async fn first_interface(&self, txn: &mut Txn<'_>) -> TestMachineInterface {
        TestMachineInterface {
            id: crate::db::machine_interface::find_by_machine_ids(txn, &[self.id])
                .await
                .unwrap()
                .get(&self.id)
                .unwrap()[0]
                .id,
            api: self.api.clone(),
        }
    }

    pub async fn reboot_completed(&self) -> rpc::forge::MachineRebootCompletedResponse {
        tracing::info!("Machine ={} rebooted", self.id);
        self.api
            .reboot_completed(Request::new(rpc::forge::MachineRebootCompletedRequest {
                machine_id: self.id.into(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    pub async fn forge_agent_control(&self) -> rpc::forge::ForgeAgentControlResponse {
        let _ = self.reboot_completed().await;
        self.api
            .forge_agent_control(Request::new(rpc::forge::ForgeAgentControlRequest {
                machine_id: self.id.into(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    pub async fn discovery_completed(&self) {
        let _response = self
            .api
            .discovery_completed(Request::new(rpc::forge::MachineDiscoveryCompletedRequest {
                machine_id: self.id.into(),
            }))
            .await
            .unwrap()
            .into_inner();
    }

    pub async fn trigger_dpu_reprovisioning(
        &self,
        mode: rpc::forge::dpu_reprovisioning_request::Mode,
        update_firmware: bool,
    ) {
        self.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: self.id.into(),
                    mode: mode as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware,
                },
            ))
            .await
            .unwrap();
    }
}

pub struct TestMachineInterface {
    id: MachineInterfaceId,
    api: Arc<Api>,
}

impl TestMachineInterface {
    pub async fn get_pxe_instructions(&self, arch: MachineArchitecture) -> PxeInstructions {
        self.api
            .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
                arch: arch as i32,
                interface_id: Some(self.id.into()),
            }))
            .await
            .unwrap()
            .into_inner()
    }
}
