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

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use forge_secrets::credentials::CredentialReader;
use forge_secrets::test_support::credentials::TestCredentialManager;
use libredfish::model::certificate::Certificate;
use libredfish::model::component_integrity::{ComponentIntegrities, ComponentIntegrity};
use libredfish::model::oem::nvidia_dpu::{HostPrivilegeLevel, NicMode};
use libredfish::model::secure_boot::SecureBootMode;
use libredfish::model::sensor::GPUSensors;
use libredfish::model::service_root::{RedfishVendor, ServiceRoot};
use libredfish::model::software_inventory::SoftwareInventory;
use libredfish::model::storage::Drives;
use libredfish::model::task::Task;
use libredfish::model::update_service::{ComponentType, TransferProtocolType, UpdateService};
use libredfish::model::{ODataId, ODataLinks};
use libredfish::{
    Assembly, Chassis, Collection, EnabledDisabled, JobState, NetworkAdapter, PowerState, Redfish,
    RedfishError, Resource, SystemPowerControl,
};

use crate::libredfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool};

const TRIGGER_EVIDENCE_TASK_ID: &str = "SpdmTriggerEvidenceTaskId";

#[derive(Default)]
struct RedfishSimState {
    hosts: HashMap<String, RedfishSimHostState>,
    users: HashMap<String, String>,
    fw_version: Arc<String>,
    secure_boot: AtomicBool,
    no_component_integrities: bool,
    firmware_for_component_error: bool,
    get_task_trigger_evidence_returns_interrupted: bool,
    machine_setup_bios_job_id: Option<String>,
    is_bios_setup: Option<bool>,
    job_state_sequence: VecDeque<JobState>,
    /// Records every call to `RedfishClientPool::create_client` so tests can
    /// assert what vendor was passed at each call site.
    create_client_calls: Vec<CreateClientCall>,
}

/// Snapshot of a single `RedfishClientPool::create_client` invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateClientCall {
    pub host: String,
    pub vendor: Option<RedfishVendor>,
}

#[derive(Debug)]
struct RedfishSimHostState {
    power: PowerState,
    lockdown: libredfish::EnabledDisabled,
    actions: Vec<RedfishSimAction>,
}

impl Default for RedfishSimHostState {
    fn default() -> Self {
        Self {
            power: PowerState::default(),
            lockdown: libredfish::EnabledDisabled::Disabled,
            actions: Vec::default(),
        }
    }
}

#[derive(Default)]
pub struct RedfishSim {
    state: Arc<Mutex<RedfishSimState>>,
    credential_manager: TestCredentialManager,
}

impl RedfishSim {
    pub fn timepoint(&self) -> RedfishSimTimepoint {
        RedfishSimTimepoint {
            pos: self
                .state
                .lock()
                .unwrap()
                .hosts
                .iter()
                .map(|(host, state)| (host.clone(), state.actions.len()))
                .collect(),
        }
    }

    pub fn actions_since(&self, timepoint: &RedfishSimTimepoint) -> RedfishSimActions {
        let state = self.state.lock().unwrap();
        RedfishSimActions {
            host_actions: state
                .hosts
                .iter()
                .map(|(host, state)| {
                    (
                        host.clone(),
                        timepoint
                            .pos
                            .get(host)
                            .map(|pos| state.actions[*pos..].to_vec())
                            .unwrap_or_else(|| state.actions.clone()),
                    )
                })
                .collect(),
        }
    }

    /// Build a simulator with optional SPDM / firmware-integration test flags.
    pub fn with_test_overrides(overrides: RedfishSimTestOverrides) -> Self {
        Self {
            state: Arc::new(Mutex::new(RedfishSimState {
                no_component_integrities: overrides.no_component_integrities,
                firmware_for_component_error: overrides.firmware_for_component_error,
                get_task_trigger_evidence_returns_interrupted: overrides
                    .get_task_trigger_evidence_returns_interrupted,
                ..Default::default()
            })),
            credential_manager: TestCredentialManager::default(),
        }
    }

    pub fn set_machine_setup_bios_job_id(&self, job_id: Option<String>) {
        self.state.lock().unwrap().machine_setup_bios_job_id = job_id;
    }

    pub fn set_job_state_sequence(&self, states: Vec<JobState>) {
        self.state.lock().unwrap().job_state_sequence = VecDeque::from(states);
    }

    pub fn set_is_bios_setup(&self, ready: bool) {
        self.state.lock().unwrap().is_bios_setup = Some(ready);
    }

    /// Returns a snapshot of every `create_client` call made through this sim,
    /// in the order they happened. Useful for asserting which vendor was
    /// passed at a given call site.
    pub fn create_client_calls(&self) -> Vec<CreateClientCall> {
        self.state.lock().unwrap().create_client_calls.clone()
    }

    /// Seed a user account so calls like `change_password` /
    /// `change_password_by_id` see it as already present.
    pub fn seed_user(&self, username: &str, password: &str) {
        self.state
            .lock()
            .unwrap()
            .users
            .insert(username.to_string(), password.to_string());
    }
}

/// Optional simulation flags used by API integration tests.
#[derive(Clone, Default)]
pub struct RedfishSimTestOverrides {
    pub no_component_integrities: bool,
    pub firmware_for_component_error: bool,
    pub get_task_trigger_evidence_returns_interrupted: bool,
}

pub struct RedfishSimTimepoint {
    pos: HashMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedfishSimAction {
    Power(libredfish::SystemPowerControl),
    BmcReset,
    SetUtcTimezone,
    MachineSetup {
        oem_manager_profiles: libredfish::BiosProfileVendor,
    },
    /// Records a call to `Redfish::is_boot_order_setup`, letting
    /// tests assert that the managed-host state controller actually
    /// asked the BMC about boot order for a given MAC. Mainly used
    /// a regression check for zero-DPU hosts to make sure we're still
    /// giving them the love they deserve.
    IsBootOrderSetup {
        boot_interface_mac: String,
    },
    /// Records a call to `Redfish::set_boot_order_dpu_first`, which is
    /// used to make the given MAC the first boot device (which zero DPU
    /// hosts flow through as well using the host NIC MAC).
    SetBootOrderDpuFirst {
        boot_interface_mac: String,
    },
}

pub struct RedfishSimActions {
    host_actions: HashMap<String, Vec<RedfishSimAction>>,
}

impl RedfishSimActions {
    pub fn all_hosts(&self) -> Vec<RedfishSimAction> {
        self.host_actions
            .values()
            .flat_map(|actions| actions.iter().cloned())
            .collect()
    }
}

struct RedfishSimClient {
    state: Arc<Mutex<RedfishSimState>>,
    _host: String,
    _port: Option<u16>,
}

impl Redfish for RedfishSimClient {
    fn get_power_state<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::PowerState, RedfishError>> {
        Box::pin(async move { Ok(self.state.lock().unwrap().hosts[&self._host].power) })
    }

    fn get_power_metrics<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::power::Power, RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn power<'a>(
        &'a self,
        action: libredfish::SystemPowerControl,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            let power_state = match action {
                libredfish::SystemPowerControl::ForceOff
                | libredfish::SystemPowerControl::GracefulShutdown => PowerState::Off,
                _ => PowerState::On,
            };
            let mut state = self.state.lock().unwrap();
            let host_state = state.hosts.get_mut(&self._host).unwrap();
            host_state.power = power_state;
            host_state.actions.push(RedfishSimAction::Power(action));
            Ok(())
        })
    }

    fn ac_powercycle_supported_by_power(&self) -> bool {
        false
    }

    fn bmc_reset<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let host_state = state.hosts.get_mut(&self._host).unwrap();
            host_state.actions.push(RedfishSimAction::BmcReset);
            Ok(())
        })
    }

    fn get_thermal_metrics<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::thermal::Thermal, RedfishError>>
    {
        Box::pin(async move { todo!() })
    }

    fn machine_setup<'a>(
        &'a self,
        _boot_interface_mac: Option<&'a str>,
        _bios_profiles: &'a HashMap<
            libredfish::model::service_root::RedfishVendor,
            HashMap<
                String,
                HashMap<libredfish::BiosProfileType, HashMap<String, serde_json::Value>>,
            >,
        >,
        _profile_type: libredfish::BiosProfileType,
        oem_manager_profiles: &'a HashMap<
            libredfish::model::service_root::RedfishVendor,
            HashMap<
                String,
                HashMap<libredfish::BiosProfileType, HashMap<String, serde_json::Value>>,
            >,
        >,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let host_state = state.hosts.get_mut(&self._host).unwrap();
            host_state.actions.push(RedfishSimAction::MachineSetup {
                oem_manager_profiles: oem_manager_profiles.clone(),
            });
            Ok(state.machine_setup_bios_job_id.clone())
        })
    }

    fn machine_setup_status<'a>(
        &'a self,
        _boot_interface_mac: Option<&'a str>,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::MachineSetupStatus, RedfishError>> {
        Box::pin(async move {
            Ok(libredfish::MachineSetupStatus {
                is_done: true,
                diffs: vec![],
            })
        })
    }

    fn lockdown<'a>(
        &'a self,
        target: libredfish::EnabledDisabled,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let host_state = state.hosts.get_mut(&self._host).unwrap();
            host_state.lockdown = target;
            Ok(())
        })
    }

    fn lockdown_status<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::Status, RedfishError>> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            Ok(libredfish::Status::build_fake(
                state.hosts[&self._host].lockdown,
            ))
        })
    }

    fn setup_serial_console<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn serial_console_status<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::Status, RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn get_boot_options<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::BootOptions, RedfishError>> {
        Box::pin(async move {
            Ok(libredfish::BootOptions {
                odata: Default::default(),
                description: None,
                members: vec![],
                name: "Boot Options".to_string(),
            })
        })
    }

    fn get_boot_option<'a>(
        &'a self,
        option_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::BootOption, RedfishError>> {
        Box::pin(async move {
            Ok(libredfish::model::BootOption {
                odata: Default::default(),
                alias: None,
                description: None,
                boot_option_enabled: None,
                boot_option_reference: String::new(),
                display_name: option_id.to_string(),
                id: option_id.to_string(),
                name: option_id.to_string(),
                uefi_device_path: None,
            })
        })
    }

    fn boot_once<'a>(
        &'a self,
        _target: libredfish::Boot,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn boot_first<'a>(
        &'a self,
        _target: libredfish::Boot,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn set_boot_override<'a>(
        &'a self,
        _settings: libredfish::BootOverride,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn clear_tpm<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn bios<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<HashMap<String, serde_json::Value>, RedfishError>>
    {
        Box::pin(async move { todo!() })
    }

    fn set_bios<'a>(
        &'a self,
        _values: HashMap<String, serde_json::Value>,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn pending<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<HashMap<String, serde_json::Value>, RedfishError>>
    {
        Box::pin(async move { todo!() })
    }

    fn clear_pending<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn pcie_devices<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<libredfish::PCIeDevice>, RedfishError>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn change_password<'a>(
        &'a self,
        user: &'a str,
        new: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            let s_user = user.to_string();
            let mut state = self.state.lock().unwrap();
            if !state.users.contains_key(&s_user) {
                return Err(RedfishError::UserNotFound(s_user));
            }
            state.users.insert(s_user, new.to_string());
            Ok(())
        })
    }

    fn change_password_by_id<'a>(
        &'a self,
        account_id: &'a str,
        new_pass: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            let s_acct = account_id.to_string();
            let mut state = self.state.lock().unwrap();
            if !state.users.contains_key(&s_acct) {
                return Err(RedfishError::UserNotFound(s_acct));
            }
            state.users.insert(s_acct, new_pass.to_string());
            Ok(())
        })
    }

    fn get_firmware<'a>(
        &'a self,
        id: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError>,
    > {
        Box::pin(async move {
            if id == "Bluefield_FW_ERoT" {
                Ok(serde_json::from_str(
                    "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/Bluefield_FW_ERoT\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"Other image\",
            \"Id\": \"Bluefield_FW_ERoT\",
            \"Manufacturer\": \"NVIDIA\",
            \"Name\": \"Software Inventory\",
            \"Version\": \"00.02.0180.0000\"
            }",
                )
                .unwrap())
            } else if id == "DPU_NIC" {
                Ok(serde_json::from_str(
                    "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/DPU_NIC\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"Other image\",
            \"Id\": \"DPU_NIC\",
            \"Manufacturer\": \"NVIDIA\",
            \"Name\": \"Software Inventory\",
            \"Version\": \"32.39.2048\"
            }",
                )
                .unwrap())
            } else {
                let state = self.state.lock().unwrap();
                Ok(serde_json::from_str(
                    "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/BMC_Firmware\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"BMC image\",
            \"Id\": \"BMC_Firmware\",
            \"Name\": \"Software Inventory\",
            \"Updateable\": true,
            \"Version\": \"BF-FW-VERSION\",
            \"WriteProtected\": false
          }"
                    .replace("FW-VERSION", state.fw_version.as_str())
                    .as_str(),
                )
                .unwrap())
            }
        })
    }

    fn update_firmware<'a>(
        &'a self,
        _firmware: tokio::fs::File,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::task::Task, RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            state.fw_version = Arc::new("24.10-17".to_string());
            Ok(serde_json::from_str(
                "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\"
            }",
            )
            .unwrap())
        })
    }

    fn update_firmware_simple_update<'a>(
        &'a self,
        _image_uri: &'a str,
        _targets: Vec<String>,
        _transfer_protocol: TransferProtocolType,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::task::Task, RedfishError>> {
        Box::pin(async move {
            Ok(serde_json::from_str(
                "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\"
            }",
            )
            .unwrap())
        })
    }

    fn get_task<'a>(
        &'a self,
        id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::task::Task, RedfishError>> {
        Box::pin(async move {
            if self
                .state
                .lock()
                .unwrap()
                .get_task_trigger_evidence_returns_interrupted
                && id == TRIGGER_EVIDENCE_TASK_ID
            {
                return Ok(serde_json::from_str(
                    "{
                    \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
                    \"@odata.type\": \"#Task.v1_4_3.Task\",
                    \"Id\": \"0\",
                    \"PercentComplete\": 100,
                    \"StartTime\": \"2024-01-30T09:00:52+00:00\",
                    \"TaskMonitor\": \"/redfish/v1/TaskService/Tasks/0/Monitor\",
                    \"TaskState\": \"Interrupted\",
                    \"TaskStatus\": \"OK\"
                    }",
                )
                .unwrap());
            }
            Ok(serde_json::from_str(
                "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\",
            \"PercentComplete\": 100,
            \"StartTime\": \"2024-01-30T09:00:52+00:00\",
            \"TaskMonitor\": \"/redfish/v1/TaskService/Tasks/0/Monitor\",
            \"TaskState\": \"Completed\",
            \"TaskStatus\": \"OK\"
            }",
            )
            .unwrap())
        })
    }

    fn get_chassis_all<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move {
            Ok(vec![
                "Bluefield_BMC".to_string(),
                "Bluefield_EROT".to_string(),
                "Card1".to_string(),
            ])
        })
    }

    fn get_chassis<'a>(
        &'a self,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Chassis, RedfishError>> {
        Box::pin(async move {
            Ok(Chassis {
                manufacturer: Some("Nvidia".to_string()),
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                name: Some("Card1".to_string()),
                ..Default::default()
            })
        })
    }

    fn get_chassis_network_adapters<'a>(
        &'a self,
        _chassis_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move { Ok(vec!["NvidiaNetworkAdapter".to_string()]) })
    }

    fn get_chassis_network_adapter<'a>(
        &'a self,
        _chassis_id: &'a str,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::chassis::NetworkAdapter, RedfishError>,
    > {
        Box::pin(async move {
            Ok(serde_json::from_str(
                r##"
            {
                "@odata.id": "/redfish/v1/Chassis/Card1/NetworkAdapters/NvidiaNetworkAdapter",
                "@odata.type": "#NetworkAdapter.v1_9_0.NetworkAdapter",
                "Id": "NetworkAdapter",
                "Manufacturer": "Nvidia",
                "Name": "NvidiaNetworkAdapter",
                "NetworkDeviceFunctions": {
                  "@odata.id": "/redfish/v1/Chassis/Card1/NetworkAdapters/NvidiaNetworkAdapter/NetworkDeviceFunctions"
                },
                "Ports": {
                  "@odata.id": "/redfish/v1/Chassis/Card1/NetworkAdapters/NvidiaNetworkAdapter/Ports"
                }
              }
            "##)
                .unwrap())
        })
    }

    fn get_chassis_assembly<'a>(
        &'a self,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Assembly, RedfishError>> {
        Box::pin(async move { todo!() })
    }

    fn get_manager_ethernet_interfaces<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<std::string::String>, RedfishError>> {
        Box::pin(async move { Ok(vec!["eth0".to_string(), "vlan4040".to_string()]) })
    }

    fn get_manager_ethernet_interface<'a>(
        &'a self,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError>,
    > {
        Box::pin(
            async move { Ok(libredfish::model::ethernet_interface::EthernetInterface::default()) },
        )
    }

    fn get_system_ethernet_interfaces<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<std::string::String>, RedfishError>> {
        Box::pin(async move { Ok(vec!["oob_net0".to_string()]) })
    }

    fn get_system_ethernet_interface<'a>(
        &'a self,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError>,
    > {
        Box::pin(
            async move { Ok(libredfish::model::ethernet_interface::EthernetInterface::default()) },
        )
    }

    fn get_software_inventories<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<std::string::String>, RedfishError>> {
        Box::pin(async move {
            Ok(vec![
                "BMC_Firmware".to_string(),
                "Bluefield_FW_ERoT".to_string(),
                "DPU_NIC".to_string(),
            ])
        })
    }

    fn get_system<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::ComputerSystem, RedfishError>>
    {
        Box::pin(async move {
            Ok(libredfish::model::ComputerSystem {
                id: "Bluefield".to_string(),
                boot_progress: Some(libredfish::model::BootProgress {
                    last_state: Some(libredfish::model::BootProgressTypes::OSRunning),
                    last_state_time: Some(Utc::now().to_string()),
                    oem_last_state: Some("OSRunning".to_string()),
                }),
                ..Default::default()
            })
        })
    }

    fn get_secure_boot<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::secure_boot::SecureBoot, RedfishError>,
    > {
        Box::pin(async move {
            let secure_boot_enabled = self
                .state
                .clone()
                .lock()
                .unwrap()
                .secure_boot
                .load(Ordering::Relaxed);
            Ok(libredfish::model::secure_boot::SecureBoot {
                odata: ODataLinks {
                    odata_context: None,
                    odata_id: "/redfish/v1/Systems/Bluefield/SecureBoot".to_string(),
                    odata_type: "#SecureBoot.v1_1_0.SecureBoot".to_string(),
                    odata_etag: None,
                    links: None,
                },
                id: "SecureBoot".to_string(),
                name: "UEFI Secure Boot".to_string(),
                secure_boot_current_boot: if secure_boot_enabled {
                    Some(EnabledDisabled::Enabled)
                } else {
                    Some(EnabledDisabled::Disabled)
                },
                secure_boot_enable: Some(secure_boot_enabled),
                secure_boot_mode: Some(SecureBootMode::UserMode),
            })
        })
    }

    fn disable_secure_boot<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_network_device_functions<'a>(
        &'a self,
        _chassis_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<std::string::String>, RedfishError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_network_device_function<'a>(
        &'a self,
        _chassis_id: &'a str,
        _id: &'a str,
        _port: Option<&'a str>,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::network_device_function::NetworkDeviceFunction, RedfishError>,
    > {
        Box::pin(async move {
            Ok(
                libredfish::model::network_device_function::NetworkDeviceFunction {
                    odata: None,
                    description: None,
                    id: None,
                    ethernet: None,
                    name: None,
                    net_dev_func_capabilities: Some(Vec::new()),
                    net_dev_func_type: None,
                    links: None,
                    oem: None,
                },
            )
        })
    }

    fn get_ports<'a>(
        &'a self,
        _chassis_id: &'a str,
        _network_adapter: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<std::string::String>, RedfishError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_port<'a>(
        &'a self,
        _chassis_id: &'a str,
        _network_adapter: &'a str,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::port::NetworkPort, RedfishError>>
    {
        Box::pin(async move {
            Ok(libredfish::model::port::NetworkPort {
                odata: None,
                description: None,
                id: None,
                name: None,
                link_status: None,
                link_network_technology: None,
                current_speed_gbps: None,
            })
        })
    }

    fn change_uefi_password<'a>(
        &'a self,
        _current_uefi_password: &'a str,
        _new_uefi_password: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn change_boot_order<'a>(
        &'a self,
        _boot_array: Vec<String>,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn create_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a str,
        _role_id: libredfish::RoleId,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            if state.users.contains_key(username) {
                return Err(RedfishError::HTTPErrorCode {
                    url: "AccountService/Accounts".to_string(),
                    status_code: http::StatusCode::BAD_REQUEST,
                    response_body: format!(
                        r##"{{
                "UserName@Message.ExtendedInfo": [
                  {{
                    "@odata.type": "#Message.v1_1_1.Message",
                    "Message": "The requested resource of type ManagerAccount with the property UserName with the value {username} already exists.",
                    "MessageArgs": [
                      "ManagerAccount",
                      "UserName",
                      "{username}"
                    ],
                    "MessageId": "Base.1.15.0.ResourceAlreadyExists",
                    "MessageSeverity": "Critical",
                    "Resolution": "Do not repeat the create operation as the resource has already been created."
                  }}
                ]
              }}"##
                    ),
                });
            }

            state
                .users
                .insert(username.to_string(), password.to_string());
            Ok(())
        })
    }

    fn delete_user<'a>(
        &'a self,
        _username: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_service_root<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::service_root::ServiceRoot, RedfishError>,
    > {
        Box::pin(async move {
            Ok(ServiceRoot {
                vendor: Some("Nvidia".to_string()),
                product: Some("GB200 NVL".to_string()),
                component_integrity: Some(ODataId {
                    odata_id: "Valid Data".to_string(),
                }),
                ..Default::default()
            })
        })
    }

    fn get_systems<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_managers<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_manager<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<libredfish::model::Manager, RedfishError>> {
        Box::pin(async move {
            let mut manager: libredfish::model::Manager = serde_json::from_str(
                r##"{
            "@odata.id": "/redfish/v1/Managers/Bluefield_BMC",
            "@odata.type": "#Manager.v1_14_0.Manager",
            "Actions": {
              "#Manager.Reset": {
                "@Redfish.ActionInfo": "/redfish/v1/Managers/Bluefield_BMC/ResetActionInfo",
                "target": "/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.Reset"
              },
              "#Manager.ResetToDefaults": {
                "ResetType@Redfish.AllowableValues": [
                  "ResetAll"
                ],
                "target": "/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.ResetToDefaults"
              }
            },
            "CommandShell": {
              "ConnectTypesSupported": [
                "SSH"
              ],
              "MaxConcurrentSessions": 1,
              "ServiceEnabled": true
            },
            "DateTime": "2024-04-09T11:13:49+00:00",
            "DateTimeLocalOffset": "+00:00",
            "Description": "Baseboard Management Controller",
            "EthernetInterfaces": {
              "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/EthernetInterfaces"
            },
            "FirmwareVersion": "bf-23.10-5-0-g87a8acd1708.1701259870.8631477",
            "GraphicalConsole": {
              "ConnectTypesSupported": [
                "KVMIP"
              ],
              "MaxConcurrentSessions": 4,
              "ServiceEnabled": true
            },
            "Id": "Bluefield_BMC",
            "LastResetTime": "2024-04-01T13:04:04+00:00",
            "LogServices": {
                "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/LogServices"
              },
              "ManagerType": "BMC",
              "Model": "OpenBmc",
              "Name": "OpenBmc Manager",
              "NetworkProtocol": {
                "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/NetworkProtocol"
              },
              "Oem": {
                "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Oem",
                "@odata.type": "#OemManager.Oem",
                "Nvidia": {
                  "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Oem/Nvidia"
                },
                "OpenBmc": {
                  "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Oem/OpenBmc",
                  "@odata.type": "#OemManager.OpenBmc",
                  "Certificates": {
                    "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Truststore/Certificates"
                  }
                }
              },
              "PowerState": "On",
              "SerialConsole": {
                "ConnectTypesSupported": [
                  "IPMI",
                  "SSH"
                ],
                "MaxConcurrentSessions": 15,
                "ServiceEnabled": true
              },
              "ServiceEntryPointUUID": "a614e837-6b4a-4560-8c22-c6ed1b96c7c9",
              "Status": {
                "Conditions": [],
                "Health": "OK",
                "HealthRollup": "OK",
                "State": "Starting"
              },
              "UUID": "0b623306-fa7f-42d2-809d-a63a13d49c8d"
        }"##,
            )
            .unwrap();
            // Update the date_time to current time for tests
            manager.date_time = Some(chrono::Utc::now());
            Ok(manager)
        })
    }

    fn bmc_reset_to_defaults<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_system_event_log<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<libredfish::model::sel::LogEntry>, RedfishError>>
    {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_bmc_event_log<'a>(
        &'a self,
        _from: Option<chrono::DateTime<chrono::Utc>>,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<libredfish::model::sel::LogEntry>, RedfishError>>
    {
        Box::pin(async move {
            Err(RedfishError::NotSupported(
                "BMC Event Log not supported for tests".to_string(),
            ))
        })
    }

    fn get_tasks<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn add_secure_boot_certificate<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Task, RedfishError>> {
        Box::pin(async move {
            Ok(Task {
                odata: ODataLinks {
                    odata_context: None,
                    odata_id: "odata_id".to_string(),
                    odata_type: "odata_type".to_string(),
                    odata_etag: None,
                    links: None,
                },
                id: "".to_string(),
                messages: Vec::new(),
                name: None,
                task_state: None,
                task_status: None,
                task_monitor: None,
                percent_complete: None,
            })
        })
    }

    fn enable_secure_boot<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            self.state
                .clone()
                .lock()
                .unwrap()
                .secure_boot
                .store(true, Ordering::Relaxed);
            Ok(())
        })
    }

    fn change_username<'a>(
        &'a self,
        _old_name: &'a str,
        _new_name: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }
    fn get_accounts<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<Vec<libredfish::model::account_service::ManagerAccount>, RedfishError>,
    > {
        Box::pin(async move { todo!() })
    }
    fn set_machine_password_policy<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }
    fn update_firmware_multipart<'a>(
        &'a self,
        _filename: &'a Path,
        _reboot: bool,
        _timeout: Duration,
        _component_type: ComponentType,
    ) -> libredfish::RedfishFuture<'a, Result<String, RedfishError>> {
        Box::pin(async move {
            // Simulate it taking a bit of time to upload
            tokio::time::sleep(Duration::from_secs(4)).await;
            Ok("0".to_string())
        })
    }

    fn get_job_state<'a>(
        &'a self,
        _job_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<JobState, RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            Ok(state
                .job_state_sequence
                .pop_front()
                .unwrap_or(JobState::Unknown))
        })
    }

    fn get_collection<'a>(
        &'a self,
        _id: ODataId,
    ) -> libredfish::RedfishFuture<'a, Result<Collection, RedfishError>> {
        Box::pin(async move {
            Ok(Collection {
                url: String::new(),
                body: HashMap::new(),
            })
        })
    }

    fn get_resource<'a>(
        &'a self,
        _id: ODataId,
    ) -> libredfish::RedfishFuture<'a, Result<Resource, RedfishError>> {
        Box::pin(async move {
            Ok(Resource {
                url: String::new(),
                raw: Default::default(),
            })
        })
    }

    fn set_boot_order_dpu_first<'a>(
        &'a self,
        mac_address: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let host_state = state.hosts.get_mut(&self._host).unwrap();
            host_state
                .actions
                .push(RedfishSimAction::SetBootOrderDpuFirst {
                    boot_interface_mac: mac_address.to_string(),
                });
            Ok(None)
        })
    }

    fn clear_uefi_password<'a>(
        &'a self,
        _current_uefi_password: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn get_base_network_adapters<'a>(
        &'a self,
        _system_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn get_base_network_adapter<'a>(
        &'a self,
        _system_id: &'a str,
        _id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<NetworkAdapter, RedfishError>> {
        Box::pin(async move {
            todo!();
        })
    }

    fn chassis_reset<'a>(
        &'a self,
        _chassis_id: &'a str,
        _reset_type: SystemPowerControl,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_update_service<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<UpdateService, RedfishError>> {
        Box::pin(async move {
            todo!();
        })
    }

    fn get_base_mac_address<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(Some("a088c208804c".to_string())) })
    }

    fn lockdown_bmc<'a>(
        &'a self,
        _target: EnabledDisabled,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_gpu_sensors<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<GPUSensors>, RedfishError>> {
        Box::pin(async move {
            todo!();
        })
    }

    fn get_drives_metrics<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<Drives>, RedfishError>> {
        Box::pin(async move {
            todo!();
        })
    }

    fn is_ipmi_over_lan_enabled<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<bool, RedfishError>> {
        Box::pin(async move { Ok(false) })
    }

    fn enable_ipmi_over_lan<'a>(
        &'a self,
        _target: EnabledDisabled,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn enable_rshim_bmc<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn clear_nvram<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_nic_mode<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Option<NicMode>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn set_nic_mode<'a>(
        &'a self,
        _mode: NicMode,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn enable_infinite_boot<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn is_infinite_boot_enabled<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Option<bool>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn reset_bios<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn set_host_rshim<'a>(
        &'a self,
        _enabled: EnabledDisabled,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_host_rshim<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Option<EnabledDisabled>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn set_idrac_lockdown<'a>(
        &'a self,
        _enabled: EnabledDisabled,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn get_boss_controller<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn decommission_storage_controller<'a>(
        &'a self,
        _controller_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn create_storage_volume<'a>(
        &'a self,
        _controller_id: &'a str,
        _volume_name: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Option<String>, RedfishError>> {
        Box::pin(async move { Ok(None) })
    }

    fn is_boot_order_setup<'a>(
        &'a self,
        boot_interface_mac: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<bool, RedfishError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let host_state = state.hosts.get_mut(&self._host).unwrap();
            host_state.actions.push(RedfishSimAction::IsBootOrderSetup {
                boot_interface_mac: boot_interface_mac.to_string(),
            });
            Ok(true)
        })
    }

    fn is_bios_setup<'a>(
        &'a self,
        _: Option<&'a str>,
    ) -> libredfish::RedfishFuture<'a, Result<bool, RedfishError>> {
        Box::pin(async move { Ok(self.state.lock().unwrap().is_bios_setup.unwrap_or(true)) })
    }

    fn get_secure_boot_certificate<'a>(
        &'a self,
        _database_id: &'a str,
        _certificate_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Certificate, RedfishError>> {
        Box::pin(async move {
            Ok(Certificate {
                certificate_string: String::new(),
                certificate_type: "PEM".to_string(),
                issuer: HashMap::new(),
                valid_not_before: String::new(),
                valid_not_after: String::new(),
            })
        })
    }

    fn get_secure_boot_certificates<'a>(
        &'a self,
        _database_id: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Vec<String>, RedfishError>> {
        Box::pin(async move { Ok(vec!["1".to_string()]) })
    }

    fn get_component_integrities<'a>(
        &'a self,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::component_integrity::ComponentIntegrities, RedfishError>,
    > {
        Box::pin(async move {
            if self.state.lock().unwrap().no_component_integrities {
                return Ok(ComponentIntegrities {
                    members: Vec::new(),
                    name: "ComponentIntegrities".to_string(),
                    count: 0,
                });
            }
            Ok(ComponentIntegrities {
                members: vec![ComponentIntegrity {
                    component_integrity_enabled: true,
                    component_integrity_type: "SPDM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "ERoT_BMC_0".to_string(),
                    name: "SPDM Integrity for ERoT_BMC_0".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/ERoT_BMC_0".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/ERoT_BMC_0/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/ERoT_BMC_0/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/ERoT_BMC_0/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Managers/BMC_0".to_string() }]
                        },
                    ),
                },
                ComponentIntegrity {
                    component_integrity_enabled: true,
                    component_integrity_type: "SPDM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "HGX_IRoT_GPU_0".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_0".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_0".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_0/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_0/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_0/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_0".to_string() }]
                        },
                    ),
                },
                ComponentIntegrity {
                    component_integrity_enabled: true,
                    component_integrity_type: "SPDM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "HGX_IRoT_GPU_1".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_1".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_1".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_1".to_string() }]
                        },
                    ),
                },
                ComponentIntegrity {
                    component_integrity_enabled: true,
                    component_integrity_type: "SPDM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "HGX_IRoT_GPU_2".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_2".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_2".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_2/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_2/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_2/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_2".to_string() }]
                        },
                    ),
                },
                ComponentIntegrity {
                    component_integrity_enabled: true,
                    component_integrity_type: "TPM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "HGX_IRoT_GPU_1".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_1".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_1".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_1".to_string() }]
                        },
                    ),
                },
                ComponentIntegrity {
                    component_integrity_enabled: false,
                    component_integrity_type: "SPDM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "HGX_IRoT_GPU_1".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_1".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_1".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_1".to_string() }]
                        },
                    ),
                },
                ComponentIntegrity {
                    component_integrity_enabled: true,
                    component_integrity_type: "SPDM".to_string(),
                    component_integrity_type_version: "0.1.0".to_string(),
                    id: "HGX_IRoT_GPU_1".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_1".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_1".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::IdentityAuthentication { responder_authentication: libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            } },
                        requester: ODataId {
                            odata_id: "/redfish/v1/Managers/BMC_0".to_string(),
                        },
                    }),
                    actions: Some(libredfish::model::component_integrity::SPDMActions {
                        get_signed_measurements: Some(
                            libredfish::model::component_integrity::SPDMGetSignedMeasurements {
                                action_info: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/SPDMGetSignedMeasurementsActionInfo".to_string(),
                                target: "/redfish/v1/ComponentIntegrity/HGX_IRoT_GPU_1/Actions/ComponentIntegrity.SPDMGetSignedMeasurements".to_string(),
                            },
                        ),
                    }),
                    links: Some(
                        libredfish::model::component_integrity::ComponentsProtectedLinks {
                            components_protected: vec![ODataId{ odata_id: "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_1".to_string() }]
                        },
                    ),
                },
                ],
                name: "ComponentIntegrities".to_string(),
                count: 7,
            })
        })
    }

    fn get_firmware_for_component<'a>(
        &'a self,
        component_integrity_id: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError>,
    > {
        Box::pin(async move {
            if self.state.lock().unwrap().firmware_for_component_error {
                return Err(RedfishError::GenericError {
                    error: "Firmware for Component Error".to_string(),
                });
            }
            if !component_integrity_id.contains("HGX_IRoT_GPU_") {
                return Err(RedfishError::NotSupported(
                    "not supported device".to_string(),
                ));
            }
            Ok(SoftwareInventory {
                odata: ODataLinks {
                    odata_context: None,
                    odata_id: "/redfish/v1/UpdateService/FirmwareInventory/HGX_FW_GPU_0"
                        .to_string(),
                    odata_type: "#SoftwareInventory.v1_4_0.SoftwareInventory".to_string(),
                    odata_etag: None,
                    links: None,
                },
                description: None,
                id: component_integrity_id.to_string(),
                version: Some("97.00.82.00.5F".to_string()),
                release_date: None,
            })
        })
    }

    fn get_component_ca_certificate<'a>(
        &'a self,
        _url: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::component_integrity::CaCertificate, RedfishError>,
    > {
        Box::pin(async move {
            Ok(serde_json::from_str(r#"{
    "@odata.id": "/redfish/v1/Chassis/HGX_IRoT_GPU_0/Certificates/CertChain",
    "@odata.type": "Certificate.v1_5_0.Certificate",
    "CertificateString": "-----BEGIN CERTIFICATE-----\nMIIDdDCCAvqgAwIBAgIUdgzUdmT3058TdKflDS6w/mP3ps3F9n3TLq8GZw3U9tiL3T57skQBoIL\nTssh8Q5sdh+fdbgkiawE0IKvw26uFwIwZ0UBCk+3B6JuSijznMdCaX+lwxJ0Eq7V\nSFpkQATVveySG/Qo8NreDDAfu5dAcVBr\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjjCCAhWgAwIBAgIJQMW6N4r97aTmMAoGCCqGSM49BAMDMFcxKzApBgNVBAMM\nIk5WSURJQSBHQjEwMCBQcm92aXNpb25lciBJQ0EgMDAwMDAxGzAZBgNVBAoMEk5W\nSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwIBcNMjMwNjIwMDAwMDAwWhgP\nOTk5OTEyMzEyMzU5NTlaMGQxGzAZBgNVBAUTEjQwQzVCQTM3OEFGREVEQTRFNjEL\nMAkGA1UEBhMCVVMxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjEbMBkGA1UE\nAwwSR0IxMDAgQTAxIEZTUCBCUk9NMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4j9u\nVBS3aGs3+UXZz0zjA75rR4+vZ/dmSi077kPcErBP7TeY82L2YfmaEpB2H/aEw9x3\n8aTby9x+920rG9NN+8O8CBKzQW7YBpwGFUkmnLtcN34cMEw2gwUGTEvdtPfdo4Gd\nMIGaMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMDcGCCsGAQUFBwEB\nBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL29jc3AubmRpcy5udmlkaWEuY29tMB0G\nA1UdDgQWBBSRs+v751iHdsbshaYSkL+OTRhnfTAfBgNVHSMEGDAWgBQD78BUvvHZ\nTb1ls+d0V1ySn+B2RTAKBggqhkjOPQQDAwNnADBkAjANWRl8oyEkvYEk2KOY6YgS\nesPo7Wjnvpox3fLIk6FCxcX0Zirezk1T6COhPIK95PACMG5JPYssNlWpjeWOLs5x\nkyAyW2sgtXU9RKxm6i8lmjWyXG3odPVUF8F12CaIxTp5eg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICrjCCAjOgAwIBAgIQXYBfwgLOvCcgRkD8IC+BhTAKBggqhkjOPQQDAzA9MR4w\nHAYDVQQDDBVOVklESUEgR0IxMDAgSWRlbnRpdHkxGzAZBgNVBAoMEk5WSURJQSBD\nb3Jwb3JhdGlvbjAgFw0yMzA2MjAwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowVzEr\nMCkGA1UEAwwiTlZJRElBIEdCMTAwIFByb3Zpc2lvbmVyIElDQSAwMDAwMDEbMBkG\nA1UECgwSTlZJRElBIENvcnBvcmF0aW9uMQswCQYDVQQGEwJVUzB2MBAGByqGSM49\nAgEGBSuBBAAiA2IABBdKHmiD7JKUIKnyKTdLazbcVBj9HMpHaOE9nEcQvoeoZeHn\nV1Gc+SwOvxtMl7tckYLx4BQLEs/AXWYx0hAVleVP3krbeIfWtmEwsPa9IQQ4APpH\nOYZp9QwBoYHNcci9c6OB2zCB2DAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\nAwIBBjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3JsLm5kaXMubnZpZGlhLmNv\nbS9jcmwvbDItZ2IxMDAuY3JsMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYb\naHR0cDovL29jc3AubmRpcy5udmlkaWEuY29tMB0GA1UdDgQWBBQD78BUvvHZTb1l\ns+d0V1ySn+B2RTAfBgNVHSMEGDAWgBTtqWR9ZFo/Pa3Guetkw1uSG6TgAjAKBggq\nhkjOPQQDAwNpADBmAjEA8M2NglY92IX9SQrtvdfMTxl4A02CqLHZeleuBHgRX7Mn\n5C7jfE5c23Ejl0j1JnB1AjEAt+tHqjht6MbZJtLX/09pFnFgcTHG0erYR8v375gq\niC3QSP6Khjum4ukzH0KV6JRm\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICijCCAhCgAwIBAgIQV7ceDOVWAwo2pOUrTKlfHjAKBggqhkjOPQQDAzA1MSIw\nIAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklE\nSUEwIBcNMjMwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMD0xHjAcBgNVBAMM\nFU5WSURJQSBHQjEwMCBJZGVudGl0eTEbMBkGA1UECgwSTlZJRElBIENvcnBvcmF0\naW9uMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/XKlEaBWlqMDj+rpBFEjY2LYS+Ja\niRyYigtuUNpFRia3nsWoBwewhLA1wrw56KAGDXInX5Yde14hqPXCgjUzNkbN5mrC\nmya7oXdUtVYA186E9LlPsm8YEwiPaDd/3Vl8o4HaMIHXMA8GA1UdEwEB/wQFMAMB\nAf8wDgYDVR0PAQH/BAQDAgEGMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwu\nbmRpcy5udmlkaWEuY29tL2NybC9sMS1yb290LmNybDA3BggrBgEFBQcBAQQrMCkw\nJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLm5kaXMubnZpZGlhLmNvbTAdBgNVHQ4E\nFgQU7alkfWRaPz2txrnrZMNbkhuk4AIwHwYDVR0jBBgwFoAUV4X/g/JjzGV9aLc6\nW/SNSsv7SV8wCgYIKoZIzj0EAwMDaAAwZQIwSDCBZ6OhBe4gV1ueWUwYAeDI/LAj\nS8GSEh5PxCwiHMs1EYcOGlCX2e/RlJ8lDFuGAjEAwFOOiBjvktWQP8Fgj7hGefny\nJPhnEXLwVYUemI4ejiPsua4GKin56ip9ZoEHdBUQ\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICCzCCAZCgAwIBAgIQLTZwscoQBBHB/sDoKgZbVDAKBggqhkjOPQQDAzA1MSIw\nIAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklE\nSUEwIBcNMjExMTA1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDUxIjAgBgNVBAMM\nGU5WSURJQSBEZXZpY2UgSWRlbnRpdHkgQ0ExDzANBgNVBAoMBk5WSURJQTB2MBAG\nByqGSM49AgEGBSuBBAAiA2IABA5MFKM7+KViZljbQSlgfky/RRnEQScW9NDZF8SX\ngAW96r6u/Ve8ZggtcYpPi2BS4VFu6KfEIrhN6FcHG7WP05W+oM+hxj7nyA1r1jkB\n2Ry70YfThX3Ba1zOryOP+MJ9vaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\nAf8EBAMCAQYwHQYDVR0OBBYEFFeF/4PyY8xlfWi3Olv0jUrL+0lfMB8GA1UdIwQY\nMBaAFFeF/4PyY8xlfWi3Olv0jUrL+0lfMAoGCCqGSM49BAMDA2kAMGYCMQCPeFM3\nTASsKQVaT+8S0sO9u97PVGCpE9d/I42IT7k3UUOLSR/qvJynVOD1vQKVXf0CMQC+\nEY55WYoDBvs2wPAH1Gw4LbcwUN8QCff8bFmV4ZxjCRr4WXTLFHBKjbfneGSBWwA=\n-----END CERTIFICATE-----\n",
    "CertificateType": "PEMchain",
    "CertificateUsageTypes": [
        "Device"
    ],
    "Id": "CertChain",
    "Name": "HGX_IRoT_GPU_0 Certificate Chain",
    "SPDM": {
        "SlotId": 0
    }
}"#).unwrap())
        })
    }

    fn trigger_evidence_collection<'a>(
        &'a self,
        _url: &'a str,
        _nonce: &'a str,
    ) -> libredfish::RedfishFuture<'a, Result<Task, RedfishError>> {
        Box::pin(async move {
            let task_str = format!(
                r##"{{
                    "@odata.id": "/redfish/v1/TaskService/Tasks/{TRIGGER_EVIDENCE_TASK_ID}",
                    "@odata.type": "#Task.v1_4_3.Task",
                    "Id": "{TRIGGER_EVIDENCE_TASK_ID}"
                }}"##
            );
            Ok(serde_json::from_str(&task_str).unwrap())
        })
    }

    fn get_evidence<'a>(
        &'a self,
        _url: &'a str,
    ) -> libredfish::RedfishFuture<
        'a,
        Result<libredfish::model::component_integrity::Evidence, RedfishError>,
    > {
        Box::pin(async move {
            Ok(serde_json::from_str(r#"{
  "HashingAlgorithm": "TPM_ALG_SHA_512",
  "SignedMeasurements": "EeAB/81ALklRkZ0fn8F7O77CNxHPOc8qUBSxyklrCAUYJkkLATUAATIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABxanBrNxxfwfICAJzQ0008O0greTQqXk737JD0VEpjAwAAJiAwRSQU+6KuRrawestxwit0TbmColQFu1wvCp+l1Iwchz0xEfaiI6r4lmCUk5tL0DPnBnYBurQrNIrqqwk5G1C+H5VW25T+N/B+8oojcVByle4LCq6pubLivQGKAYPb",
  "SigningAlgorithm": "TPM_ALG_ECDSA_ECC_NIST_P384",
  "Version": "1.1.0"
}"#).unwrap())
        })
    }

    fn set_host_privilege_level<'a>(
        &'a self,
        _level: HostPrivilegeLevel,
    ) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move { Ok(()) })
    }

    fn set_utc_timezone<'a>(&'a self) -> libredfish::RedfishFuture<'a, Result<(), RedfishError>> {
        Box::pin(async move {
            self.state
                .lock()
                .unwrap()
                .hosts
                .get_mut(&self._host)
                .unwrap()
                .actions
                .push(RedfishSimAction::SetUtcTimezone);
            Ok(())
        })
    }
}

#[async_trait]
impl RedfishClientPool for RedfishSim {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        _auth: RedfishAuth,
        vendor: Option<RedfishVendor>,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        {
            let mut state = self.state.lock().unwrap();
            state.create_client_calls.push(CreateClientCall {
                host: host.to_string(),
                vendor,
            });
            state
                .hosts
                .entry(host.to_string())
                .or_insert(RedfishSimHostState {
                    power: PowerState::On,
                    lockdown: EnabledDisabled::Disabled,
                    actions: Default::default(),
                });
            if state.fw_version.is_empty() {
                state.fw_version = Arc::new("24.10-17".to_string());
            }
        }
        Ok(Box::new(RedfishSimClient {
            state: self.state.clone(),
            _host: host.to_string(),
            _port: port,
        }))
    }

    fn credential_reader(&self) -> &dyn CredentialReader {
        &self.credential_manager
    }

    async fn uefi_setup(
        &self,
        _client: &dyn Redfish,
        _dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        Ok(None)
    }
}
