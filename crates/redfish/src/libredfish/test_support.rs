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
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialReader, TestCredentialManager,
};
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
use mac_address::MacAddress;
use sqlx::PgPool;

use crate::libredfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool};

#[derive(Default)]
struct RedfishSimState {
    hosts: HashMap<String, RedfishSimHostState>,
    users: HashMap<String, String>,
    fw_version: Arc<String>,
    secure_boot: AtomicBool,
    machine_setup_bios_job_id: Option<String>,
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

    pub fn set_machine_setup_bios_job_id(&self, job_id: Option<String>) {
        self.state.lock().unwrap().machine_setup_bios_job_id = job_id;
    }

    pub fn set_job_state_sequence(&self, states: Vec<JobState>) {
        self.state.lock().unwrap().job_state_sequence = VecDeque::from(states);
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

#[async_trait]
impl Redfish for RedfishSimClient {
    async fn get_power_state(&self) -> Result<libredfish::PowerState, RedfishError> {
        Ok(self.state.lock().unwrap().hosts[&self._host].power)
    }

    async fn get_power_metrics(&self) -> Result<libredfish::model::power::Power, RedfishError> {
        todo!()
    }

    async fn power(&self, action: libredfish::SystemPowerControl) -> Result<(), RedfishError> {
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
    }

    fn ac_powercycle_supported_by_power(&self) -> bool {
        false
    }

    async fn bmc_reset(&self) -> Result<(), RedfishError> {
        let mut state = self.state.lock().unwrap();
        let host_state = state.hosts.get_mut(&self._host).unwrap();
        host_state.actions.push(RedfishSimAction::BmcReset);
        Ok(())
    }

    async fn get_thermal_metrics(
        &self,
    ) -> Result<libredfish::model::thermal::Thermal, RedfishError> {
        todo!()
    }

    async fn machine_setup(
        &self,
        _boot_interface_mac: Option<&str>,
        _bios_profiles: &HashMap<
            libredfish::model::service_root::RedfishVendor,
            HashMap<
                String,
                HashMap<libredfish::BiosProfileType, HashMap<String, serde_json::Value>>,
            >,
        >,
        _profile_type: libredfish::BiosProfileType,
        oem_manager_profiles: &HashMap<
            libredfish::model::service_root::RedfishVendor,
            HashMap<
                String,
                HashMap<libredfish::BiosProfileType, HashMap<String, serde_json::Value>>,
            >,
        >,
    ) -> Result<Option<String>, RedfishError> {
        let mut state = self.state.lock().unwrap();
        let host_state = state.hosts.get_mut(&self._host).unwrap();
        host_state.actions.push(RedfishSimAction::MachineSetup {
            oem_manager_profiles: oem_manager_profiles.clone(),
        });
        Ok(state.machine_setup_bios_job_id.clone())
    }

    async fn machine_setup_status(
        &self,
        _boot_interface_mac: Option<&str>,
    ) -> Result<libredfish::MachineSetupStatus, RedfishError> {
        Ok(libredfish::MachineSetupStatus {
            is_done: true,
            diffs: vec![],
        })
    }

    async fn lockdown(&self, target: libredfish::EnabledDisabled) -> Result<(), RedfishError> {
        let mut state = self.state.lock().unwrap();
        let host_state = state.hosts.get_mut(&self._host).unwrap();
        host_state.lockdown = target;
        Ok(())
    }

    async fn lockdown_status(&self) -> Result<libredfish::Status, RedfishError> {
        let state = self.state.lock().unwrap();
        Ok(libredfish::Status::build_fake(
            state.hosts[&self._host].lockdown,
        ))
    }

    async fn setup_serial_console(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn serial_console_status(&self) -> Result<libredfish::Status, RedfishError> {
        todo!()
    }

    async fn get_boot_options(&self) -> Result<libredfish::BootOptions, RedfishError> {
        Ok(libredfish::BootOptions {
            odata: Default::default(),
            description: None,
            members: vec![],
            name: "Boot Options".to_string(),
        })
    }

    async fn get_boot_option(
        &self,
        option_id: &str,
    ) -> Result<libredfish::model::BootOption, RedfishError> {
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
    }

    async fn boot_once(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn boot_first(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
        todo!()
    }

    async fn clear_tpm(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn bios(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    async fn set_bios(
        &self,
        _values: HashMap<String, serde_json::Value>,
    ) -> Result<(), RedfishError> {
        todo!()
    }

    async fn pending(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    async fn clear_pending(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn pcie_devices(&self) -> Result<Vec<libredfish::PCIeDevice>, RedfishError> {
        Ok(vec![])
    }

    async fn change_password(&self, user: &str, new: &str) -> Result<(), RedfishError> {
        let s_user = user.to_string();
        let mut state = self.state.lock().unwrap();
        if !state.users.contains_key(&s_user) {
            return Err(RedfishError::UserNotFound(s_user));
        }
        state.users.insert(s_user, new.to_string());
        Ok(())
    }

    async fn change_password_by_id(
        &self,
        account_id: &str,
        new_pass: &str,
    ) -> Result<(), RedfishError> {
        let s_acct = account_id.to_string();
        let mut state = self.state.lock().unwrap();
        if !state.users.contains_key(&s_acct) {
            return Err(RedfishError::UserNotFound(s_acct));
        }
        state.users.insert(s_acct, new_pass.to_string());
        Ok(())
    }

    async fn get_firmware(
        &self,
        id: &str,
    ) -> Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError> {
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
    }

    async fn update_firmware(
        &self,
        _firmware: tokio::fs::File,
    ) -> Result<libredfish::model::task::Task, RedfishError> {
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
    }

    async fn update_firmware_simple_update(
        &self,
        _image_uri: &str,
        _targets: Vec<String>,
        _transfer_protocol: TransferProtocolType,
    ) -> Result<libredfish::model::task::Task, RedfishError> {
        Ok(serde_json::from_str(
            "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\"
            }",
        )
        .unwrap())
    }

    async fn get_task(&self, _id: &str) -> Result<libredfish::model::task::Task, RedfishError> {
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
    }

    async fn get_chassis_all(&self) -> Result<Vec<String>, RedfishError> {
        Ok(vec![
            "Bluefield_BMC".to_string(),
            "Bluefield_EROT".to_string(),
            "Card1".to_string(),
        ])
    }

    async fn get_chassis(&self, _id: &str) -> Result<Chassis, RedfishError> {
        Ok(Chassis {
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            name: Some("Card1".to_string()),
            ..Default::default()
        })
    }

    async fn get_chassis_network_adapters(
        &self,
        _chassis_id: &str,
    ) -> Result<Vec<String>, RedfishError> {
        Ok(vec!["NvidiaNetworkAdapter".to_string()])
    }

    async fn get_chassis_network_adapter(
        &self,
        _chassis_id: &str,
        _id: &str,
    ) -> Result<libredfish::model::chassis::NetworkAdapter, RedfishError> {
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
    }

    async fn get_chassis_assembly(&self, _id: &str) -> Result<Assembly, RedfishError> {
        todo!()
    }

    async fn get_manager_ethernet_interfaces(
        &self,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        Ok(vec!["eth0".to_string(), "vlan4040".to_string()])
    }

    async fn get_manager_ethernet_interface(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError> {
        Ok(libredfish::model::ethernet_interface::EthernetInterface::default())
    }

    async fn get_system_ethernet_interfaces(
        &self,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        Ok(vec!["oob_net0".to_string()])
    }

    async fn get_system_ethernet_interface(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError> {
        Ok(libredfish::model::ethernet_interface::EthernetInterface::default())
    }

    async fn get_software_inventories(&self) -> Result<Vec<std::string::String>, RedfishError> {
        Ok(vec![
            "BMC_Firmware".to_string(),
            "Bluefield_FW_ERoT".to_string(),
            "DPU_NIC".to_string(),
        ])
    }

    async fn get_system(&self) -> Result<libredfish::model::ComputerSystem, RedfishError> {
        Ok(libredfish::model::ComputerSystem {
            id: "Bluefield".to_string(),
            boot_progress: Some(libredfish::model::BootProgress {
                last_state: Some(libredfish::model::BootProgressTypes::OSRunning),
                last_state_time: Some(Utc::now().to_string()),
                oem_last_state: Some("OSRunning".to_string()),
            }),
            ..Default::default()
        })
    }

    async fn get_secure_boot(
        &self,
    ) -> Result<libredfish::model::secure_boot::SecureBoot, RedfishError> {
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
    }

    async fn disable_secure_boot(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_network_device_functions(
        &self,
        _chassis_id: &str,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        Ok(Vec::new())
    }

    async fn get_network_device_function(
        &self,
        _chassis_id: &str,
        _id: &str,
        _port: Option<&str>,
    ) -> Result<libredfish::model::network_device_function::NetworkDeviceFunction, RedfishError>
    {
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
    }

    async fn get_ports(
        &self,
        _chassis_id: &str,
        _network_adapter: &str,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        Ok(Vec::new())
    }

    async fn get_port(
        &self,
        _chassis_id: &str,
        _network_adapter: &str,
        _id: &str,
    ) -> Result<libredfish::model::port::NetworkPort, RedfishError> {
        Ok(libredfish::model::port::NetworkPort {
            odata: None,
            description: None,
            id: None,
            name: None,
            link_status: None,
            link_network_technology: None,
            current_speed_gbps: None,
        })
    }

    async fn change_uefi_password(
        &self,
        _current_uefi_password: &str,
        _new_uefi_password: &str,
    ) -> Result<Option<String>, RedfishError> {
        Ok(None)
    }

    async fn change_boot_order(&self, _boot_array: Vec<String>) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn create_user(
        &self,
        username: &str,
        password: &str,
        _role_id: libredfish::RoleId,
    ) -> Result<(), RedfishError> {
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
    }

    async fn delete_user(&self, _username: &str) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_service_root(
        &self,
    ) -> Result<libredfish::model::service_root::ServiceRoot, RedfishError> {
        Ok(ServiceRoot {
            vendor: Some("Nvidia".to_string()),
            component_integrity: Some(ODataId {
                odata_id: "Valid Data".to_string(),
            }),
            ..Default::default()
        })
    }

    async fn get_systems(&self) -> Result<Vec<String>, RedfishError> {
        Ok(Vec::new())
    }

    async fn get_managers(&self) -> Result<Vec<String>, RedfishError> {
        Ok(Vec::new())
    }

    async fn get_manager(&self) -> Result<libredfish::model::Manager, RedfishError> {
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
    }

    async fn bmc_reset_to_defaults(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_system_event_log(
        &self,
    ) -> Result<Vec<libredfish::model::sel::LogEntry>, RedfishError> {
        Ok(Vec::new())
    }

    async fn get_bmc_event_log(
        &self,
        _from: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<libredfish::model::sel::LogEntry>, RedfishError> {
        Err(RedfishError::NotSupported(
            "BMC Event Log not supported for tests".to_string(),
        ))
    }

    async fn get_tasks(&self) -> Result<Vec<String>, RedfishError> {
        Ok(Vec::new())
    }

    async fn add_secure_boot_certificate(&self, _: &str, _: &str) -> Result<Task, RedfishError> {
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
    }

    async fn enable_secure_boot(&self) -> Result<(), RedfishError> {
        self.state
            .clone()
            .lock()
            .unwrap()
            .secure_boot
            .store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn change_username(&self, _old_name: &str, _new_name: &str) -> Result<(), RedfishError> {
        Ok(())
    }
    async fn get_accounts(
        &self,
    ) -> Result<Vec<libredfish::model::account_service::ManagerAccount>, RedfishError> {
        todo!()
    }
    async fn set_machine_password_policy(&self) -> Result<(), RedfishError> {
        Ok(())
    }
    async fn update_firmware_multipart(
        &self,
        _filename: &Path,
        _reboot: bool,
        _timeout: Duration,
        _component_type: ComponentType,
    ) -> Result<String, RedfishError> {
        // Simulate it taking a bit of time to upload
        tokio::time::sleep(Duration::from_secs(4)).await;
        Ok("0".to_string())
    }

    async fn get_job_state(&self, _job_id: &str) -> Result<JobState, RedfishError> {
        let mut state = self.state.lock().unwrap();
        Ok(state
            .job_state_sequence
            .pop_front()
            .unwrap_or(JobState::Unknown))
    }

    async fn get_collection(&self, _id: ODataId) -> Result<Collection, RedfishError> {
        Ok(Collection {
            url: String::new(),
            body: HashMap::new(),
        })
    }

    async fn get_resource(&self, _id: ODataId) -> Result<Resource, RedfishError> {
        Ok(Resource {
            url: String::new(),
            raw: Default::default(),
        })
    }

    async fn set_boot_order_dpu_first(
        &self,
        mac_address: &str,
    ) -> Result<Option<String>, RedfishError> {
        let mut state = self.state.lock().unwrap();
        let host_state = state.hosts.get_mut(&self._host).unwrap();
        host_state
            .actions
            .push(RedfishSimAction::SetBootOrderDpuFirst {
                boot_interface_mac: mac_address.to_string(),
            });
        Ok(None)
    }

    async fn clear_uefi_password(
        &self,
        _current_uefi_password: &str,
    ) -> Result<Option<String>, RedfishError> {
        Ok(None)
    }

    async fn get_base_network_adapters(
        &self,
        _system_id: &str,
    ) -> Result<Vec<String>, RedfishError> {
        Ok(vec![])
    }

    async fn get_base_network_adapter(
        &self,
        _system_id: &str,
        _id: &str,
    ) -> Result<NetworkAdapter, RedfishError> {
        todo!();
    }

    async fn chassis_reset(
        &self,
        _chassis_id: &str,
        _reset_type: SystemPowerControl,
    ) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_update_service(&self) -> Result<UpdateService, RedfishError> {
        todo!();
    }

    async fn get_base_mac_address(&self) -> Result<Option<String>, RedfishError> {
        Ok(Some("a088c208804c".to_string()))
    }

    async fn lockdown_bmc(&self, _target: EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_gpu_sensors(&self) -> Result<Vec<GPUSensors>, RedfishError> {
        todo!();
    }

    async fn get_drives_metrics(&self) -> Result<Vec<Drives>, RedfishError> {
        todo!();
    }

    async fn is_ipmi_over_lan_enabled(&self) -> Result<bool, RedfishError> {
        Ok(false)
    }

    async fn enable_ipmi_over_lan(&self, _target: EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn enable_rshim_bmc(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn clear_nvram(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_nic_mode(&self) -> Result<Option<NicMode>, RedfishError> {
        Ok(None)
    }

    async fn set_nic_mode(&self, _mode: NicMode) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn enable_infinite_boot(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn is_infinite_boot_enabled(&self) -> Result<Option<bool>, RedfishError> {
        Ok(None)
    }

    async fn reset_bios(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn set_host_rshim(&self, _enabled: EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_host_rshim(&self) -> Result<Option<EnabledDisabled>, RedfishError> {
        Ok(None)
    }

    async fn set_idrac_lockdown(&self, _enabled: EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_boss_controller(&self) -> Result<Option<String>, RedfishError> {
        Ok(None)
    }

    async fn decommission_storage_controller(
        &self,
        _controller_id: &str,
    ) -> Result<Option<String>, RedfishError> {
        Ok(None)
    }

    async fn create_storage_volume(
        &self,
        _controller_id: &str,
        _volume_name: &str,
    ) -> Result<Option<String>, RedfishError> {
        Ok(None)
    }

    async fn is_boot_order_setup(&self, boot_interface_mac: &str) -> Result<bool, RedfishError> {
        let mut state = self.state.lock().unwrap();
        let host_state = state.hosts.get_mut(&self._host).unwrap();
        host_state.actions.push(RedfishSimAction::IsBootOrderSetup {
            boot_interface_mac: boot_interface_mac.to_string(),
        });
        Ok(true)
    }

    async fn is_bios_setup(&self, _: Option<&str>) -> Result<bool, RedfishError> {
        Ok(true)
    }

    async fn get_secure_boot_certificate(
        &self,
        _database_id: &str,
        _certificate_id: &str,
    ) -> Result<Certificate, RedfishError> {
        Ok(Certificate {
            certificate_string: String::new(),
            certificate_type: "PEM".to_string(),
            issuer: HashMap::new(),
            valid_not_before: String::new(),
            valid_not_after: String::new(),
        })
    }

    async fn get_secure_boot_certificates(
        &self,
        _database_id: &str,
    ) -> Result<Vec<String>, RedfishError> {
        Ok(vec!["1".to_string()])
    }

    async fn get_component_integrities(
        &self,
    ) -> Result<libredfish::model::component_integrity::ComponentIntegrities, RedfishError> {
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
                            libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/ERoT_BMC_0/Certificates/CertChain"
                                            .to_string(),
                                },
                            },
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
                            libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_0/Certificates/CertChain"
                                            .to_string(),
                                },
                            },
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
                            libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            },
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
                    component_integrity_type: "TPM".to_string(),
                    component_integrity_type_version: "1.1.0".to_string(),
                    id: "HGX_IRoT_GPU_1".to_string(),
                    name: "SPDM Integrity for HGX_IRoT_GPU_1".to_string(),
                    target_component_uri: Some("/redfish/v1/Chassis/HGX_IRoT_GPU_1".to_string()),
                    spdm: Some(libredfish::model::component_integrity::SPDMData {
                        identity_authentication:
                            libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            },
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
                            libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            },
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
                            libredfish::model::component_integrity::ResponderAuthentication {
                                component_certificate: ODataId {
                                    odata_id:
                                        "/redfish/v1/Chassis/HGX_IRoT_GPU_1/Certificates/CertChain"
                                            .to_string(),
                                },
                            },
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
                count: 6,
            })
    }

    async fn get_firmware_for_component(
        &self,
        component_integrity_id: &str,
    ) -> Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError> {
        if !component_integrity_id.contains("HGX_IRoT_GPU_") {
            return Err(RedfishError::NotSupported(
                "not supported device".to_string(),
            ));
        }
        Ok(SoftwareInventory {
            odata: ODataLinks {
                odata_context: None,
                odata_id: "/redfish/v1/UpdateService/FirmwareInventory/HGX_FW_GPU_0".to_string(),
                odata_type: "#SoftwareInventory.v1_4_0.SoftwareInventory".to_string(),
                odata_etag: None,
                links: None,
            },
            description: None,
            id: component_integrity_id.to_string(),
            version: Some("97.00.82.00.5F".to_string()),
            release_date: None,
        })
    }

    async fn get_component_ca_certificate(
        &self,
        _url: &str,
    ) -> Result<libredfish::model::component_integrity::CaCertificate, RedfishError> {
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
    }

    async fn trigger_evidence_collection(
        &self,
        _url: &str,
        _nonce: &str,
    ) -> Result<Task, RedfishError> {
        Ok(serde_json::from_str(
            "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\"
            }",
        )
        .unwrap())
    }

    async fn get_evidence(
        &self,
        _url: &str,
    ) -> Result<libredfish::model::component_integrity::Evidence, RedfishError> {
        Ok(serde_json::from_str(r#"{
  "HashingAlgorithm": "TPM_ALG_SHA_512",
  "SignedMeasurements": "EeAB/81ALklRkZ0fn8F7O77CNxHPOc8qUBSxyklrCAUYJkkLATUAATIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABxanBrNxxfwfICAJzQ0008O0greTQqXk737JD0VEpjAwAAJiAwRSQU+6KuRrawestxwit0TbmColQFu1wvCp+l1Iwchz0xEfaiI6r4lmCUk5tL0DPnBnYBurQrNIrqqwk5G1C+H5VW25T+N/B+8oojcVByle4LCq6pubLivQGKAYPb",
  "SigningAlgorithm": "TPM_ALG_ECDSA_ECC_NIST_P384",
  "Version": "1.1.0"
}"#).unwrap())
    }

    async fn set_host_privilege_level(
        &self,
        _level: HostPrivilegeLevel,
    ) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn set_utc_timezone(&self) -> Result<(), RedfishError> {
        self.state
            .lock()
            .unwrap()
            .hosts
            .get_mut(&self._host)
            .unwrap()
            .actions
            .push(RedfishSimAction::SetUtcTimezone);
        Ok(())
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

    async fn create_client_for_ingested_host(
        &self,
        ip: IpAddr,
        port: Option<u16>,
        _txn: &PgPool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_client(
            &ip.to_string(),
            port,
            RedfishAuth::Key(CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: MacAddress::default(),
                },
            }),
            None,
        )
        .await
    }

    async fn uefi_setup(
        &self,
        _client: &dyn Redfish,
        _dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        Ok(None)
    }
}
