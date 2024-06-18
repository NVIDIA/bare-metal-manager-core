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
    collections::HashMap,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, CredentialType, Credentials,
};
use http::{header::InvalidHeaderName, HeaderName, StatusCode};
use libredfish::{
    model::{
        service_root::{RedfishVendor, ServiceRoot},
        task::Task,
    },
    Chassis, Endpoint, JobState, PowerState, Redfish, RedfishError, RoleId, SystemPowerControl,
};

use crate::{
    db::{machine::Machine, machine_interface::MachineInterface},
    ipmitool::IPMITool,
    model::machine::MachineSnapshot,
    CarbideError, CarbideResult,
};
use tokio::time;

const FORGE_DPU_BMC_USERNAME: &str = "forge_admin";
const AMI_USERNAME: &str = "admin";

#[derive(thiserror::Error, Debug)]
pub enum RedfishClientCreationError {
    #[error("Missing credential {key}: {cause}")]
    MissingCredentials { key: String, cause: eyre::Report },
    #[error("Failed redfish request {0}")]
    RedfishError(RedfishError),
    #[error("Failed subtask to create redfish client  {0}")]
    SubtaskError(tokio::task::JoinError),
    #[error("Not implemeted")]
    NotImplemented,
    #[error(transparent)]
    IdentifyError(#[from] crate::site_explorer::IdentifyError),
    #[error("Invalid Header")]
    InvalidHeader(#[from] InvalidHeaderName),
    #[error("Failed setting credential {key}: {cause}")]
    SetCredentials { key: String, cause: eyre::Report },
    #[error("Missing Arguments: {0}")]
    MissingArgument(String),
    #[error("Invalid Argument: {0}: {1}")]
    InvalidArgument(String, String),
    #[error("Database Error Loading Machine Interface")]
    MachineInterfaceLoadError(#[from] crate::db::DatabaseError),
}

pub enum RedfishAuth {
    Anonymous,
    Key(CredentialKey),
    Direct(String, String), // username, password
}

/// Create Redfish clients for a certain Redfish BMC endpoint
#[async_trait]
pub trait RedfishClientPool: Send + Sync + 'static {
    /// Creates a new Redfish client for a Machines BMC
    /// `host` is the IP address or hostname of the BMC
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        initialize: bool, // fetch some initial values like system id and manager id
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;

    async fn create_client_with_custom_headers(
        &self,
        host: &str,
        port: Option<u16>,
        custom_headers: &[(String, String)],
        auth: RedfishAuth,
        initialize: bool, // fetch some initial values like system id and manager id
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;

    async fn create_forge_admin_user(
        &self,
        client: &dyn Redfish,
        machine_id: String,
    ) -> Result<(), RedfishClientCreationError>;

    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError>;
}

#[derive(Debug)]
pub struct RedfishClientPoolImpl<C> {
    pool: libredfish::RedfishClientPool,
    credential_provider: Arc<C>,
}

impl<C: CredentialProvider + 'static> RedfishClientPoolImpl<C> {
    pub fn new(credential_provider: Arc<C>, pool: libredfish::RedfishClientPool) -> Self {
        RedfishClientPoolImpl {
            credential_provider,
            pool,
        }
    }

    /// This method determines the username for AMI vendor. AMI vendor represents Viking host and
    /// Viking hosts have 'admin' as site_default username. Rest all hardware have root as
    /// site_default username.
    async fn get_user_for_ami_vendor(
        &self,
        host: &str,
        port: Option<u16>,
        password: String,
    ) -> Result<Option<&str>, RedfishClientCreationError> {
        // create a client without credentials.
        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: None,
            password: None,
        };
        let standard_client = self
            .pool
            .create_standard_client(endpoint.clone())
            .map_err(RedfishClientCreationError::RedfishError)?;

        let service_root = standard_client
            .get_service_root()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        // AMI seems very generic vendor name. So we should validate if host is reachable with
        // admin or not. If not, we can try to continue with root.
        if matches!(service_root.vendor(), Some(RedfishVendor::AMI)) {
            let endpoint = Endpoint {
                host: host.to_string(),
                port,
                user: Some(AMI_USERNAME.to_string()),
                password: Some(password),
            };

            // Creating the client performs a HTTP request to determine the BMC vendor
            let pool = self.pool.clone();
            match pool.create_client(endpoint).await {
                Ok(_) => {
                    return Ok(Some(AMI_USERNAME));
                }
                Err(_) => {
                    // We couldn't connect with admin user, may be some other hardware has AMI
                    // as vendor.
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> RedfishClientPool for RedfishClientPoolImpl<C> {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_client_with_custom_headers(host, port, &Vec::default(), auth, initialize)
            .await
    }

    async fn create_client_with_custom_headers(
        &self,
        host: &str,
        port: Option<u16>,
        custom_headers: &[(String, String)],
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let (username, password) = match auth {
            RedfishAuth::Anonymous => (None, None), // anonymous login, usually to get service root Vendor info
            RedfishAuth::Direct(username, password) => (Some(username), Some(password)),
            RedfishAuth::Key(credential_key) => {
                let credentials = self
                    .credential_provider
                    .get_credentials(credential_key.clone())
                    .await
                    .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                        key: credential_key.to_key_str(),
                        cause,
                    })?;

                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => {
                        (Some(username), Some(password))
                    }
                };

                // TODO this is annoying and needs fixing
                //
                // AMI (Viking) host uses 'admin' as username while all other hardware use 'root' as
                // username. This method will impact only for site_default HostCredentials.
                let username = if let CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                } = credential_key
                {
                    match self
                        .get_user_for_ami_vendor(host, port, password.clone().unwrap_or_default())
                        .await?
                    {
                        None => username,
                        Some(u) => {
                            tracing::info!("Viking alert. Using {u} user for host: {host}");
                            Some(u.to_string())
                        }
                    }
                } else {
                    username
                };

                (username, password)
            }
        };

        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: username,
            password,
        };

        let custom_headers = custom_headers
            .iter()
            .map(|(header_str, value_str)| {
                let header: HeaderName = HeaderName::from_str(header_str)
                    .map_err(RedfishClientCreationError::InvalidHeader)?;
                Ok((header, value_str.clone()))
            })
            .collect::<Result<Vec<(HeaderName, String)>, RedfishClientCreationError>>()?;

        if initialize {
            // Creating the client performs a HTTP request to determine the BMC vendor
            self.pool
                .create_client_with_custom_headers(endpoint, custom_headers)
                .await
                .map_err(RedfishClientCreationError::RedfishError)
        } else {
            // This client does not make any HTTP requests
            let client: Box<dyn Redfish> = self
                .pool
                .create_standard_client(endpoint.clone())
                .map_err(RedfishClientCreationError::RedfishError)?;
            Ok(client)
        }
    }

    async fn create_forge_admin_user(
        &self,
        client: &dyn Redfish,
        machine_id: String,
    ) -> Result<(), RedfishClientCreationError> {
        let username = FORGE_DPU_BMC_USERNAME;
        let password = Credentials::generate_password();
        let credential_key = CredentialKey::DpuRedfish {
            credential_type: CredentialType::Machine { machine_id },
        };
        self.credential_provider
            .set_credentials(
                credential_key.clone(),
                Credentials::UsernamePassword {
                    username: username.to_string(),
                    password: password.clone(),
                },
            )
            .await
            .map_err(|cause| RedfishClientCreationError::SetCredentials {
                key: credential_key.to_key_str(),
                cause,
            })?;
        if let Err(e) = client
            .create_user(username, password.as_str(), RoleId::Administrator)
            .await
        {
            if e.to_string().to_uppercase().contains("ALREADY EXISTS") {
                return client
                    .change_password(username, password.as_str())
                    .await
                    .map_err(RedfishClientCreationError::RedfishError);
            }
            return Err(RedfishClientCreationError::RedfishError(e));
        }
        Ok(())
    }

    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let mut job_id = None;
        let bios_attrs = client
            .bios()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;
        // If the attribute field is empty we couldn't change a UEFI password.
        if bios_attrs
            .get("Attributes")
            .map_or(true, |v| v.as_object().is_none())
        {
            tracing::warn!("Bios attributes don't have CurrentUefiPassword.");
            return Ok(job_id);
        }

        let mut current_password = String::new();
        let new_password: String;
        if dpu {
            // Replace DPU UEFI default password with site default
            // default password is taken from DpuUefi:factory_default key
            // site password is taken from DpuUefi:site_default key
            //
            let credentials = self
                .credential_provider
                .get_credentials(CredentialKey::DpuUefi {
                    credential_type: CredentialType::DpuHardwareDefault,
                })
                .await
                .unwrap_or(Credentials::UsernamePassword {
                    username: "".to_string(),
                    password: "bluefield".to_string(),
                });

            (_, current_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };

            let credential_key = CredentialKey::DpuUefi {
                credential_type: CredentialType::SiteDefault,
            };
            let credentials = self
                .credential_provider
                .get_credentials(credential_key.clone())
                .await
                .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                    key: credential_key.to_key_str(),
                    cause,
                })?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        } else {
            // the current password is always an empty string for the host uefi
            let credential_key = CredentialKey::HostUefi {
                credential_type: CredentialType::SiteDefault,
            };
            let credentials = self
                .credential_provider
                .get_credentials(credential_key.clone())
                .await
                .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                    key: credential_key.to_key_str(),
                    cause,
                })?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        }

        job_id = client
            .change_uefi_password(current_password.as_str(), new_password.as_str())
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(job_id)
    }
}

#[derive(Debug, Default)]
struct RedfishSimState {
    _hosts: HashMap<String, RedfishSimHostState>,
    users: HashMap<String, String>,
}

#[derive(Debug, Default)]
struct RedfishSimHostState {
    power: PowerState,
}

#[derive(Debug, Default)]
pub struct RedfishSim {
    state: Arc<Mutex<RedfishSimState>>,
}

#[derive(Debug)]
struct RedfishSimClient {
    state: Arc<Mutex<RedfishSimState>>,
    _host: String,
    _port: Option<u16>,
}

#[async_trait]
impl Redfish for RedfishSimClient {
    async fn get_power_state(&self) -> Result<libredfish::PowerState, RedfishError> {
        Ok(self.state.clone().lock().unwrap()._hosts[&self._host].power)
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
        self.state
            .clone()
            .lock()
            .unwrap()
            ._hosts
            .get_mut(&self._host)
            .unwrap()
            .power = power_state;
        Ok(())
    }

    async fn bmc_reset(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_thermal_metrics(
        &self,
    ) -> Result<libredfish::model::thermal::Thermal, RedfishError> {
        todo!()
    }

    async fn forge_setup(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn forge_setup_status(&self) -> Result<libredfish::ForgeSetupStatus, RedfishError> {
        Ok(libredfish::ForgeSetupStatus {
            is_done: true,
            diffs: vec![],
        })
    }

    async fn lockdown(&self, _target: libredfish::EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn lockdown_status(&self) -> Result<libredfish::Status, RedfishError> {
        // TODO: Return the real lockdown status based on the simulated host
        Err(RedfishError::NoContent)
    }

    async fn setup_serial_console(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn serial_console_status(&self) -> Result<libredfish::Status, RedfishError> {
        todo!()
    }

    async fn get_boot_options(&self) -> Result<libredfish::BootOptions, RedfishError> {
        todo!()
    }

    async fn get_boot_option(
        &self,
        _option_id: &str,
    ) -> Result<libredfish::model::BootOption, RedfishError> {
        todo!()
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

    async fn pending(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    async fn clear_pending(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn pcie_devices(&self) -> Result<Vec<libredfish::PCIeDevice>, RedfishError> {
        todo!()
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
        _id: &str,
    ) -> Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError> {
        Ok(serde_json::from_str(
            "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/BMC_Firmware\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"BMC image\",
            \"Id\": \"BMC_Firmware\",
            \"Name\": \"Software Inventory\",
            \"Updateable\": true,
            \"Version\": \"BF-23.07-3\",
            \"WriteProtected\": false
          }",
        )
        .unwrap())
    }

    async fn update_firmware(
        &self,
        _firmware: tokio::fs::File,
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
        ])
    }

    async fn get_system(&self) -> Result<libredfish::model::ComputerSystem, RedfishError> {
        Ok(libredfish::model::ComputerSystem {
            id: "Bluefield".to_string(),
            ..Default::default()
        })
    }

    async fn get_secure_boot(
        &self,
    ) -> Result<libredfish::model::secure_boot::SecureBoot, RedfishError> {
        todo!()
    }

    async fn disable_secure_boot(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    async fn get_network_device_functions(
        &self,
        _chassis_id: &str,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    async fn get_network_device_function(
        &self,
        _chassis_id: &str,
        _id: &str,
    ) -> Result<libredfish::model::network_device_function::NetworkDeviceFunction, RedfishError>
    {
        todo!()
    }

    async fn get_ports(&self, _chassis_id: &str) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    async fn get_port(
        &self,
        _chassis_id: &str,
        _id: &str,
    ) -> Result<libredfish::model::port::NetworkPort, RedfishError> {
        todo!()
    }

    async fn change_uefi_password(
        &self,
        _current_uefi_password: &str,
        _new_uefi_password: &str,
    ) -> Result<Option<String>, RedfishError> {
        Ok(None)
    }

    async fn change_boot_order(&self, _boot_array: Vec<String>) -> Result<(), RedfishError> {
        todo!()
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
                status_code: StatusCode::BAD_REQUEST,
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

    async fn get_service_root(
        &self,
    ) -> Result<libredfish::model::service_root::ServiceRoot, RedfishError> {
        Ok(ServiceRoot {
            vendor: Some("Nvidia".to_string()),
            ..Default::default()
        })
    }

    async fn get_systems(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn get_managers(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn get_manager(&self) -> Result<libredfish::model::Manager, RedfishError> {
        Ok(serde_json::from_str(
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
        .unwrap())
    }

    async fn bmc_reset_to_defaults(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn get_system_event_log(
        &self,
    ) -> Result<Vec<libredfish::model::sel::LogEntry>, RedfishError> {
        todo!()
    }

    async fn get_tasks(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn add_secure_boot_certificate(&self, _: &str) -> Result<Task, RedfishError> {
        todo!()
    }

    async fn enable_secure_boot(&self) -> Result<(), RedfishError> {
        todo!()
    }

    async fn change_username(&self, _old_name: &str, _new_name: &str) -> Result<(), RedfishError> {
        todo!()
    }
    async fn get_accounts(
        &self,
    ) -> Result<Vec<libredfish::model::account_service::ManagerAccount>, RedfishError> {
        todo!()
    }
    async fn set_forge_password_policy(&self) -> Result<(), RedfishError> {
        todo!()
    }
    async fn update_firmware_multipart(
        &self,
        _filename: &Path,
        _reboot: bool,
    ) -> Result<String, RedfishError> {
        // Simulate it taking a bit of time to upload
        time::sleep(Duration::from_secs(4)).await;
        Ok("0".to_string())
    }

    async fn get_job_state(&self, _job_id: &str) -> Result<JobState, RedfishError> {
        Ok(JobState::Unknown)
    }
}

#[async_trait]
impl RedfishClientPool for RedfishSim {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_client_with_custom_headers(host, port, &Vec::default(), auth, initialize)
            .await
    }
    async fn create_client_with_custom_headers(
        &self,
        host: &str,
        port: Option<u16>,
        _custom_headers: &[(String, String)],
        _auth: RedfishAuth,
        _initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        {
            self.state
                .clone()
                .lock()
                .unwrap()
                ._hosts
                .entry(host.to_string())
                .or_insert(RedfishSimHostState {
                    power: PowerState::On,
                });
        }
        Ok(Box::new(RedfishSimClient {
            state: self.state.clone(),
            _host: host.to_string(),
            _port: port,
        }))
    }

    async fn create_forge_admin_user(
        &self,
        client: &dyn Redfish,
        _machine_id: String,
    ) -> Result<(), RedfishClientCreationError> {
        let username = FORGE_DPU_BMC_USERNAME;
        let password = Credentials::generate_password();
        if let Err(e) = client
            .create_user(username, password.as_str(), RoleId::Administrator)
            .await
        {
            if e.to_string().to_uppercase().contains("ALREADY EXISTS") {
                return client
                    .change_password(username, password.as_str())
                    .await
                    .map_err(RedfishClientCreationError::RedfishError);
            }
            return Err(RedfishClientCreationError::RedfishError(e));
        }
        Ok(())
    }

    async fn uefi_setup(
        &self,
        _client: &dyn Redfish,
        _dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        Ok(None)
    }
}

/// redfish utility functions
///
/// host_power_control allows control over the power of the host
pub async fn host_power_control(
    redfish_client: &dyn Redfish,
    machine_snapshot: &MachineSnapshot,
    action: SystemPowerControl,
    ipmi_tool: Arc<dyn IPMITool>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> CarbideResult<()> {
    if machine_snapshot.bmc_vendor.is_lenovo() || machine_snapshot.bmc_vendor.is_supermicro() {
        // Lenovos prepend the users OS to the boot order once it is installed and this cleans up the mess
        // Supermicro will boot the users OS if we don't do this
        redfish_client
            .boot_once(libredfish::Boot::Pxe)
            .await
            .map_err(CarbideError::RedfishError)?;
    }

    let is_reboot = (action == SystemPowerControl::GracefulRestart)
        || (action == SystemPowerControl::ForceRestart);

    // vikings reboot their DPU's if redfish reset is used. \
    // ipmitool is verified to not cause it to reset, so we use it, hackily, here.
    if is_reboot && machine_snapshot.bmc_vendor.is_nvidia() {
        let bmc_ip = machine_snapshot
            .bmc_info
            .ip
            .as_ref()
            .ok_or_else(|| CarbideError::MissingArgument("MachineState.bmc_info.ip: {e}"))?;
        ipmi_tool
            .restart(&machine_snapshot.machine_id, bmc_ip.clone(), false)
            .await
            .map_err(|e: eyre::ErrReport| {
                CarbideError::GenericError(format!("Failed to restart machine: {}", e))
            })?;
    } else {
        redfish_client
            .power(action)
            .await
            .map_err(CarbideError::RedfishError)?;
    }

    Machine::update_reboot_requested_time(&machine_snapshot.machine_id, txn, action.into()).await?;
    Ok(())
}

/// set_host_uefi_password sets the UEFI password on the host and then power-cycles it.
/// It returns the job ID for the UEFI password change for vendors that require
/// generating a job to set the UEFI password.
pub async fn set_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .uefi_setup(redfish_client, false)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run uefi_setup call");
            CarbideError::GenericError(format!("Failed redfish uefi_setup subtask: {}", e))
        })
}

/// poll_redfish_job returns true if the job specified by job_id is at the state specified by job_state.
/// it will return an error if the job could not be found.
pub async fn poll_redfish_job(
    redfish_client: &dyn Redfish,
    job_id: String,
    expected_state: libredfish::JobState,
) -> CarbideResult<bool> {
    let job_state = redfish_client
        .get_job_state(&job_id)
        .await
        .map_err(CarbideError::RedfishError)?;

    if job_state != expected_state {
        tracing::trace!(
            "Current state for redfish job {:#?}: {:#?}",
            job_id,
            job_state
        );
        return Ok(false);
    }

    Ok(true)
}

pub async fn build_redfish_client_from_machine_snapshot(
    target: &MachineSnapshot,
    pool: &Arc<dyn RedfishClientPool>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
    let machine_id = &target.machine_id;

    let maybe_ip = target.bmc_info.ip.as_ref().ok_or_else(|| {
        RedfishClientCreationError::MissingArgument(format!(
            "IP address is missing for {}",
            machine_id
        ))
    })?;

    let ip = maybe_ip.parse().map_err(|_| {
        RedfishClientCreationError::InvalidArgument(
            format!("Invalid IP address for {}", machine_id),
            maybe_ip.into(),
        )
    })?;

    let machine_interface_target =
        MachineInterface::find_by_ip(txn, ip)
            .await?
            .ok_or_else(|| {
                RedfishClientCreationError::MissingArgument(format!(
                    "Machine Interface for IP address: {}",
                    ip
                ))
            })?;

    (*pool)
        .clone()
        .create_client(
            ip.to_string().as_str(),
            target.bmc_info.port,
            RedfishAuth::Key(CredentialKey::BmcCredentials {
                // TODO(ajf): Change this to Forge Admin user once site explorer
                // ensures it exist, credentials are done by mac address
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: machine_interface_target.mac_address,
                },
            }),
            true,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_power_state() {
        let sim = RedfishSim::default();
        let client = sim
            .create_client(
                "localhost",
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                true,
            )
            .await
            .unwrap();

        assert_eq!(PowerState::On, client.get_power_state().await.unwrap());
        client
            .power(libredfish::SystemPowerControl::ForceOff)
            .await
            .unwrap();

        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
        let client = sim
            .create_client(
                "localhost",
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                true,
            )
            .await
            .unwrap();
        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
    }
}
