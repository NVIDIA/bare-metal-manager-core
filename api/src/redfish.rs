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
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, CredentialType, Credentials};
use http::StatusCode;
use libredfish::{
    model::task::Task, standard::RedfishStandard, Endpoint, Redfish, RedfishError, RoleId,
};

const FORGE_DPU_BMC_USERNAME: &str = "forge_admin";

#[derive(thiserror::Error, Debug)]
pub enum RedfishClientCreationError {
    #[error("Failed to look up credentials {0}")]
    MissingCredentials(eyre::Report),
    #[error("Failed redfish request {0}")]
    RedfishError(RedfishError),
    #[error("Failed subtask to create redfish client  {0}")]
    SubtaskError(tokio::task::JoinError),
    #[error("Not implemeted")]
    NotImplemented,
}

/// Allows to create Redfish clients for a certain Redfish BMC endpoint
#[async_trait]
pub trait RedfishClientPool: Send + Sync + 'static {
    /// Creates a new Redfish client for a Machines BMC
    /// `host` is the IP address or hostname of the BMC
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_key: CredentialKey,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;

    async fn create_standard_client(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError>;

    async fn change_root_password_to_site_default(
        &self,
        standard_client: RedfishStandard,
    ) -> Result<(), RedfishClientCreationError>;

    async fn create_forge_admin_user(
        &self,
        client: Box<dyn Redfish>,
        machine_id: String,
    ) -> Result<(), RedfishClientCreationError>;

    async fn uefi_setup(&self, client: &dyn Redfish) -> Result<(), RedfishClientCreationError>;
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
}

#[async_trait]
impl<C: CredentialProvider + 'static> RedfishClientPool for RedfishClientPoolImpl<C> {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_key: CredentialKey,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let credentials = self
            .credential_provider
            .get_credentials(credential_key)
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: Some(username),
            password: Some(password),
        };

        // Creating the client performs a HTTP request to determine the BMC vendor
        let pool = self.pool.clone();
        pool.create_client(endpoint)
            .await
            .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn create_standard_client(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuRedfish {
                credential_type: CredentialType::HardwareDefault,
            })
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: Some(username),
            password: Some(password),
        };

        let standard_client = self
            .pool
            .create_standard_client(endpoint.clone())
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(standard_client)
    }

    async fn change_root_password_to_site_default(
        &self,
        standard_client: RedfishStandard,
    ) -> Result<(), RedfishClientCreationError> {
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            })
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        standard_client
            .change_password(username.as_str(), password.as_str())
            .await
            .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn create_forge_admin_user(
        &self,
        client: Box<dyn Redfish>,
        machine_id: String,
    ) -> Result<(), RedfishClientCreationError> {
        let username = FORGE_DPU_BMC_USERNAME;
        let password = Credentials::generate_password();
        self.credential_provider
            .set_credentials(
                CredentialKey::DpuRedfish {
                    credential_type: CredentialType::Machine { machine_id },
                },
                Credentials::UsernamePassword {
                    username: username.to_string(),
                    password: password.clone(),
                },
            )
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;
        if let Err(e) = client
            .create_user(username, password.as_str(), RoleId::Administrator)
            .await
        {
            if e.to_string().to_uppercase().contains("ALREADY EXISTS") {
                return client
                    .change_password(username, password.as_str())
                    .await
                    .map_err(RedfishClientCreationError::RedfishError);
            } else {
                return Err(RedfishClientCreationError::RedfishError(e));
            }
        }
        Ok(())
    }

    async fn uefi_setup(&self, client: &dyn Redfish) -> Result<(), RedfishClientCreationError> {
        // Replace DPU UEFI default password with site default
        // default password is taken from DpuUefi:factory_default key
        // site password is taken from DpuUefi:site_default key
        //
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuUefi {
                credential_type: CredentialType::HardwareDefault,
            })
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (_, current_password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuUefi {
                credential_type: CredentialType::SiteDefault,
            })
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (_, new_password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        client
            .change_uefi_password(current_password.as_str(), new_password.as_str())
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(())
    }
}

#[derive(Debug, Default)]
struct RedfishSimState {
    _hosts: HashMap<String, RedfishSimHostState>,
    users: HashMap<String, String>,
}

#[derive(Debug, Default)]
struct RedfishSimHostState {}

#[derive(Debug, Default)]
pub struct RedfishSim {
    state: Arc<Mutex<RedfishSimState>>,
}

#[derive(Debug)]
struct RedfishSimClient {
    _state: Arc<Mutex<RedfishSimState>>,
    _credential_key: CredentialKey,
    _host: String,
    _port: Option<u16>,
}

#[async_trait]
impl Redfish for RedfishSimClient {
    async fn get_power_state(&self) -> Result<libredfish::PowerState, RedfishError> {
        todo!()
    }

    async fn get_power_metrics(&self) -> Result<libredfish::model::power::Power, RedfishError> {
        todo!()
    }

    async fn power(&self, _action: libredfish::SystemPowerControl) -> Result<(), RedfishError> {
        // TODO: Only return Ok if the machine is actually known
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
        let mut state = self._state.lock().unwrap();
        if !state.users.contains_key(&user.to_string()) {
            return Err(RedfishError::UserNotFound(user.to_string()));
        }
        state.users.insert(user.to_string(), new.to_string());
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
        todo!()
    }

    async fn get_task(&self, _id: &str) -> Result<libredfish::model::task::Task, RedfishError> {
        todo!()
    }

    async fn get_chassis_all(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn get_chassis(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::chassis::Chassis, RedfishError> {
        todo!()
    }

    async fn get_chassis_network_adapters(
        &self,
        _chassis_id: &str,
    ) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn get_chassis_network_adapter(
        &self,
        _chassis_id: &str,
        _id: &str,
    ) -> Result<libredfish::model::chassis::NetworkAdapter, RedfishError> {
        todo!()
    }

    async fn get_manager_ethernet_interfaces(
        &self,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    async fn get_manager_ethernet_interface(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError> {
        todo!()
    }

    async fn get_system_ethernet_interfaces(
        &self,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    async fn get_system_ethernet_interface(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError> {
        todo!()
    }

    async fn get_software_inventories(&self) -> Result<Vec<std::string::String>, RedfishError> {
        Ok(vec![
            "BMC_Firmware".to_string(),
            "Bluefield_FW_ERoT".to_string(),
        ])
    }

    async fn get_system(&self) -> Result<libredfish::model::ComputerSystem, RedfishError> {
        todo!()
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
    ) -> Result<(), RedfishError> {
        Ok(())
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
        let mut state = self._state.lock().unwrap();
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
        todo!()
    }

    async fn get_systems(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn get_managers(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    async fn get_manager(&self) -> Result<libredfish::model::Manager, RedfishError> {
        todo!()
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
}

#[async_trait]
impl RedfishClientPool for RedfishSim {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_key: CredentialKey,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        Ok(Box::new(RedfishSimClient {
            _state: self.state.clone(),
            _credential_key: credential_key,
            _host: host.to_string(),
            _port: port,
        }))
    }

    async fn create_standard_client(
        &self,
        _host: &str,
        _port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    async fn change_root_password_to_site_default(
        &self,
        _standard_client: RedfishStandard,
    ) -> Result<(), RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    async fn create_forge_admin_user(
        &self,
        client: Box<dyn Redfish>,
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
            } else {
                return Err(RedfishClientCreationError::RedfishError(e));
            }
        }
        Ok(())
    }

    async fn uefi_setup(&self, _client: &dyn Redfish) -> Result<(), RedfishClientCreationError> {
        Ok(())
    }
}
