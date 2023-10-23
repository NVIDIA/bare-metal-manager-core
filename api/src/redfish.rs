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
use libredfish::{standard::RedfishStandard, Endpoint, Redfish, RedfishError, RoleId};
use uuid::Uuid;

use crate::db::bmc_metadata::UserRoles;

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

#[derive(PartialEq, Debug, Clone)]
pub enum RedfishCredentialType {
    HardwareDefault,
    SiteDefault,
    BmcMachine { bmc_machine_id: String },
    Machine { machine_id: String },
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
        credential_type: RedfishCredentialType,
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
        bmc_machine_id: Uuid,
    ) -> Result<(), RedfishClientCreationError>;
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
        credential_type: RedfishCredentialType,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let credentials_key: CredentialKey = match credential_type.clone() {
            RedfishCredentialType::HardwareDefault => CredentialKey::DpuRedfish {
                credential_type: CredentialType::HardwareDefault,
            },
            RedfishCredentialType::SiteDefault => CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            RedfishCredentialType::BmcMachine { bmc_machine_id } => CredentialKey::DpuRedfish {
                credential_type: CredentialType::BmcMachine { bmc_machine_id },
            },
            RedfishCredentialType::Machine { machine_id } => CredentialKey::Bmc {
                machine_id,
                user_role: UserRoles::Administrator.to_string(),
            },
        };
        let credentials = self
            .credential_provider
            .get_credentials(credentials_key)
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
        // The request is blocking - therefore we need to offload it into a ThreadPool
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || pool.create_client(endpoint))
            .await
            .map_err(RedfishClientCreationError::SubtaskError)?
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

        tokio::task::spawn_blocking(move || {
            standard_client.change_password(username.as_str(), password.as_str())
        })
        .await
        .map_err(RedfishClientCreationError::SubtaskError)?
        .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn create_forge_admin_user(
        &self,
        client: Box<dyn Redfish>,
        bmc_machine_id: Uuid,
    ) -> Result<(), RedfishClientCreationError> {
        let username = FORGE_DPU_BMC_USERNAME.clone();
        let password = Credentials::generate_password();
        self.credential_provider
            .set_credentials(
                CredentialKey::DpuRedfish {
                    credential_type: CredentialType::BmcMachine {
                        bmc_machine_id: bmc_machine_id.to_string(),
                    },
                },
                Credentials::UsernamePassword {
                    username: username.to_string(),
                    password: password.clone(),
                },
            )
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;
        tokio::task::spawn_blocking(move || {
            client.create_user(username, password.as_str(), RoleId::Administrator)
        })
        .await
        .map_err(RedfishClientCreationError::SubtaskError)?
        .map_err(RedfishClientCreationError::RedfishError)
    }
}

#[derive(Debug, Default)]
struct RedfishSimState {
    _hosts: HashMap<String, RedfishSimHostState>,
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
    _credentials_type: RedfishCredentialType,
    _host: String,
    _port: Option<u16>,
}

impl Redfish for RedfishSimClient {
    fn get_power_state(&self) -> Result<libredfish::PowerState, RedfishError> {
        todo!()
    }

    fn get_power_metrics(&self) -> Result<libredfish::model::power::Power, RedfishError> {
        todo!()
    }

    fn power(&self, _action: libredfish::SystemPowerControl) -> Result<(), RedfishError> {
        // TODO: Only return Ok if the machine is actually known
        Ok(())
    }

    fn bmc_reset(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    fn get_thermal_metrics(&self) -> Result<libredfish::model::thermal::Thermal, RedfishError> {
        todo!()
    }

    fn forge_setup(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    fn lockdown(&self, _target: libredfish::EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    fn lockdown_status(&self) -> Result<libredfish::Status, RedfishError> {
        // TODO: Return the real lockdown status based on the simulated host
        Err(RedfishError::NoContent)
    }

    fn setup_serial_console(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn serial_console_status(&self) -> Result<libredfish::Status, RedfishError> {
        todo!()
    }

    fn get_boot_options(&self) -> Result<libredfish::BootOptions, RedfishError> {
        todo!()
    }

    fn get_boot_option(
        &self,
        _option_id: &str,
    ) -> Result<libredfish::model::BootOption, RedfishError> {
        todo!()
    }

    fn boot_once(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
        Ok(())
    }

    fn boot_first(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
        todo!()
    }

    fn clear_tpm(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn bios(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    fn pending(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    fn clear_pending(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn pcie_devices(&self) -> Result<Vec<libredfish::PCIeDevice>, RedfishError> {
        todo!()
    }

    fn change_password(&self, _user: &str, _new: &str) -> Result<(), RedfishError> {
        todo!()
    }

    fn get_firmware(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError> {
        todo!()
    }

    fn update_firmware(
        &self,
        _firmware: std::fs::File,
    ) -> Result<libredfish::model::task::Task, RedfishError> {
        todo!()
    }

    fn get_task(&self, _id: &str) -> Result<libredfish::model::task::Task, RedfishError> {
        todo!()
    }

    fn get_chassis(&self, _id: &str) -> Result<libredfish::model::chassis::Chassis, RedfishError> {
        todo!()
    }

    fn get_ethernet_interfaces(&self) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    fn get_ethernet_interface(
        &self,
        _id: &str,
    ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError> {
        todo!()
    }

    fn get_software_inventories(&self) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    fn get_system(&self) -> Result<libredfish::model::ComputerSystem, RedfishError> {
        todo!()
    }

    fn get_secure_boot(&self) -> Result<libredfish::model::secure_boot::SecureBoot, RedfishError> {
        todo!()
    }

    fn disable_secure_boot(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    fn get_network_device_functions(
        &self,
        _chassis_id: &str,
    ) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    fn get_network_device_function(
        &self,
        _chassis_id: &str,
        _id: &str,
    ) -> Result<libredfish::model::network_device_function::NetworkDeviceFunction, RedfishError>
    {
        todo!()
    }

    fn get_ports(&self, _chassis_id: &str) -> Result<Vec<std::string::String>, RedfishError> {
        todo!()
    }

    fn get_port(
        &self,
        _chassis_id: &str,
        _id: &str,
    ) -> Result<libredfish::model::port::NetworkPort, RedfishError> {
        todo!()
    }

    fn change_uefi_password(
        &self,
        _current_uefi_password: &str,
        _new_uefi_password: &str,
    ) -> Result<(), RedfishError> {
        todo!()
    }

    fn change_boot_order(&self, _boot_array: Vec<String>) -> Result<(), RedfishError> {
        todo!()
    }

    fn set_internal_cpu_model(
        &self,
        _model: libredfish::model::oem::nvidia::InternalCPUModel,
    ) -> Result<(), RedfishError> {
        todo!()
    }

    fn set_host_privilege_level(
        &self,
        _level: libredfish::model::oem::nvidia::HostPrivilegeLevel,
    ) -> Result<(), RedfishError> {
        todo!()
    }

    fn create_user(
        &self,
        _username: &str,
        _password: &str,
        _role_id: libredfish::RoleId,
    ) -> Result<(), RedfishError> {
        todo!()
    }

    fn get_service_root(
        &self,
    ) -> Result<libredfish::model::service_root::ServiceRoot, RedfishError> {
        todo!()
    }

    fn get_systems(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    fn get_managers(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    fn get_manager(&self) -> Result<libredfish::model::Manager, RedfishError> {
        todo!()
    }

    fn bmc_reset_to_defaults(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn get_system_event_log(&self) -> Result<Vec<libredfish::model::sel::LogEntry>, RedfishError> {
        todo!()
    }

    fn get_chassis_all(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }

    fn get_tasks(&self) -> Result<Vec<String>, RedfishError> {
        todo!()
    }
}

#[async_trait]
impl RedfishClientPool for RedfishSim {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_type: RedfishCredentialType,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        Ok(Box::new(RedfishSimClient {
            _state: self.state.clone(),
            _credentials_type: credential_type,
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
        _client: Box<dyn Redfish>,
        _bmc_machine_id: Uuid,
    ) -> Result<(), RedfishClientCreationError> {
        Ok(())
    }
}
