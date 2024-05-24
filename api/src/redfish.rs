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
    model::{
        service_root::{RedfishVendor, ServiceRoot},
        task::Task,
    },
    standard::RedfishStandard,
    Chassis, Endpoint, PowerState, Redfish, RedfishError, RoleId,
};

const FORGE_DPU_BMC_USERNAME: &str = "forge_admin";
const AMI_USERNAME: &str = "admin";

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
    #[error(transparent)]
    IdentifyError(#[from] crate::site_explorer::IdentifyError),
}

/// Allows to create Redfish clients for a certain Redfish BMC endpoint
///
/// TODO: This is a mess. Maybe replace with:
///  get_credentials(CredentialKey)
///  create_client(host, port, Enum(CredentialKey or (user,pass)),  should_do_initial_fetch:bool)
///
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

    async fn create_factory_host_client(
        &self,
        host: &str,
        port: Option<u16>,
        vendor: bmc_vendor::BMCVendor,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError>;

    async fn create_factory_dpu_client(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError>;

    async fn create_standard_client(
        &self,
        host: &str,
        port: Option<u16>,
        key: CredentialKey,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError>;

    fn create_anonymous_client(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError>;

    fn create_direct_client(
        &self,
        host: &str,
        port: Option<u16>,
        username: &str,
        password: &str,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError>;

    async fn get_factory_root_credentials(
        &self,
        vendor: bmc_vendor::BMCVendor,
    ) -> eyre::Result<(String, String)>;

    async fn get_site_default_credentials(&self) -> eyre::Result<(String, String)>;

    async fn change_root_password_to_site_default(
        &self,
        client: Box<dyn Redfish>,
        new_credential_key: CredentialKey,
    ) -> Result<(), RedfishClientCreationError>;

    async fn create_forge_admin_user(
        &self,
        client: Box<dyn Redfish>,
        machine_id: String,
    ) -> Result<(), RedfishClientCreationError>;

    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
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
        credential_key: CredentialKey,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let credentials = self
            .credential_provider
            .get_credentials(credential_key.clone())
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        // AMI (Viking) host uses 'admin' as username while all other hardware use 'root' as
        // username. This method will impact only for site_default HostCredentials.
        let username = if let CredentialKey::HostRedfish {
            credential_type: CredentialType::SiteDefault,
        } = credential_key
        {
            let username = match self
                .get_user_for_ami_vendor(host, port, password.clone())
                .await?
            {
                None => username,
                Some(u) => u.to_string(),
            };
            tracing::info!("Using {username} user for host: {host}");
            username
        } else {
            username
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

    async fn create_factory_host_client(
        &self,
        host: &str,
        port: Option<u16>,
        vendor: bmc_vendor::BMCVendor,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        let key = forge_secrets::credentials::CredentialKey::HostRedfish {
            credential_type: CredentialType::HostHardwareDefault { vendor },
        };
        self.create_standard_client(host, port, key).await
    }

    async fn create_factory_dpu_client(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        let key = CredentialKey::DpuRedfish {
            credential_type: CredentialType::DpuHardwareDefault,
        };
        self.create_standard_client(host, port, key).await
    }

    /// A "standard" client is a client that doesn't make any HTTP calls yet
    async fn create_standard_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_key: CredentialKey,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
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

        let standard_client = self
            .pool
            .create_standard_client(endpoint.clone())
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(standard_client)
    }

    fn create_direct_client(
        &self,
        host: &str,
        port: Option<u16>,
        username: &str,
        password: &str,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: Some(username.to_string()),
            password: Some(password.to_string()),
        };
        self.pool
            .create_standard_client(endpoint.clone())
            .map_err(RedfishClientCreationError::RedfishError)
    }

    fn create_anonymous_client(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: None,
            password: None,
        };

        self.pool
            .create_standard_client(endpoint.clone())
            .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn get_factory_root_credentials(
        &self,
        vendor: bmc_vendor::BMCVendor,
    ) -> eyre::Result<(String, String)> {
        let key = forge_secrets::credentials::CredentialKey::HostRedfish {
            credential_type: CredentialType::HostHardwareDefault { vendor },
        };
        let credentials = self.credential_provider.get_credentials(key).await?;
        let creds_pair = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };
        Ok(creds_pair)
    }

    async fn get_site_default_credentials(&self) -> eyre::Result<(String, String)> {
        let key = CredentialKey::HostRedfish {
            credential_type: CredentialType::SiteDefault,
        };
        let credentials = self.credential_provider.get_credentials(key).await?;
        let creds_pair = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };
        Ok(creds_pair)
    }

    async fn change_root_password_to_site_default(
        &self,
        client: Box<dyn Redfish>,
        new_credential_key: CredentialKey,
    ) -> Result<(), RedfishClientCreationError> {
        let credentials = self
            .credential_provider
            .get_credentials(new_credential_key.clone())
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let username = if let CredentialKey::HostRedfish { .. } = new_credential_key {
            let service_root = client
                .get_service_root()
                .await
                .map_err(RedfishClientCreationError::RedfishError)?;

            if matches!(service_root.vendor(), Some(RedfishVendor::AMI)) {
                AMI_USERNAME.to_string()
            } else {
                username
            }
        } else {
            username
        };

        tracing::info!("Using {username} user while updating root password to site default.");

        client
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
            }
            return Err(RedfishClientCreationError::RedfishError(e));
        }
        Ok(())
    }

    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
    ) -> Result<(), RedfishClientCreationError> {
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
            return Ok(());
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

            let credentials = self
                .credential_provider
                .get_credentials(CredentialKey::DpuUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await
                .map_err(RedfishClientCreationError::MissingCredentials)?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        } else {
            // the current password is always an empty string for the host uefi
            let credentials = self
                .credential_provider
                .get_credentials(CredentialKey::HostUefi {
                    credential_type: CredentialType::SiteDefault,
                })
                .await
                .map_err(RedfishClientCreationError::MissingCredentials)?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        }

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
    _credential_key: CredentialKey,
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
        _firmware: &std::path::Path,
        _reboot: bool,
    ) -> Result<String, RedfishError> {
        todo!();
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
            _credential_key: credential_key,
            _host: host.to_string(),
            _port: port,
        }))
    }

    async fn create_factory_host_client(
        &self,
        _host: &str,
        _port: Option<u16>,
        _vendor: bmc_vendor::BMCVendor,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    async fn create_factory_dpu_client(
        &self,
        _host: &str,
        _port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    async fn create_standard_client(
        &self,
        _host: &str,
        _port: Option<u16>,
        _key: CredentialKey,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    fn create_anonymous_client(
        &self,
        _host: &str,
        _port: Option<u16>,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    fn create_direct_client(
        &self,
        _host: &str,
        _port: Option<u16>,
        _username: &str,
        _password: &str,
    ) -> Result<Box<RedfishStandard>, RedfishClientCreationError> {
        Err(RedfishClientCreationError::NotImplemented)
    }

    async fn get_factory_root_credentials(
        &self,
        _vendor: bmc_vendor::BMCVendor,
    ) -> eyre::Result<(String, String)> {
        Err(eyre::eyre!("Not implemented"))
    }

    async fn get_site_default_credentials(&self) -> eyre::Result<(String, String)> {
        Err(eyre::eyre!("Not implemented"))
    }

    async fn change_root_password_to_site_default(
        &self,
        _client: Box<dyn Redfish>,
        _new_credential_key: CredentialKey,
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
            }
            return Err(RedfishClientCreationError::RedfishError(e));
        }
        Ok(())
    }

    async fn uefi_setup(
        &self,
        _client: &dyn Redfish,
        _dpu: bool,
    ) -> Result<(), RedfishClientCreationError> {
        Ok(())
    }
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
                CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                },
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
                CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                },
            )
            .await
            .unwrap();
        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
    }
}
