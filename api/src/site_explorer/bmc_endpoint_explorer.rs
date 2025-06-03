/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::SocketAddr;
use std::sync::Arc;

use forge_secrets::credentials::{CredentialProvider, Credentials};
use forge_ssh::ssh::SshConfig;
use libredfish::model::oem::nvidia_dpu::NicMode;
use libredfish::model::service_root::RedfishVendor;
use mac_address::MacAddress;
use tokio::time::{Duration, sleep};

use super::credentials::{CredentialClient, get_bmc_root_credential_key};
use super::metrics::SiteExplorationMetrics;
use super::redfish::RedfishClient;
use crate::db::expected_machine::ExpectedMachine;
use crate::ipmitool::IPMITool;
use crate::model::machine::MachineInterfaceSnapshot;
use crate::{
    model::site_explorer::{EndpointExplorationError, EndpointExplorationReport},
    redfish::RedfishClientPool,
    site_explorer::EndpointExplorer,
};

/// An `EndpointExplorer` which uses redfish APIs to query the endpoint
pub struct BmcEndpointExplorer {
    redfish_client: RedfishClient,
    ipmi_tool: Arc<dyn IPMITool>,
    credential_client: CredentialClient,
}

impl BmcEndpointExplorer {
    pub fn new(
        redfish_client_pool: Arc<dyn RedfishClientPool>,
        ipmi_tool: Arc<dyn IPMITool>,
        credential_provider: Arc<dyn CredentialProvider>,
    ) -> Self {
        Self {
            redfish_client: RedfishClient::new(redfish_client_pool),
            ipmi_tool,
            credential_client: CredentialClient::new(credential_provider),
        }
    }

    pub async fn get_sitewide_bmc_password(&self) -> Result<String, EndpointExplorationError> {
        let credentials = self
            .credential_client
            .get_sitewide_bmc_root_credentials()
            .await?;

        let (_, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        Ok(password)
    }

    pub async fn get_default_hardware_dpu_bmc_root_credentials(
        &self,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.credential_client
            .get_default_hardware_dpu_bmc_root_credentials()
            .await
    }

    pub async fn get_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.credential_client
            .get_bmc_root_credentials(bmc_mac_address)
            .await
    }

    pub async fn set_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        self.credential_client
            .set_bmc_root_credentials(bmc_mac_address, credentials)
            .await
    }

    pub async fn probe_redfish_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<RedfishVendor, EndpointExplorationError> {
        self.redfish_client
            .probe_redfish_endpoint(bmc_ip_address)
            .await
    }

    pub async fn set_bmc_root_password(
        &self,
        bmc_ip_address: SocketAddr,
        vendor: RedfishVendor,
        current_bmc_credentials: Credentials,
        new_password: String,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.redfish_client
            .set_bmc_root_password(
                bmc_ip_address,
                vendor,
                current_bmc_credentials.clone(),
                new_password.clone(),
            )
            .await?;

        let (user, _) = match current_bmc_credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        Ok(Credentials::UsernamePassword {
            username: user,
            password: new_password,
        })
    }

    pub async fn generate_exploration_report(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .generate_exploration_report(bmc_ip_address, username, password)
            .await
    }

    // Handle machines that still have their bmc root password set to the factory default.
    // (1) For hosts, the factory default must exist in the expected machines table (expected_machine). Otherwise, return an error.
    // (2) For DPUs, try the hardware default root credentials.
    // At this point, we dont know if the machine is a host or dpu. So, try both (1) and (2).
    // If neither credentials work, return an error.
    // If we can log in using the factory credentials:
    // (1) use Redfish to set the machine's bmc root password to be the sitewide bmc root password.
    // (2) update the BMC specific root password path in vault
    pub async fn set_sitewide_bmc_root_password(
        &self,
        bmc_ip_address: SocketAddr,
        bmc_mac_address: MacAddress,
        vendor: RedfishVendor,
        expected_machine: Option<ExpectedMachine>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let current_bmc_credentials;

        tracing::info!(%bmc_ip_address, %bmc_mac_address, %vendor, "attempting to set the administrative credentials to the site password");

        if let Some(expected_machine_credentials) = expected_machine {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, "Found an expected machine for this BMC mac address");
            current_bmc_credentials = Credentials::UsernamePassword {
                username: expected_machine_credentials.bmc_username,
                password: expected_machine_credentials.bmc_password,
            };
        } else {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, %vendor, "No expected machine found, could be a BlueField");
            // We dont know if this machine is a DPU at this point
            // Check the vendor to see if it could be a DPU (the DPU's vendor is NVIDIA)
            match vendor {
                RedfishVendor::NvidiaDpu => {
                    // This machine is a DPU.
                    // Try the DPU hardware default password to handle the DPU case
                    // This password will not work for a Viking host and we will return an error
                    current_bmc_credentials =
                        self.get_default_hardware_dpu_bmc_root_credentials().await?;
                }
                _ => {
                    return Err(EndpointExplorationError::MissingCredentials {
                        key: "expected_machine".to_owned(),
                        cause: format!(
                            "The expected machine credentials do not exist for {} machine {}/{} ",
                            vendor, bmc_ip_address, bmc_mac_address
                        ),
                    });
                }
            }
        }

        let sitewide_bmc_password = self.get_sitewide_bmc_password().await?;

        // use redfish to set the machine's BMC root password to
        // match Forge's sitewide BMC root password (from the factory default).
        // return an error if we cannot log into the machine's BMC using current credentials
        let bmc_credentials = self
            .set_bmc_root_password(
                bmc_ip_address,
                vendor,
                current_bmc_credentials,
                sitewide_bmc_password,
            )
            .await?;

        tracing::info!(
            %bmc_ip_address, %bmc_mac_address, %vendor,
            "Site explorer successfully updated the root password for {bmc_mac_address} to the Forge sitewide BMC root password"
        );

        // set the BMC root credentials in vault for this machine
        self.set_bmc_root_credentials(bmc_mac_address, bmc_credentials.clone())
            .await?;

        self.generate_exploration_report(bmc_ip_address, bmc_credentials)
            .await
    }

    pub async fn redfish_reset_bmc(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .reset_bmc(bmc_ip_address, username, password)
            .await
    }

    pub async fn redfish_power_control(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .power(bmc_ip_address, username, password, action)
            .await
    }

    pub async fn forge_setup(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .forge_setup(bmc_ip_address, username, password, boot_interface_mac)
            .await
    }

    pub async fn set_nic_mode(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        mode: NicMode,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .set_nic_mode(bmc_ip_address, username, password, mode)
            .await
    }

    async fn is_viking(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<bool, EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .is_viking(bmc_ip_address, username, password)
            .await
    }

    pub async fn clear_nvram(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.redfish_client
            .clear_nvram(bmc_ip_address, username, password)
            .await
    }

    async fn is_rshim_enabled(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        ssh_config: Option<SshConfig>,
    ) -> Result<bool, EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };
        let rshim_status =
            forge_ssh::ssh::is_rshim_enabled(bmc_ip_address, username, password, ssh_config)
                .await
                .map_err(|err| EndpointExplorationError::Other {
                    details: format!("failed query RSHIM status on on {bmc_ip_address}: {err}"),
                })?;

        Ok(rshim_status)
    }

    async fn enable_rshim(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        ssh_config: Option<SshConfig>,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        forge_ssh::ssh::enable_rshim(bmc_ip_address, username, password, ssh_config)
            .await
            .map_err(|err| EndpointExplorationError::Other {
                details: format!("failed enable RSHIM on {bmc_ip_address}: {err}"),
            })
    }

    async fn check_and_enable_rshim(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        ssh_config: Option<SshConfig>,
    ) -> Result<(), EndpointExplorationError> {
        let mut i = 0;
        while i < 3 {
            if !self
                .is_rshim_enabled(bmc_ip_address, credentials.clone(), ssh_config.clone())
                .await?
            {
                tracing::warn!("RSHIM is not enabled on {bmc_ip_address}");
                self.enable_rshim(bmc_ip_address, credentials.clone(), ssh_config.clone())
                    .await?;

                // Sleep for 10 seconds before checking again
                sleep(Duration::from_secs(10)).await;
                i += 1;
            } else {
                return Ok(());
            }
        }

        Err(EndpointExplorationError::Other {
            details: format!("could not enable RSHIM on {bmc_ip_address}"),
        })
    }

    async fn copy_bfb_to_dpu_rshim(
        &self,
        bmc_ip_address: SocketAddr,
        bfb_path: String,
        credentials: Credentials,
        ssh_config: Option<SshConfig>,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.check_and_enable_rshim(bmc_ip_address, credentials, ssh_config.clone())
            .await?;

        forge_ssh::ssh::copy_bfb_to_bmc_rshim(
            bmc_ip_address,
            username,
            password,
            ssh_config,
            bfb_path.clone(),
        )
        .await
        .map_err(|err| EndpointExplorationError::Other {
            details: format!(
                "failed to copy BFB from {bfb_path} to BMC RSHIM on {bmc_ip_address}: {err}"
            ),
        })
    }
}

#[async_trait::async_trait]
impl EndpointExplorer for BmcEndpointExplorer {
    async fn check_preconditions(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        self.credential_client.check_preconditions(metrics).await
    }

    async fn have_credentials(&self, interface: &MachineInterfaceSnapshot) -> bool {
        self.get_bmc_root_credentials(interface.mac_address)
            .await
            .is_ok()
    }

    // 1) Authenticate and set the BMC root account credentials
    // 2) Authenticate and set the BMC forge-admin account credentials (TODO)
    async fn explore_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        expected_machine: Option<ExpectedMachine>,
        last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        // If the site explorer was previously unable to login to the root BMC account using
        // the expected credentials, wait for an operator to manually intervene.
        // This will avoid locking us out of BMCs.
        if let Some(report) = last_report {
            if report.cannot_login() {
                return Err(EndpointExplorationError::AvoidLockout);
            }
        }

        let bmc_mac_address = interface.mac_address;
        let vendor = self.probe_redfish_endpoint(bmc_ip_address).await?;
        tracing::trace!(%bmc_ip_address, "Is a {vendor} BMC that supports Redfish");

        // Authenticate and set the BMC root account credentials

        // Case 1: Vault contains a path at "bmc/{bmc_mac_address}/root"
        // This machine has its BMC set to the Forge sitewide BMC root password.
        // Create the redfish client and generate the report.
        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => Ok(self
                .generate_exploration_report(bmc_ip_address, credentials)
                .await?),

            Err(_) => {
                tracing::info!(
                    %bmc_ip_address,
                    "Site explorer could not find an entry in vault at 'bmc/{}/root' - this is expected if the BMC has never been seen before.",
                    bmc_mac_address,
                );

                // The machine's BMC root password has not been set to the Forge Sitewide BMC root password
                // 1) Try to login to the machine's BMC root account
                // 2) Set the machine's BMC root password to the Forge Sitewide BMC root password
                // 3) Set the password policy for the machine's BMC
                // 4) Generate the report
                self.set_sitewide_bmc_root_password(
                    bmc_ip_address,
                    bmc_mac_address,
                    vendor,
                    expected_machine,
                )
                .await
            }
        }
    }

    async fn redfish_reset_bmc(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.redfish_reset_bmc(bmc_ip_address, credentials).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "Site explorer does not support resetting the BMCs that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn ipmitool_reset_bmc(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;
        let credential_key = get_bmc_root_credential_key(bmc_mac_address);
        self.ipmi_tool
            .bmc_cold_reset(bmc_ip_address.ip(), credential_key)
            .await
            .map_err(|err| EndpointExplorationError::Other {
                details: format!("ipmi_tool failed against {bmc_ip_address} failed: {err}"),
            })
    }

    async fn redfish_power_control(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.redfish_power_control(bmc_ip_address, credentials, action)
                    .await
            }
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "Site explorer does not support rebooting the endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn forge_setup(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.forge_setup(bmc_ip_address, credentials, boot_interface_mac)
                    .await
            }
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support starting forge_setup for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn set_nic_mode(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        mode: NicMode,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.set_nic_mode(bmc_ip_address, credentials, mode).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support set_nic_mode for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn is_viking(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<bool, EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.is_viking(bmc_ip_address, credentials).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support set_nic_mode for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn clear_nvram(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.clear_nvram(bmc_ip_address, credentials).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support set_nic_mode for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn copy_bfb_to_dpu_rshim(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        bfb_path: String,
        ssh_config: Option<SshConfig>,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.copy_bfb_to_dpu_rshim(bmc_ip_address, bfb_path, credentials, ssh_config)
                    .await
            }
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support set_nic_mode for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }
}
