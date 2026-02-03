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
use std::sync::atomic::{AtomicBool, Ordering};

use forge_secrets::credentials::{CredentialProvider, Credentials};
use libredfish::model::oem::nvidia_dpu::NicMode;
use libredfish::model::service_root::RedfishVendor;
use mac_address::MacAddress;
use model::expected_machine::ExpectedMachine;
use model::expected_power_shelf::ExpectedPowerShelf;
use model::expected_switch::ExpectedSwitch;
use model::machine::MachineInterfaceSnapshot;
use model::site_explorer::{EndpointExplorationError, EndpointExplorationReport, LockdownStatus};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

use super::credentials::{CredentialClient, get_bmc_root_credential_key};
use super::metrics::SiteExplorationMetrics;
use super::redfish::RedfishClient;
use crate::ipmitool::IPMITool;
use crate::redfish::RedfishClientPool;
use crate::site_explorer::EndpointExplorer;

const UNIFIED_PREINGESTION_BFB_PATH: &str =
    "/forge-boot-artifacts/blobs/internal/aarch64/preingestion_unified_update.bfb";
const PREINGESTION_BFB_PATH: &str = "/forge-boot-artifacts/blobs/internal/aarch64/preingestion.bfb";

/// An `EndpointExplorer` which uses redfish APIs to query the endpoint
pub struct BmcEndpointExplorer {
    redfish_client: RedfishClient,
    ipmi_tool: Arc<dyn IPMITool>,
    credential_client: CredentialClient,
    mutex: Arc<Mutex<()>>,
    rotate_switch_nvos_credentials: Arc<AtomicBool>,
}

impl BmcEndpointExplorer {
    pub fn new(
        redfish_client_pool: Arc<dyn RedfishClientPool>,
        ipmi_tool: Arc<dyn IPMITool>,
        credential_provider: Arc<dyn CredentialProvider>,
        rotate_switch_nvos_credentials: Arc<AtomicBool>,
    ) -> Self {
        Self {
            redfish_client: RedfishClient::new(redfish_client_pool),
            ipmi_tool,
            credential_client: CredentialClient::new(credential_provider),
            mutex: Arc::new(Mutex::new(())),
            rotate_switch_nvos_credentials,
        }
    }

    pub async fn get_sitewide_bmc_password(&self) -> Result<String, EndpointExplorationError> {
        let credentials = self
            .credential_client
            .get_sitewide_bmc_root_credentials()
            .await?;

        let (_, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        Ok(password)
    }

    pub fn get_default_hardware_dpu_bmc_root_credentials(&self) -> Credentials {
        self.credential_client
            .get_default_hardware_dpu_bmc_root_credentials()
    }

    pub async fn get_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.credential_client
            .get_bmc_root_credentials(bmc_mac_address)
            .await
    }

    pub async fn get_switch_nvos_admin_credentials(
        &self,
        bmc_mac_address: MacAddress,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.credential_client
            .get_switch_nvos_admin_credentials(bmc_mac_address)
            .await
    }

    pub async fn set_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
        credentials: &Credentials,
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
        skip_password_change: bool,
    ) -> Result<Credentials, EndpointExplorationError> {
        if !skip_password_change {
            self.redfish_client
                .set_bmc_root_password(
                    bmc_ip_address,
                    vendor,
                    current_bmc_credentials.clone(),
                    new_password.clone(),
                )
                .await?;
        }

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
        boot_interface_mac: Option<MacAddress>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        self.redfish_client
            .generate_exploration_report(bmc_ip_address, credentials, boot_interface_mac)
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
        expected_machine: Option<&ExpectedMachine>,
        expected_power_shelf: Option<&ExpectedPowerShelf>,
        expected_switch: Option<&ExpectedSwitch>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let current_bmc_credentials;
        let mut skip_password_change = false;

        tracing::info!(%bmc_ip_address, %bmc_mac_address, %vendor, "attempting to set the administrative credentials to the site password");
        let mut sitewide_bmc_password = self.get_sitewide_bmc_password().await?;

        if let Some(expected_machine_credentials) = expected_machine {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, "Found an expected machine for this BMC mac address");
            current_bmc_credentials = Credentials::UsernamePassword {
                username: expected_machine_credentials.data.bmc_username.clone(),
                password: expected_machine_credentials.data.bmc_password.clone(),
            };
        } else if let Some(expected_power_shelf_credentials) = expected_power_shelf {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, "Found an expected power shelf for this BMC mac address");
            sitewide_bmc_password = expected_power_shelf_credentials.bmc_password.clone();
            // Lite-On power shelf BMCs do not support the Redfish service root endpoint
            // so we skip the password change
            skip_password_change = true;
            current_bmc_credentials = Credentials::UsernamePassword {
                username: expected_power_shelf_credentials.bmc_username.clone(),
                password: expected_power_shelf_credentials.bmc_password.clone(),
            };
        } else if let Some(expected_switch_credentials) = expected_switch {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, "Found an expected switch for this BMC mac address");
            current_bmc_credentials = Credentials::UsernamePassword {
                username: expected_switch_credentials.bmc_username.clone(),
                password: expected_switch_credentials.bmc_password.clone(),
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
                    current_bmc_credentials = self.get_default_hardware_dpu_bmc_root_credentials();
                }
                _ => {
                    return Err(EndpointExplorationError::MissingCredentials {
                        key: "expected_machine".to_owned(),
                        cause: format!(
                            "The expected machine credentials do not exist for {vendor} machine {bmc_ip_address}/{bmc_mac_address} "
                        ),
                    });
                }
            }
        }

        // use redfish to set the machine's BMC root password to
        // match Forge's sitewide BMC root password (from the factory default).
        // return an error if we cannot log into the machine's BMC using current credentials
        let bmc_credentials = self
            .set_bmc_root_password(
                bmc_ip_address,
                vendor,
                current_bmc_credentials,
                sitewide_bmc_password,
                skip_password_change,
            )
            .await?;

        tracing::info!(
            %bmc_ip_address, %bmc_mac_address, %vendor,
            "Site explorer successfully updated the root password for {bmc_mac_address} to the Forge sitewide BMC root password"
        );

        // set the BMC root credentials in vault for this machine
        self.set_bmc_root_credentials(bmc_mac_address, &bmc_credentials)
            .await?;

        self.generate_exploration_report(bmc_ip_address, bmc_credentials, None)
            .await
    }

    // Handle switch NVOS admin credentials setup
    // Store NVOS admin credentials in vault for the switch if they exist in expected_switch
    pub async fn set_sitewide_switch_nvos_admin_credentials(
        &self,
        bmc_mac_address: MacAddress,
        expected_switch: &ExpectedSwitch,
    ) -> Result<(), EndpointExplorationError> {
        if let (Some(nvos_username), Some(nvos_password)) = (
            expected_switch.nvos_username.as_ref(),
            expected_switch.nvos_password.as_ref(),
        ) {
            tracing::info!(
                %bmc_mac_address,
                "Storing NVOS admin credentials in vault for switch {bmc_mac_address}"
            );
            self.credential_client
                .set_bmc_nvos_admin_credentials(
                    bmc_mac_address,
                    &Credentials::UsernamePassword {
                        username: nvos_username.clone(),
                        password: nvos_password.clone(),
                    },
                )
                .await?;
        }
        Ok(())
    }

    pub async fn redfish_reset_bmc(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .reset_bmc(bmc_ip_address, credentials)
            .await
    }

    pub async fn redfish_power_control(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .power(bmc_ip_address, credentials, action)
            .await
    }

    pub async fn machine_setup(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .machine_setup(bmc_ip_address, credentials, boot_interface_mac)
            .await
    }

    pub async fn set_boot_order_dpu_first(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        boot_interface_mac: &str,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .set_boot_order_dpu_first(bmc_ip_address, credentials, boot_interface_mac)
            .await
    }

    pub async fn set_nic_mode(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        mode: NicMode,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .set_nic_mode(bmc_ip_address, credentials, mode)
            .await
    }

    async fn is_viking(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<bool, EndpointExplorationError> {
        self.redfish_client
            .is_viking(bmc_ip_address, credentials)
            .await
    }

    pub async fn clear_nvram(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .clear_nvram(bmc_ip_address, credentials)
            .await
    }

    pub async fn disable_secure_boot(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .disable_secure_boot(bmc_ip_address, credentials)
            .await
    }

    pub async fn lockdown(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        action: libredfish::EnabledDisabled,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .lockdown(bmc_ip_address, credentials, action)
            .await
    }

    pub async fn lockdown_status(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<LockdownStatus, EndpointExplorationError> {
        self.redfish_client
            .lockdown_status(bmc_ip_address, credentials)
            .await
    }

    pub async fn enable_infinite_boot(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .enable_infinite_boot(bmc_ip_address, credentials)
            .await
    }

    pub async fn is_infinite_boot_enabled(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Option<bool>, EndpointExplorationError> {
        self.redfish_client
            .is_infinite_boot_enabled(bmc_ip_address, credentials)
            .await
    }

    async fn is_rshim_enabled(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<bool, EndpointExplorationError> {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };
        let rshim_status = forge_ssh::ssh::is_rshim_enabled(bmc_ip_address, username, password)
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
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        forge_ssh::ssh::enable_rshim(bmc_ip_address, username, password)
            .await
            .map_err(|err| EndpointExplorationError::Other {
                details: format!("failed enable RSHIM on {bmc_ip_address}: {err}"),
            })
    }

    async fn check_and_enable_rshim(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: &Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let mut i = 0;
        while i < 3 {
            if !self
                .is_rshim_enabled(bmc_ip_address, credentials.clone())
                .await?
            {
                tracing::warn!("RSHIM is not enabled on {bmc_ip_address}");
                self.enable_rshim(bmc_ip_address, credentials.clone())
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

    async fn create_unified_preingestion_bfb(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), EndpointExplorationError> {
        let mutex_clone = Arc::clone(&self.mutex);
        let _lock = mutex_clone.lock().await;

        if fs::metadata(UNIFIED_PREINGESTION_BFB_PATH).await.is_err() {
            tracing::info!("Writing {UNIFIED_PREINGESTION_BFB_PATH}");
            let bf_cfg_contents = format!(
                "BMC_USER=\"{username}\"\nBMC_PASSWORD=\"{password}\"\nBMC_REBOOT=\"yes\"\nCEC_REBOOT=\"yes\"\n"
            );

            let mut preingestion_bfb = File::open(PREINGESTION_BFB_PATH).await.map_err(|err| {
                EndpointExplorationError::Other {
                    details: format!("failed to open {PREINGESTION_BFB_PATH}: {err}"),
                }
            })?;

            let mut unified_bfb =
                File::create(UNIFIED_PREINGESTION_BFB_PATH)
                    .await
                    .map_err(|err| EndpointExplorationError::Other {
                        details: format!("failed to create {UNIFIED_PREINGESTION_BFB_PATH}: {err}"),
                    })?;

            let mut buffer = vec![0; 1024 * 1024].into_boxed_slice(); // 1 MB buffer

            tracing::info!("Writing BFB to {UNIFIED_PREINGESTION_BFB_PATH}");
            loop {
                let n = preingestion_bfb.read(&mut buffer).await.map_err(|err| {
                    EndpointExplorationError::Other {
                        details: format!("failed to read BFB: {err}"),
                    }
                })?;

                if n == 0 {
                    break;
                }

                unified_bfb.write_all(&buffer[..n]).await.map_err(|err| {
                    EndpointExplorationError::Other {
                        details: format!(
                            "failed to write BFB to {UNIFIED_PREINGESTION_BFB_PATH}: {err}"
                        ),
                    }
                })?;
            }

            tracing::info!("Writing bf.cfg to {UNIFIED_PREINGESTION_BFB_PATH}:\n{bf_cfg_contents}");

            unified_bfb
                .write_all(bf_cfg_contents.as_bytes())
                .await
                .map_err(|err| EndpointExplorationError::Other {
                    details: format!("failed to write bf.cfg: {err}"),
                })?;

            unified_bfb
                .sync_all()
                .await
                .map_err(|err| EndpointExplorationError::Other {
                    details: format!("failed to flush {UNIFIED_PREINGESTION_BFB_PATH}: {err}"),
                })?;
        }

        Ok(())
    }

    async fn copy_bfb_to_dpu_rshim(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let (username, password) = match credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        self.create_unified_preingestion_bfb(&username, &password)
            .await?;

        self.check_and_enable_rshim(bmc_ip_address, &credentials)
            .await?;

        forge_ssh::ssh::copy_bfb_to_bmc_rshim(
            bmc_ip_address,
            username,
            password,
            UNIFIED_PREINGESTION_BFB_PATH.to_string(),
        )
        .await
        .map_err(|err| EndpointExplorationError::Other {
            details: format!(
                "failed to copy BFB from {UNIFIED_PREINGESTION_BFB_PATH} to BMC RSHIM on {bmc_ip_address}: {err}"
            ),
        })
    }

    async fn create_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        new_username: &str,
        new_password: &str,
        role_id: libredfish::RoleId,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .create_bmc_user(
                bmc_ip_address,
                credentials,
                new_username,
                new_password,
                role_id,
            )
            .await
    }

    async fn delete_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        delete_username: &str,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .delete_bmc_user(bmc_ip_address, credentials, delete_username)
            .await
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

    async fn probe_redfish_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .probe_redfish_endpoint(bmc_ip_address)
            .await
            .map(|_| ())
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
        expected_machine: Option<&ExpectedMachine>,
        expected_power_shelf: Option<&ExpectedPowerShelf>,
        expected_switch: Option<&ExpectedSwitch>,
        last_report: Option<&EndpointExplorationReport>,
        boot_interface_mac: Option<MacAddress>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        // If the site explorer was previously unable to login to the root BMC account using
        // the expected credentials, wait for an operator to manually intervene.
        // This will avoid locking us out of BMCs.
        if let Some(report) = last_report
            && report.cannot_login()
        {
            return Err(EndpointExplorationError::AvoidLockout);
        }

        let bmc_mac_address = interface.mac_address;
        let vendor = match self.probe_redfish_endpoint(bmc_ip_address).await {
            Ok(vendor) => vendor,
            Err(e) => {
                tracing::error!(%bmc_ip_address, "Failed to probe Redfish service root endpoint: {e}");
                //This is workaround for Lite-On power shelf BMCs
                // that do not support the Redfish service root endpoint
                let credentials = self.get_bmc_root_credentials(bmc_mac_address).await?;
                let (username, password) = match credentials.clone() {
                    Credentials::UsernamePassword { username, password } => (username, password),
                };

                let vendor = self
                    .redfish_client
                    .probe_vendor_name_from_chassis(bmc_ip_address, username, password)
                    .await?;
                if !vendor.to_lowercase().contains("lite-on technology corp") {
                    return Err(e);
                }
                RedfishVendor::LiteOnPowerShelf
            }
        };

        tracing::info!(%bmc_ip_address, "Is a {vendor} BMC that supports Redfish");

        // Authenticate and set the BMC root account credentials

        // Case 1: Vault contains a path at "bmc/{bmc_mac_address}/root"
        // This machine has its BMC set to the carbide sitewide BMC root password.
        // Create the redfish client and generate the report.
        let report = match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                match self
                    .generate_exploration_report(bmc_ip_address, credentials, boot_interface_mac)
                    .await
                {
                    Ok(report) => report,
                    // BMCs (HPEs currently) can return intermittent 401 errors even with valid credentials.
                    // Allow up to MAX_AUTH_RETRIES before escalating to regular Unauthorized.
                    Err(EndpointExplorationError::Unauthorized {
                        details,
                        response_body,
                        response_code,
                    }) if vendor == RedfishVendor::Hpe => {
                        const MAX_AUTH_RETRIES: u32 = 3;

                        let previous_count = last_report
                            .and_then(|r| r.last_exploration_error.as_ref())
                            .and_then(|e| e.intermittent_unauthorized_count())
                            .unwrap_or(0);
                        let consecutive_count = previous_count + 1;

                        if consecutive_count > MAX_AUTH_RETRIES {
                            tracing::warn!(
                                %bmc_ip_address, %bmc_mac_address, %details, consecutive_count,
                                "BMC unauthorized error persisted - escalating to Unauthorized"
                            );
                            return Err(EndpointExplorationError::Unauthorized {
                                details,
                                response_body,
                                response_code,
                            });
                        }

                        tracing::warn!(
                            %bmc_ip_address, %bmc_mac_address, %details, consecutive_count,
                            "BMC unauthorized error - treating as intermittent"
                        );
                        return Err(EndpointExplorationError::IntermittentUnauthorized {
                            details,
                            response_body,
                            response_code,
                            consecutive_count,
                        });
                    }
                    Err(e) => return Err(e),
                }
            }

            Err(EndpointExplorationError::MissingCredentials { .. }) => {
                tracing::info!(
                    %bmc_ip_address,
                    "Site explorer could not find an entry in vault at 'bmc/{bmc_mac_address}/root' - this is expected if the BMC has never been seen before.",
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
                    expected_power_shelf,
                    expected_switch,
                )
                .await?
            }
            Err(e) => {
                return Err(e);
            }
        };

        // Check for switch NVOS admin credentials if this is a switch
        if let Some(expected_switch) = expected_switch
            && expected_switch.nvos_username.is_some()
            && expected_switch.nvos_password.is_some()
        {
            // Only check if rotation is enabled
            if self.rotate_switch_nvos_credentials.load(Ordering::Relaxed) {
                match self
                    .get_switch_nvos_admin_credentials(bmc_mac_address)
                    .await
                {
                    Ok(_) => {
                        tracing::trace!(
                            %bmc_ip_address, %bmc_mac_address,
                            "NVOS admin credentials already exist in vault for switch {bmc_mac_address}"
                        );
                    }
                    Err(_) => {
                        tracing::info!(
                            %bmc_ip_address, %bmc_mac_address,
                            "Site explorer could not find NVOS admin credentials in vault for switch {bmc_mac_address} - setting them up.",
                        );
                        self.set_sitewide_switch_nvos_admin_credentials(
                            bmc_mac_address,
                            expected_switch,
                        )
                        .await?;
                    }
                }
            }
        }

        Ok(report)
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
            .bmc_cold_reset(bmc_ip_address.ip(), &credential_key)
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

    async fn disable_secure_boot(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.disable_secure_boot(bmc_ip_address, credentials).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support disabling secure boot for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn lockdown(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        action: libredfish::EnabledDisabled,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.lockdown(bmc_ip_address, credentials, action).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support lockdown for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn lockdown_status(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<LockdownStatus, EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.lockdown_status(bmc_ip_address, credentials).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support lockdown status for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn enable_infinite_boot(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => self.enable_infinite_boot(bmc_ip_address, credentials).await,
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support enabling infinite boot for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn is_infinite_boot_enabled(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
    ) -> Result<Option<bool>, EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.is_infinite_boot_enabled(bmc_ip_address, credentials)
                    .await
            }
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support checking infinite boot status for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn machine_setup(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.machine_setup(bmc_ip_address, credentials, boot_interface_mac)
                    .await
            }
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support starting machine_setup for endpoints that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
                    bmc_mac_address,
                );
                Err(e)
            }
        }
    }

    async fn set_boot_order_dpu_first(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        boot_interface_mac: &str,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.set_boot_order_dpu_first(bmc_ip_address, credentials, boot_interface_mac)
                    .await
            }
            Err(e) => {
                tracing::info!(
                    %bmc_ip_address,
                    "BMC endpoint explorer does not support configuring the boot order on host BMCs that have not been authenticated: could not find an entry in vault at 'bmc/{}/root'.",
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
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.copy_bfb_to_dpu_rshim(bmc_ip_address, credentials)
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

    async fn create_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        username: &str,
        password: &str,
        role_id: libredfish::RoleId,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.create_bmc_user(bmc_ip_address, credentials, username, password, role_id)
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

    async fn delete_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterfaceSnapshot,
        username: &str,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_mac_address = interface.mac_address;

        match self.get_bmc_root_credentials(bmc_mac_address).await {
            Ok(credentials) => {
                self.delete_bmc_user(bmc_ip_address, credentials, username)
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
