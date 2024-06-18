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

use bmc_vendor::BMCVendor;
use forge_secrets::credentials::{CredentialProvider, Credentials};
use mac_address::MacAddress;

use crate::db::{expected_machine::ExpectedMachine, machine_interface::MachineInterface};

use crate::{
    model::site_explorer::{EndpointExplorationError, EndpointExplorationReport},
    redfish::RedfishClientPool,
    site_explorer::EndpointExplorer,
};

use super::credentials::CredentialClient;
use super::metrics::SiteExplorationMetrics;
use super::redfish::RedfishClient;

/// An `EndpointExplorer` which uses redfish APIs to query the endpoint
pub struct RedfishEndpointExplorer {
    redfish_client: RedfishClient,
    credential_client: CredentialClient,
}

impl RedfishEndpointExplorer {
    pub fn new(
        redfish_client_pool: Arc<dyn RedfishClientPool>,
        credential_provider: Arc<dyn CredentialProvider>,
    ) -> Self {
        Self {
            redfish_client: RedfishClient::new(redfish_client_pool),
            credential_client: CredentialClient::new(credential_provider),
        }
    }

    pub async fn get_sitewide_bmc_root_credentials(
        &self,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.credential_client
            .get_sitewide_bmc_root_credentials()
            .await
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
    ) -> Result<BMCVendor, EndpointExplorationError> {
        self.redfish_client
            .probe_redfish_endpoint(bmc_ip_address)
            .await
    }

    pub async fn set_bmc_root_password(
        &self,
        bmc_ip_address: SocketAddr,
        bmc_vendor: BMCVendor,
        current_bmc_credentials: Credentials,
        new_bmc_credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        self.redfish_client
            .set_bmc_root_password(
                bmc_ip_address,
                bmc_vendor,
                current_bmc_credentials,
                new_bmc_credentials,
            )
            .await
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
        bmc_vendor: BMCVendor,
        expected_machine: Option<ExpectedMachine>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let current_bmc_credentials;

        tracing::info!(%bmc_ip_address, %bmc_mac_address, %bmc_vendor, "attempting to set the administrative credentials to the site password");

        if let Some(expected_machine_credentials) = expected_machine {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, "Found an expected machine for this BMC mac address");
            current_bmc_credentials = Credentials::UsernamePassword {
                username: expected_machine_credentials.bmc_username,
                password: expected_machine_credentials.bmc_password,
            };
        } else {
            tracing::info!(%bmc_ip_address, %bmc_mac_address, %bmc_vendor, "No expected machine found, could be a BlueField");
            // We dont know if this machine is a DPU at this point
            // Check the vendor to see if it could be a DPU (the DPU's vendor is NVIDIA)
            match bmc_vendor {
                BMCVendor::Nvidia => {
                    // This machine is either is either a DPU or a Viking host.
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
                            bmc_vendor, bmc_ip_address, bmc_mac_address
                        ),
                    })
                }
            }
        }

        let sitewide_bmc_root_credentials = self.get_sitewide_bmc_root_credentials().await?;

        // use redfish to set the machine's BMC root password to
        // match Forge's sitewide BMC root password (from the factory default).
        // return an error if we cannot log into the machine's BMC using current credentials
        self.set_bmc_root_password(
            bmc_ip_address,
            bmc_vendor,
            current_bmc_credentials,
            sitewide_bmc_root_credentials.clone(),
        )
        .await?;

        tracing::info!(
            %bmc_ip_address, %bmc_mac_address, %bmc_vendor,
            "Site explorer successfully updated the root password for {bmc_mac_address} to the Forge sitewide BMC root password"
        );

        // set the BMC root credentials in vault for this machine
        self.set_bmc_root_credentials(bmc_mac_address, sitewide_bmc_root_credentials.clone())
            .await?;

        self.generate_exploration_report(bmc_ip_address, sitewide_bmc_root_credentials)
            .await
    }

    // Handle the legacy case: machines that were previously discovered through the legacy ingestion flow
    // and already had their bmc's root account password changed from the factory to the site specific password.
    // These machines do not need their root authentication changed; we just need to add the appropriate bmc specific
    // credentials in vault so that the new site explorer flow can continue ingesting this machine
    pub async fn handle_legacy_bmc_root_auth(
        &self,
        bmc_ip_address: SocketAddr,
        bmc_mac_address: MacAddress,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let sitewide_bmc_root_credentials = self.get_sitewide_bmc_root_credentials().await?;

        let report = self
            .generate_exploration_report(bmc_ip_address, sitewide_bmc_root_credentials.clone())
            .await?;

        self.set_bmc_root_credentials(bmc_mac_address, sitewide_bmc_root_credentials)
            .await?;

        Ok(report)
    }
}

#[async_trait::async_trait]
impl EndpointExplorer for RedfishEndpointExplorer {
    async fn check_preconditions(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        self.credential_client.is_ready(metrics).await
    }

    // 1) Authenticate and set the BMC root account credentials
    // 2) Authenticate and set the BMC forge-admin account credentials (TODO)
    async fn explore_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
        interface: &MachineInterface,
        expected_machine: Option<ExpectedMachine>,
        last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        // If the site explorer was previously unable to login to the root BMC account using
        // the expected credentials, wait for an operator to manually intervene.
        // This will avoid locking us out of BMCs.
        if let Some(report) = last_report {
            if report.cannot_login() {
                return Err(EndpointExplorationError::Other{ details: format!("Site explorer is not exploring endpoint {bmc_ip_address:#?} because it was previously unable to login using the known credentials") });
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

                // Case 2:
                // The machine's BMC root password has already been set to the Forge Sitewide BMC root password.
                // But, Vault does NOT have an entry for "bmc/{bmc_mac_address}/root"
                // 1) Add an entry in vault for "bmc/{bmc_mac_address}/root"
                // 2) Create the redfish client and generate the report.
                match self
                    .handle_legacy_bmc_root_auth(bmc_ip_address, bmc_mac_address)
                    .await
                {
                    Ok(report) => Ok(report),
                    Err(e) => match e {
                        EndpointExplorationError::Unauthorized { details: _ } => {
                            tracing::info!(
                                %bmc_ip_address,
                                "Site Explorer could not use site-wide credentials to login to this unknown BMC - this is expected if the BMC has never been seen before: {e}"
                            );

                            // Case 3:
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
                        _ => Err(e),
                    },
                }
            }
        }
    }
}
