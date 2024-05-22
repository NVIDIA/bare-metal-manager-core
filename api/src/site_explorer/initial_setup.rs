/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use forge_secrets::credentials::{CredentialKey, CredentialType};
use libredfish::{model::service_root::ServiceRoot, Redfish, RedfishError, RoleId};

use super::redfish_endpoint_explorer::map_redfish_client_creation_error;
use crate::{
    model::site_explorer::{EndpointExplorationError, EndpointExplorationReport, EndpointType},
    redfish::{RedfishClientCreationError, RedfishClientPool},
    site_explorer::redfish_endpoint_explorer::map_redfish_error,
};

/// Takes the address of the BMC of a host and:
/// - ensures it has site default authentication
/// - and will UEFI HTTP boot (forge_setup)
///
/// site explorer creates the machine in DpuDiscoveringState::Initializing which leads to
///  the Configuring state.
/// forge_setup will be run by api/src/state_controller/machine/handler.rs
///  in that state ManagedHostState::DpuDiscoveringState / DpuDiscoveringState::Configuring.
/// forge_setup does most of the BIOS / BMC setup.
pub async fn host(
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    address: SocketAddr,
) -> Result<Option<EndpointExplorationReport>, EndpointExplorationError> {
    tracing::info!(%address, "Running first time setup");
    let mut has_changes = false;

    let endpoint = UnknownEndpoint {
        address,
        redfish_client_pool: redfish_client_pool.clone(),
    };
    let endpoint: AnonymousRedfishEndpoint = endpoint.try_redfish().await?;
    tracing::trace!(%address, "Is a BMC that supports Redfish");

    // If this is a DPU not a Host this auth will fail
    let mut endpoint: RedfishEndpoint = endpoint.try_auth().await?;
    tracing::trace!(%address, "Is a host, we are authenticated");

    if endpoint.has_factory_credentials {
        tracing::trace!(%address, "Has factory default credentials. Changing them to site default.");
        // Ensures site user/pass exist
        endpoint = endpoint.convert_to_site_auth().await?;
        has_changes = true;
    }

    let setup_status = endpoint
        .client
        .forge_setup_status()
        .await
        .map_err(map_redfish_error)?;
    if !setup_status.is_done {
        // First pass at setting all the BMC/BIOS values.
        // On some vendors (Supermicro) this will fail because some values don't appear until
        // others are set. That's fine, the state machine runs it again later.
        let _ = endpoint.client.forge_setup().await;
        has_changes = true;
        tracing::trace!(%address, "BMC/BIOS values set.");
    } else {
        tracing::trace!(%address, "BMC/BIOS settings are up to date");
    }

    if has_changes {
        tracing::trace!(%address, "Rebooting");
        endpoint
            .client
            .power(libredfish::SystemPowerControl::ForceRestart)
            .await
            .map_err(map_redfish_error)?;
        // if we changed something site explorer should stop now as we're waiting for a reboot
        Ok(Some(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            vendor: Some(endpoint.vendor),
            managers: vec![],
            systems: vec![],
            chassis: vec![],
            service: vec![],
            machine_id: None,
        }))
    } else {
        Ok(None)
    }
}

struct UnknownEndpoint {
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    address: SocketAddr,
}

impl UnknownEndpoint {
    async fn try_redfish(self) -> Result<AnonymousRedfishEndpoint, EndpointExplorationError> {
        let client = self
            .redfish_client_pool
            .create_anonymous_client(&self.address.ip().to_string(), Some(self.address.port()))
            .map_err(map_redfish_client_creation_error)?;
        let service_root = match client.get_service_root().await {
            Ok(sr) => sr,
            Err(RedfishError::HTTPErrorCode { status_code, .. })
                if status_code == http::StatusCode::NOT_FOUND =>
            {
                return Err(EndpointExplorationError::MissingRedfish);
            }
            Err(e) => {
                return Err(EndpointExplorationError::RedfishError {
                    details: e.to_string(),
                })
            }
        };
        Ok(AnonymousRedfishEndpoint {
            redfish_client_pool: self.redfish_client_pool,
            address: self.address,
            service_root,
        })
    }
}

struct AnonymousRedfishEndpoint {
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    address: SocketAddr,
    service_root: ServiceRoot,
}
impl AnonymousRedfishEndpoint {
    async fn try_auth(self) -> Result<RedfishEndpoint, EndpointExplorationError> {
        let Some(vendor) = self.service_root.vendor().map(|v| v.into()) else {
            return Err(EndpointExplorationError::MissingVendor);
        };

        let key = forge_secrets::credentials::CredentialKey::HostRedfish {
            credential_type: CredentialType::HostHardwareDefault { vendor },
        };
        let factory_client = self
            .redfish_client_pool
            .create_client(
                &self.address.ip().to_string(),
                Some(self.address.port()),
                key,
            )
            .await;
        let (client, has_factory_credentials) = match factory_client {
            Ok(factory_client) => (factory_client, true),
            Err(RedfishClientCreationError::RedfishError(e)) if e.is_unauthorized() => {
                let key = CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                };
                let site_client = self
                    .redfish_client_pool
                    .create_client(
                        &self.address.ip().to_string(),
                        Some(self.address.port()),
                        key,
                    )
                    .await
                    .map_err(map_redfish_client_creation_error)?;
                (site_client, false)
            }
            Err(err) => return Err(map_redfish_client_creation_error(err)),
        };

        Ok(RedfishEndpoint {
            redfish_client_pool: self.redfish_client_pool,
            address: self.address,
            client,
            has_factory_credentials,
            vendor,
        })
    }
}

struct RedfishEndpoint {
    pub has_factory_credentials: bool,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    address: SocketAddr,
    client: Box<dyn Redfish>,
    vendor: bmc_vendor::BMCVendor,
}

impl RedfishEndpoint {
    async fn convert_to_site_auth(self) -> Result<RedfishEndpoint, EndpointExplorationError> {
        let (factory_user, _) = self
            .redfish_client_pool
            .get_factory_root_credentials(self.vendor)
            .await
            .map_err(|err| {
                tracing::error!(vendor = %self.vendor, %err, "get_factory_root_credentials");
                EndpointExplorationError::MissingCredentials
            })?;
        let (site_user, site_pass) = self
            .redfish_client_pool
            .get_site_default_credentials()
            .await
            .map_err(|err| {
                tracing::error!(%err, "get_site_default_credentials");
                EndpointExplorationError::MissingCredentials
            })?;

        use bmc_vendor::BMCVendor;
        match self.vendor {
            BMCVendor::Lenovo => {
                self.client
                    .change_username(&factory_user, &site_user)
                    .await
                    .map_err(map_redfish_error)?;
                self.client
                    .set_forge_password_policy()
                    .await
                    .map_err(map_redfish_error)?;
                self.client
                    .change_password(site_user.as_str(), site_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            BMCVendor::Supermicro => {
                // I think Supermicro does not allow renaming it's original superuser ('ADMIN').
                // Check this.
                self.client
                    .create_user(&site_user, &site_pass, RoleId::Administrator)
                    .await
                    .map_err(map_redfish_error)?;
            }
            BMCVendor::Dell | BMCVendor::Nvidia => {
                self.client
                    .change_password(site_user.as_str(), site_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            BMCVendor::Hpe => {
                // We don't have an Ansible playbook for HPE. We only run one or two of them
                // in dev, no prod deploys.
                return Err(EndpointExplorationError::UnsupportedVendor(
                    self.vendor.to_string(),
                ));
            }
            BMCVendor::Unknown => {
                return Err(EndpointExplorationError::UnsupportedVendor(
                    self.vendor.to_string(),
                ));
            }
        };

        // Now login with the site credentials
        let client = self
            .redfish_client_pool
            .create_client(
                &self.address.ip().to_string(),
                Some(self.address.port()),
                CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                },
            )
            .await
            .map_err(map_redfish_client_creation_error)?;

        Ok(RedfishEndpoint {
            client,
            has_factory_credentials: false,
            redfish_client_pool: self.redfish_client_pool,
            address: self.address,
            vendor: self.vendor,
        })
    }
}
