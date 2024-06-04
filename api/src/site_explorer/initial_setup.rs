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

use bmc_vendor::BMCVendor;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, CredentialType, Credentials};
use libredfish::{model::service_root::ServiceRoot, Redfish, RedfishError, RoleId};

use super::redfish_endpoint_explorer::map_redfish_client_creation_error;
use crate::{
    db::expected_machine::ExpectedMachine,
    model::site_explorer::{EndpointExplorationError, EndpointExplorationReport, EndpointType},
    redfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool},
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
    credential_provider: Arc<dyn CredentialProvider>,
    address: SocketAddr,
    expected: Option<ExpectedMachine>,
) -> Result<Option<EndpointExplorationReport>, EndpointExplorationError> {
    tracing::info!(%address, "Running first time setup");
    let mut has_changes = false;

    let endpoint = UnknownEndpoint {
        address,
        redfish_client_pool: redfish_client_pool.clone(),
    };
    let mut endpoint: AnonymousRedfishEndpoint = endpoint.try_redfish().await?;
    tracing::trace!(%address, "Is a BMC that supports Redfish");
    endpoint.set_per_host_factory_credentials(expected);

    // If this is a DPU not a Host this auth will fail
    let mut endpoint: RedfishEndpoint = endpoint.try_auth(credential_provider.clone()).await?;
    tracing::trace!(%address, "Is a host, we are authenticated");

    if endpoint.has_factory_credentials {
        tracing::trace!(%address, "Has factory default credentials. Changing them to site default.");
        // Ensures site user/pass exist
        endpoint = endpoint.convert_to_site_auth(credential_provider).await?;
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
            .create_client(
                &self.address.ip().to_string(),
                Some(self.address.port()),
                RedfishAuth::Anonymous,
                false,
            )
            .await
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
            exp_username: None,
            exp_password: None,
        })
    }
}

struct AnonymousRedfishEndpoint {
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    address: SocketAddr,
    service_root: ServiceRoot,

    // Optional per-host factory default credentials from expected_machines table
    exp_username: Option<String>,
    exp_password: Option<String>,
}

impl AnonymousRedfishEndpoint {
    fn set_per_host_factory_credentials(&mut self, exp: Option<ExpectedMachine>) {
        if let Some(exp) = exp {
            tracing::trace!(address=%self.address, "Has individual factory credentials");
            self.exp_username = Some(exp.bmc_username);
            self.exp_password = Some(exp.bmc_password);
        }
    }

    /// Try to login. There are three potential credentials:
    /// - The site default. This is what we want all hosts to use. If we login any other way we
    /// change the auth to this. SRE load this into vault via forge-admin-cli during site setup.
    /// - A per-host factory default. This is provided to Forge in a CSV/JSON manifest as
    /// an ExpectedMachine. Often these comes from a sticker printed on the chassis that data
    /// center folks copied into Nautobot.
    /// - A general vendor factory default: Some vendors set all their BMCs to the same user/pass
    /// and force a change on first use. This is also loaded into Vault for us by SRE during setup.
    ///
    async fn try_auth(
        self,
        credential_provider: Arc<dyn CredentialProvider>,
    ) -> Result<RedfishEndpoint, EndpointExplorationError> {
        let Some(vendor) = self.service_root.vendor().map(|v| v.into()) else {
            return Err(EndpointExplorationError::MissingVendor);
        };

        struct Auth {
            username: String,
            password: String,
            is_factory: bool,
            log_msg: &'static str,
        }
        let mut auths = vec![];

        // Site default - this is what we want so try it first
        let site_key = CredentialKey::HostRedfish {
            credential_type: CredentialType::SiteDefault,
        };
        match credential_provider.get_credentials(site_key).await {
            Ok(Credentials::UsernamePassword { username, password }) => {
                auths.push(Auth {
                    username,
                    password,
                    is_factory: false,
                    log_msg: "site default",
                });
            }
            Err(err) => {
                tracing::error!(%err, "Site default credentials missing from Vault");
                return Err(EndpointExplorationError::MissingCredentials);
            }
        }

        // Per-host factory default. New sites should have this populated
        if let (Some(username), Some(password)) = (self.exp_username, self.exp_password) {
            auths.push(Auth {
                username,
                password,
                is_factory: true,
                log_msg: "per-host factory",
            });
        }

        // Per-vendor factory default. If all else fails.
        let default_factory_key = forge_secrets::credentials::CredentialKey::HostRedfish {
            credential_type: CredentialType::HostHardwareDefault { vendor },
        };
        match credential_provider
            .get_credentials(default_factory_key)
            .await
        {
            Ok(Credentials::UsernamePassword { username, password }) => {
                auths.push(Auth {
                    username,
                    password,
                    is_factory: true,
                    log_msg: "per-vendor factory",
                });
            }
            Err(err) => {
                // info only, and continue because eventually we will switch to per-host only
                tracing::info!(%err, %vendor, "Vendor factory default credentials missing from Vault");
            }
        };

        for auth in &auths {
            tracing::trace!(address=%self.address, "Attempting to authenticate with {} credential", auth.log_msg);
            let maybe_client = self
                .redfish_client_pool
                .create_client(
                    &self.address.ip().to_string(),
                    Some(self.address.port()),
                    RedfishAuth::Direct(auth.username.clone(), auth.password.clone()),
                    true, // initialize, which makes Redfish HTTP requests to test auth
                )
                .await;
            match maybe_client {
                Ok(client) => {
                    tracing::trace!(address=%self.address, "Authenticated with {} credentials", auth.log_msg);
                    return Ok(RedfishEndpoint {
                        redfish_client_pool: self.redfish_client_pool,
                        address: self.address,
                        current_username: auth.username.clone(),
                        client,
                        has_factory_credentials: auth.is_factory,
                        vendor,
                    });
                }
                Err(RedfishClientCreationError::RedfishError(
                    RedfishError::PasswordChangeRequired,
                )) => {
                    // Auth worked but needs changing immediately. Create new client that doesn't
                    // do the HTTP requests
                    tracing::trace!(address=%self.address, "Password change required on {} credentials", auth.log_msg);
                    let client = self
                        .redfish_client_pool
                        .create_client(
                            &self.address.ip().to_string(),
                            Some(self.address.port()),
                            RedfishAuth::Direct(auth.username.clone(), auth.password.clone()),
                            false,
                        )
                        .await
                        .map_err(map_redfish_client_creation_error)?;
                    return Ok(RedfishEndpoint {
                        redfish_client_pool: self.redfish_client_pool,
                        address: self.address,
                        current_username: auth.username.clone(),
                        client,
                        has_factory_credentials: auth.is_factory,
                        vendor,
                    });
                }
                Err(RedfishClientCreationError::RedfishError(e)) if e.is_unauthorized() => {
                    tracing::trace!(address=%self.address, "Authentication with {} did not work", auth.log_msg);
                }
                Err(err) => return Err(map_redfish_client_creation_error(err)),
            }
        }

        // None of the auths worked
        Err(EndpointExplorationError::InvalidCredentials(
            auths
                .iter()
                .map(|a| a.log_msg)
                .collect::<Vec<&str>>()
                .join(", "),
        ))
    }
}

struct RedfishEndpoint {
    pub has_factory_credentials: bool,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    address: SocketAddr,
    current_username: String,
    client: Box<dyn Redfish>,
    vendor: BMCVendor,
}

impl RedfishEndpoint {
    async fn convert_to_site_auth(
        self,
        credential_provider: Arc<dyn CredentialProvider>,
    ) -> Result<RedfishEndpoint, EndpointExplorationError> {
        let site_key = CredentialKey::HostRedfish {
            credential_type: CredentialType::SiteDefault,
        };
        let maybe_creds = credential_provider.get_credentials(site_key.clone()).await;

        let (site_user, site_pass) = match maybe_creds {
            Err(err) => {
                tracing::error!(%err, "Site default credentials missing from Vault");
                return Err(EndpointExplorationError::MissingCredentials);
            }
            Ok(Credentials::UsernamePassword { username, password }) => (username, password),
        };

        match self.vendor {
            BMCVendor::Lenovo => {
                // Change (factory_user, factory_pass) to (factory_user, site_pass)
                // We must do this first, BMC won't allow any other call until this is done
                self.client
                    .change_password_by_id("1", site_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;

                // Auth has changed
                let mid_client = self
                    .redfish_client_pool
                    .create_client(
                        &self.address.ip().to_string(),
                        Some(self.address.port()),
                        RedfishAuth::Direct(self.current_username.clone(), site_pass),
                        false,
                    )
                    .await
                    .map_err(map_redfish_client_creation_error)?;

                // Change (factory_user, site_pass) to (site_user, site_pass)
                mid_client
                    .change_username(&self.current_username, &site_user)
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
                RedfishAuth::Key(site_key),
                true,
            )
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .set_forge_password_policy()
            .await
            .map_err(map_redfish_error)?;

        Ok(RedfishEndpoint {
            client,
            has_factory_credentials: false,
            redfish_client_pool: self.redfish_client_pool,
            current_username: site_user,
            address: self.address,
            vendor: self.vendor,
        })
    }
}
