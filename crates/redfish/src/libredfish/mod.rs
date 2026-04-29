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

mod implementation;

pub mod auth;
pub mod error;
#[cfg(feature = "test-support")]
pub mod test_support;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
pub use auth::RedfishAuth;
use carbide_utils::HostPortPair;
pub use error::RedfishClientCreationError;
use forge_secrets::credentials::{CredentialKey, CredentialReader, CredentialType, Credentials};
use libredfish::Redfish;
use libredfish::model::service_root::RedfishVendor;
use model::machine::Machine;
use sqlx::PgPool;

pub fn new_pool(
    credential_reader: Arc<dyn CredentialReader>,
    pool: libredfish::RedfishClientPool,
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
) -> Arc<dyn RedfishClientPool> {
    Arc::new(implementation::RedfishClientPoolImpl::new(
        credential_reader,
        pool,
        proxy_address,
    ))
}

/// Create Redfish clients for a certain Redfish BMC endpoint
#[async_trait]
pub trait RedfishClientPool: Send + Sync + 'static {
    // MARK: - Required methods

    /// Creates a new Redfish client for a Machines BMC.
    /// `host` is the IP address or hostname of the BMC.
    /// `vendor` allows you to pre-assign the underlying
    /// RedfishVendor to use for the client, saving the
    /// service root call to auto-detect the vendor.
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        vendor: Option<RedfishVendor>,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;

    /// Returns a CredentialReader for use in setting credentials in the UEFI/BMC.
    fn credential_reader(&self) -> &dyn CredentialReader;

    // MARK: - Default (helper) methods

    async fn probe_redfish_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<(), RedfishClientCreationError> {
        let client = self
            .create_client(
                &bmc_ip_address.ip().to_string(),
                Some(bmc_ip_address.port()),
                RedfishAuth::Anonymous,
                Some(RedfishVendor::Unknown),
            )
            .await?;

        client
            .get_service_root()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(())
    }

    async fn create_client_from_machine(
        &self,
        target: &Machine,
        pool: &PgPool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let Some(addr) = target.bmc_addr() else {
            return Err(RedfishClientCreationError::MissingBmcEndpoint(format!(
                "BMC Endpoint Information (bmc_info.ip) is missing for {}",
                target.id,
            )));
        };
        let ip = addr.ip();
        let port = addr.port();
        let auth_key = db::machine_interface::find_by_ip(pool, ip)
            .await?
            .ok_or_else(|| {
                RedfishClientCreationError::MissingArgument(format!(
                    "Machine Interface for IP address: {ip}"
                ))
            })
            .map(|machine_interface| RedfishAuth::for_bmc_mac(machine_interface.mac_address))?;

        self.create_client(&ip.to_string(), Some(port), auth_key, None)
            .await
    }

    /// Create a redfish client using auth credentials we already have in machine_interfaces for a
    /// given IP.
    ///
    /// For testing purposes, if no credentials are found for the IP, and if self.proxy_address is
    /// set, will use anonymous auth.
    async fn create_client_for_ingested_host(
        &self,
        ip: IpAddr,
        port: Option<u16>,
        pool: &PgPool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let auth_key = db::machine_interface::find_by_ip(pool, ip)
            .await?
            .ok_or_else(|| {
                RedfishClientCreationError::MissingArgument(format!(
                    "Machine Interface for IP address: {ip}"
                ))
            })
            .map(|machine_interface| RedfishAuth::for_bmc_mac(machine_interface.mac_address))?;

        self.create_client(&ip.to_string(), port, auth_key, None)
            .await
    }

    // clear_host_uefi_password updates the UEFI password from Forge's sitewide password to an empty string
    // The assumption is that this function will only be called on a machine that already updated the UEFI password to match the Forge sitewide password.
    async fn clear_host_uefi_password(
        &self,
        client: &dyn Redfish,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let credential_key = CredentialKey::HostUefi {
            credential_type: CredentialType::SiteDefault,
        };

        let credentials = self
            .credential_reader()
            .get_credentials(&credential_key)
            .await?
            .ok_or_else(|| RedfishClientCreationError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
            })?;

        let (_, current_password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        client
            .clear_uefi_password(current_password.as_str())
            .await
            .map_err(|err| redact_password(err, current_password.as_str()))
            .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let mut current_password = String::new();
        let new_password: String;
        if dpu {
            let bios_attrs = client
                .bios()
                .await
                .map_err(RedfishClientCreationError::RedfishError)?;

            //
            // This should be changed to be an actual failure once we make it this far since we don't
            // want to leave machines lying around in the datacenter without UEFI credentials.
            //
            // But adding logs here so that we know when it happens
            //
            match bios_attrs.get("Attributes") {
                None => {
                    tracing::warn!(
                        "BIOS Attributes are missing in the Redfish System BIOS endpoint, skipping UEFI password setting"
                    );
                    return Ok(None);
                }
                Some(attrs) => match attrs.as_object() {
                    None => {
                        tracing::warn!(
                            "BIOS attributes are not an object in the Redfish System BIOS endpoint, skipping UEFI password setting"
                        );
                        return Ok(None);
                    }
                    Some(attrs) if !attrs.contains_key("CurrentUefiPassword") => {
                        tracing::warn!(
                            "BIOS Attributes exist, but is missing CurrentUefiPassword key, skipping UEFI password setting"
                        );
                        return Ok(None);
                    }
                    _ => {
                        tracing::info!(
                            "BIOS Attributes found, and contains CurrentUefiPassword, continuing with UEFI password setting"
                        );
                    }
                },
            }

            // Replace DPU UEFI default password with site default
            // default password is taken from DpuUefi:factory_default key
            // site password is taken from DpuUefi:site_default key
            //
            let credentials = self
                .credential_reader()
                .get_credentials(&CredentialKey::DpuUefi {
                    credential_type: CredentialType::DpuHardwareDefault,
                })
                .await?
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
                .credential_reader()
                .get_credentials(&credential_key)
                .await?
                .ok_or_else(|| RedfishClientCreationError::MissingCredentials {
                    key: credential_key.to_key_str().to_string(),
                })?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        } else {
            // For hosts, first try with empty current password (assuming no password is set)
            let credential_key = CredentialKey::HostUefi {
                credential_type: CredentialType::SiteDefault,
            };
            let credentials = self
                .credential_reader()
                .get_credentials(&credential_key)
                .await?
                .ok_or_else(|| RedfishClientCreationError::MissingCredentials {
                    key: credential_key.to_key_str().to_string(),
                })?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };

            // Try with empty password first (no password set on host)
            match client
                .change_uefi_password(current_password.as_str(), new_password.as_str())
                .await
            {
                Ok(jid) => return Ok(jid),
                Err(e) => {
                    // If the first attempt fails (likely because a password is already set),
                    // retry using the site default password as the current password.
                    // This handles the case where a host was force-deleted without clearing
                    // its UEFI password.
                    let redacted_error = redact_password(e, new_password.as_str());
                    tracing::warn!(
                        error = %redacted_error,
                        "Failed to set UEFI password with empty current password, retrying with site default password"
                    );
                    current_password = new_password.clone();
                }
            }
        }

        client
            .change_uefi_password(current_password.as_str(), new_password.as_str())
            .await
            .map_err(|err| redact_password(err, new_password.as_str()))
            .map_err(|err| redact_password(err, current_password.as_str()))
            .map_err(RedfishClientCreationError::RedfishError)
    }
}

// Some BMC implementation may return passwords in response body and
// we can display them to user. This function is helper to remove
// password leak for password-related refish functions.
pub fn redact_password(err: libredfish::RedfishError, password: &str) -> libredfish::RedfishError {
    type RfError = libredfish::RedfishError;
    const REDACTED: &str = "REDACTED";
    let redact = |v: String| v.replace(password, REDACTED);
    match err {
        RfError::HTTPErrorCode {
            url,
            status_code,
            response_body,
        } => RfError::HTTPErrorCode {
            url,
            status_code,
            response_body: redact(response_body),
        },
        RfError::JsonDeserializeError { url, body, source } => RfError::JsonDeserializeError {
            url,
            body: redact(body),
            source,
        },
        RfError::JsonSerializeError {
            url,
            object_debug,
            source,
        } => RfError::JsonSerializeError {
            url,
            object_debug: redact(object_debug),
            source,
        },
        RfError::InvalidValue {
            url,
            field,
            err: libredfish::model::InvalidValueError(v),
        } => RfError::InvalidValue {
            url,
            field,
            err: libredfish::model::InvalidValueError(redact(v)),
        },
        RfError::GenericError { error } => RfError::GenericError {
            error: redact(error),
        },
        // All errors are enumerated here instead of default to get
        // compile error on any new error in libredfish added. This
        // gives you chance to think if password may leak to the new
        // error or not.
        RfError::NetworkError { .. }
        | RfError::NoContent
        | RfError::NoHeader
        | RfError::Lockdown
        | RfError::MissingVendor
        | RfError::PasswordChangeRequired
        | RfError::FileError(_)
        | RfError::UserNotFound(_)
        | RfError::NotSupported(_)
        | RfError::UnnecessaryOperation
        | RfError::MissingKey { .. }
        | RfError::InvalidKeyType { .. }
        | RfError::TooManyUsers
        | RfError::NoDpu
        | RfError::ReqwestError(_)
        | RfError::TypeMismatch { .. }
        | RfError::MissingBootOption(_) => err,
    }
}

#[cfg(test)]
mod tests {
    use libredfish::PowerState;

    use super::*;
    use crate::libredfish::test_support::*;

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
                None,
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
                None,
            )
            .await
            .unwrap();
        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
    }

    #[test]
    fn password_redact_from_error() {
        const PASSWORD: &str = "1234";
        let err = libredfish::RedfishError::HTTPErrorCode {
            url: "https://example.com/redfish/v1/Systems/1/Bios/Actions/Bios.ChangePassword".into(),
            status_code: http::StatusCode::BAD_REQUEST,
            response_body: format!(r#""MessageArgs":["{PASSWORD}"]"#),
        };
        assert!(err.to_string().contains(PASSWORD));
        assert!(
            !redact_password(err, PASSWORD)
                .to_string()
                .contains(PASSWORD)
        );
    }
}
