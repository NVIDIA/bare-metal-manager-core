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

use std::sync::Arc;

use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, CredentialType, Credentials,
};
use mac_address::MacAddress;
use model::site_explorer::EndpointExplorationError;

use super::metrics::SiteExplorationMetrics;

const SITEWIDE_BMC_ROOT_CREDENTIAL_KEY: CredentialKey = CredentialKey::BmcCredentials {
    credential_type: forge_secrets::credentials::BmcCredentialType::SiteWideRoot,
};

pub fn get_bmc_root_credential_key(bmc_mac_address: MacAddress) -> CredentialKey {
    CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    }
}

pub fn get_bmc_nvos_admin_credential_key(bmc_mac_address: MacAddress) -> CredentialKey {
    CredentialKey::SwitchNvosAdmin { bmc_mac_address }
}

pub struct CredentialClient {
    credential_provider: Arc<dyn CredentialProvider>,
}

impl CredentialClient {
    fn valid_password(credentials: &Credentials) -> bool {
        let (_, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        if password.is_empty() {
            return false;
        }

        true
    }

    // TODO (spyda): fix the credential implementation for DPU and Host UEFI so that
    // we dont have to pass a validate boolean. We shouldnt store a username field in the
    // UEFI credential entry if its not relevant.
    async fn get_credentials(
        &self,
        credential_key: &CredentialKey,
    ) -> Result<Credentials, EndpointExplorationError> {
        match self
            .credential_provider
            .get_credentials(credential_key)
            .await
        {
            Ok(Some(credentials)) => {
                if !Self::valid_password(&credentials) {
                    return Err(EndpointExplorationError::Other {
                        details: format!(
                            "vault does not have a valid password entry at {}",
                            credential_key.to_key_str()
                        ),
                    });
                }

                Ok(credentials)
            }
            Ok(None) => Err(EndpointExplorationError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: "No credentials exists".to_string(),
            }),
            Err(err) => Err(EndpointExplorationError::SecretsEngineError {
                cause: err.to_string(),
            }),
        }
    }

    async fn set_credentials(
        &self,
        credential_key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), EndpointExplorationError> {
        match self
            .credential_provider
            .set_credentials(credential_key, credentials)
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => Err(EndpointExplorationError::SetCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: err.to_string(),
            }),
        }
    }

    pub fn new(credential_provider: Arc<dyn CredentialProvider>) -> Self {
        Self {
            credential_provider,
        }
    }

    pub async fn check_preconditions(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        // Site wide BMC credentials
        let credential_key = SITEWIDE_BMC_ROOT_CREDENTIAL_KEY;
        if let Some(e) = self.get_credentials(&credential_key).await.err() {
            let credential_key_str = credential_key.to_key_str();
            metrics.increment_credential_missing(&credential_key_str);
            return Err(EndpointExplorationError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: e.to_string(),
            });
        }

        // Site wide DPU UEFI credentials
        let credential_key = CredentialKey::DpuUefi {
            credential_type: CredentialType::SiteDefault,
        };
        if let Some(e) = self.get_credentials(&credential_key).await.err() {
            let credential_key_str = credential_key.to_key_str();
            metrics.increment_credential_missing(&credential_key_str);
            return Err(EndpointExplorationError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: e.to_string(),
            });
        }

        // Site wide Host UEFI credentials
        let credential_key = CredentialKey::HostUefi {
            credential_type: CredentialType::SiteDefault,
        };
        if let Some(e) = self.get_credentials(&credential_key).await.err() {
            let credential_key_str = credential_key.to_key_str();
            metrics.increment_credential_missing(&credential_key_str);
            return Err(EndpointExplorationError::MissingCredentials {
                key: credential_key.to_key_str().to_string(),
                cause: e.to_string(),
            });
        }

        Ok(())
    }

    pub async fn get_sitewide_bmc_root_credentials(
        &self,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.get_credentials(&SITEWIDE_BMC_ROOT_CREDENTIAL_KEY)
            .await
    }

    pub fn get_default_hardware_dpu_bmc_root_credentials(&self) -> Credentials {
        Credentials::UsernamePassword {
            username: "root".into(),
            password: "0penBmc".into(),
        }
    }

    pub async fn get_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
    ) -> Result<Credentials, EndpointExplorationError> {
        let bmc_root_credential_key = get_bmc_root_credential_key(bmc_mac_address);
        self.get_credentials(&bmc_root_credential_key).await
    }

    pub async fn get_switch_nvos_admin_credentials(
        &self,
        bmc_mac_address: MacAddress,
    ) -> Result<Credentials, EndpointExplorationError> {
        let switch_nvos_admin_credential_key = get_bmc_nvos_admin_credential_key(bmc_mac_address);
        self.get_credentials(&switch_nvos_admin_credential_key)
            .await
    }

    pub async fn set_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
        credentials: &Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_root_credential_key = get_bmc_root_credential_key(bmc_mac_address);
        self.set_credentials(&bmc_root_credential_key, credentials)
            .await
    }

    pub async fn set_bmc_nvos_admin_credentials(
        &self,
        bmc_mac_address: MacAddress,
        credentials: &Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_nvos_admin_credential_key = get_bmc_nvos_admin_credential_key(bmc_mac_address);
        self.set_credentials(&bmc_nvos_admin_credential_key, credentials)
            .await
    }
}
