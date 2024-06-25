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

use crate::model::site_explorer::EndpointExplorationError;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, Credentials,
};
use mac_address::MacAddress;
use std::sync::Arc;

use super::metrics::SiteExplorationMetrics;

const SITEWIDE_BMC_ROOT_CREDENTIAL_KEY: CredentialKey = CredentialKey::BmcCredentials {
    credential_type: forge_secrets::credentials::BmcCredentialType::SiteWideRoot,
};

pub fn get_bmc_root_credential_key(bmc_mac_address: MacAddress) -> CredentialKey {
    CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
    }
}

pub struct CredentialClient {
    credential_provider: Arc<dyn CredentialProvider>,
}

impl CredentialClient {
    fn valid_credentials(credentials: Credentials) -> bool {
        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        if username.is_empty() || password.is_empty() {
            return false;
        }

        true
    }

    async fn get_credentials(
        &self,
        credential_key: CredentialKey,
    ) -> Result<Credentials, EndpointExplorationError> {
        match self
            .credential_provider
            .get_credentials(credential_key.clone())
            .await
        {
            Ok(credentials) => {
                if !Self::valid_credentials(credentials.clone()) {
                    return Err(EndpointExplorationError::Other {
                        details: format!(
                            "vault does not have a valid entry at {}",
                            credential_key.to_key_str()
                        ),
                    });
                }

                Ok(credentials)
            }
            Err(err) => Err(EndpointExplorationError::MissingCredentials {
                key: credential_key.to_key_str(),
                cause: err.to_string(),
            }),
        }
    }

    async fn set_credentials(
        &self,
        credential_key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        match self
            .credential_provider
            .set_credentials(credential_key.clone(), credentials)
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => Err(EndpointExplorationError::SetCredentials {
                key: credential_key.to_key_str(),
                cause: err.to_string(),
            }),
        }
    }

    pub fn new(credential_provider: Arc<dyn CredentialProvider>) -> Self {
        Self {
            credential_provider,
        }
    }

    pub async fn is_ready(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        let credential_key = SITEWIDE_BMC_ROOT_CREDENTIAL_KEY;
        if let Some(e) = self.get_credentials(credential_key.clone()).await.err() {
            let credential_key_str = credential_key.to_key_str();
            metrics.increment_credential_missing(credential_key_str.clone());
            return Err(EndpointExplorationError::MissingCredentials {
                key: credential_key.to_key_str(),
                cause: e.to_string(),
            });
        }

        Ok(())
    }

    pub async fn get_sitewide_bmc_root_credentials(
        &self,
    ) -> Result<Credentials, EndpointExplorationError> {
        self.get_credentials(SITEWIDE_BMC_ROOT_CREDENTIAL_KEY).await
    }

    pub async fn get_default_hardware_dpu_bmc_root_credentials(
        &self,
    ) -> Result<Credentials, EndpointExplorationError> {
        Ok(Credentials::UsernamePassword {
            username: "root".into(),
            password: "0penBmc".into(),
        })
    }

    pub async fn get_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
    ) -> Result<Credentials, EndpointExplorationError> {
        let bmc_root_credential_key = get_bmc_root_credential_key(bmc_mac_address);
        self.get_credentials(bmc_root_credential_key).await
    }

    pub async fn set_bmc_root_credentials(
        &self,
        bmc_mac_address: MacAddress,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let bmc_root_credential_key = get_bmc_root_credential_key(bmc_mac_address);
        self.set_credentials(bmc_root_credential_key, credentials)
            .await
    }
}
