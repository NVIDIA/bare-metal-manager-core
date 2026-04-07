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
use std::fmt::Display;
use std::sync::Arc;

use opentelemetry::metrics::Meter;

pub use crate::chained_reader::ChainedCredentialReader;
/// Exposed for `CertificateProvider` usage only. Credential operations should go
/// through `create_credential_manager` instead of using the vault client directly.
pub use crate::forge_vault::{ForgeVaultClient, VaultConfig, create_vault_client};
pub use crate::local_credentials::{
    CredentialSnapshot, EnvCredentialsConfig, FileCredentialsConfig, MachineIdentityConfig,
    UsernamePassword,
};

pub mod certificates;
pub(crate) mod chained_reader;
pub mod credentials;
pub mod forge_vault;
pub mod key_encryption;
pub(crate) mod local_credentials;

use credentials::{CompositeCredentialManager, CredentialManager, CredentialReader};
use local_credentials::{EnvCredentials, FileCredentialsWatcher};

#[derive(Default, Debug, Clone)]
pub struct CredentialConfig {
    pub vault: VaultConfig,
    pub env: EnvCredentialsConfig,
    pub file: FileCredentialsConfig,
}

pub async fn create_credential_manager(
    config: &CredentialConfig,
    meter: Meter,
) -> eyre::Result<Arc<dyn CredentialManager>> {
    let mut readers: Vec<Box<dyn CredentialReader>> = Vec::new();

    if config.env.enabled() {
        readers.push(Box::new(EnvCredentials::new(config.env.clone())?));
    }

    if config.file.enabled() {
        readers.push(Box::new(
            FileCredentialsWatcher::new(config.file.clone()).await?,
        ));
    }

    let vault_client = create_vault_client(&config.vault, meter)?;
    readers.push(Box::new(vault_client.clone()));

    let chained = ChainedCredentialReader::from(readers);
    let composite = CompositeCredentialManager::new(chained, vault_client);
    Ok(Arc::new(composite))
}

#[derive(Debug)]
pub enum SecretsError {
    GenericError(eyre::Report),
}

impl Display for SecretsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretsError::GenericError(report) => {
                write!(f, "Secrets operation failed: {}", report)
            }
        }
    }
}

impl From<eyre::Report> for SecretsError {
    fn from(value: eyre::Report) -> Self {
        SecretsError::GenericError(value)
    }
}

impl From<SecretsError> for eyre::Report {
    fn from(value: SecretsError) -> Self {
        match value {
            SecretsError::GenericError(report) => report,
        }
    }
}
