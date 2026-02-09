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

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
pub use model::ib::{IBMtu, IBRateLimit, IBServiceLevel};

#[cfg(test)]
pub use self::iface::Filter;
pub use self::iface::{
    GetPartitionOptions, IBFabric, IBFabricConfig, IBFabricManager, IBFabricVersions,
};
use crate::{CarbideError, cfg};

mod disable;
mod iface;
mod rest;
mod ufmclient;

#[cfg(test)]
mod mock;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub enum IBFabricManagerType {
    #[default]
    Disable,
    #[cfg(test)]
    Mock,
    Rest,
}

pub struct IBFabricManagerImpl {
    config: IBFabricManagerConfig,
    credential_provider: Arc<dyn CredentialProvider>,
    #[cfg(test)]
    mock_fabric: Arc<mock::MockIBFabric>,
    disable_fabric: Arc<dyn IBFabric>,
}

impl IBFabricManagerImpl {
    /// Gets the mocked fabric manager that is used within tests
    #[cfg(test)]
    pub fn get_mock_manager(&self) -> Arc<mock::MockIBFabric> {
        self.mock_fabric.clone()
    }
}

#[derive(Clone)]
pub struct IBFabricManagerConfig {
    /// List of endpoint per fabric
    pub endpoints: HashMap<String, Vec<String>>,
    pub manager_type: IBFabricManagerType,
    pub max_partition_per_tenant: i32,
    pub mtu: IBMtu,
    pub rate_limit: IBRateLimit,
    pub service_level: IBServiceLevel,
    pub allow_insecure_fabric_configuration: bool,
    /// The interval at which ib fabric monitor runs
    pub fabric_manager_run_interval: std::time::Duration,
}

impl Default for IBFabricManagerConfig {
    fn default() -> Self {
        IBFabricManagerConfig {
            allow_insecure_fabric_configuration: false,
            endpoints: HashMap::default(),
            manager_type: IBFabricManagerType::default(),
            max_partition_per_tenant: cfg::file::IBFabricConfig::default_max_partition_per_tenant(),
            mtu: IBMtu::default(),
            rate_limit: IBRateLimit::default(),
            service_level: IBServiceLevel::default(),
            fabric_manager_run_interval:
                cfg::file::IBFabricConfig::default_fabric_monitor_run_interval(),
        }
    }
}

pub fn create_ib_fabric_manager(
    credential_provider: Arc<dyn CredentialProvider>,
    config: IBFabricManagerConfig,
) -> Result<IBFabricManagerImpl, eyre::Report> {
    for (fabric_id, endpoints) in config.endpoints.iter() {
        if endpoints.len() != 1 {
            return Err(eyre::eyre!(
                "Exactly 1 endpoint can be specified for each IB fabric. Fabric \"{fabric_id}\" specifies endpoints: {}",
                endpoints.clone().join(",")
            ));
        }

        for ep in endpoints.iter() {
            if ep.parse::<http::Uri>().is_err() {
                return Err(eyre::eyre!(
                    "Endpoint \"{ep}\" for fabric \"{fabric_id}\" is not a valid HTTP(S) URI. Expected format is https://1.2.3.4:443 ?"
                ));
            }
        }
    }

    #[cfg(test)]
    let mock_fabric = Arc::new(mock::MockIBFabric::new());
    let disable_fabric = Arc::new(disable::DisableIBFabric {});

    Ok(IBFabricManagerImpl {
        credential_provider,
        config,
        #[cfg(test)]
        mock_fabric,
        disable_fabric,
    })
}

#[async_trait]
impl IBFabricManager for IBFabricManagerImpl {
    fn get_config(&self) -> IBFabricManagerConfig {
        self.config.clone()
    }

    async fn new_client(&self, fabric_name: &str) -> Result<Arc<dyn IBFabric>, CarbideError> {
        match self.config.manager_type {
            IBFabricManagerType::Disable => Ok(self.disable_fabric.clone()),
            #[cfg(test)]
            IBFabricManagerType::Mock => Ok(self.mock_fabric.clone()),
            IBFabricManagerType::Rest => {
                let endpoint = self
                    .config
                    .endpoints
                    .get(fabric_name)
                    .and_then(|fabric_endpoints| fabric_endpoints.first())
                    .ok_or_else(|| CarbideError::NotFoundError {
                        kind: "ib_fabric_endpoint",
                        id: fabric_name.to_string(),
                    })?;

                let key = &CredentialKey::UfmAuth {
                    fabric: fabric_name.to_string(),
                };
                let credentials = self
                    .credential_provider
                    .get_credentials(key)
                    .await
                    .map_err(|err| {
                        CarbideError::internal(format!(
                            "Cannot create UFM client: secret manager error: {err}"
                        ))
                    })?
                    .ok_or_else(|| {
                        CarbideError::internal(format!(
                            "Cannot create UFM client: vault key not found or token is not set: {}",
                            key.to_key_str()
                        ))
                    })?;

                let (_deprecated_address, token) = match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                };

                rest::new_client(endpoint, &token)
            }
        }
    }
}
