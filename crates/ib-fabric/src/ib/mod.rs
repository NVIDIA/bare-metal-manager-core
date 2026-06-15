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
use carbide_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
pub use iface::{
    Filter, GetPartitionOptions, IBFabric, IBFabricConfig, IBFabricManager, IBFabricVersions,
};
pub use model::ib::{IBMtu, IBRateLimit, IBServiceLevel};

use crate::config;
use crate::errors::IbError;

mod disable;
mod iface;
mod rest;
mod ufmclient;

#[cfg(feature = "test-support")]
mod mock;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub enum IBFabricManagerType {
    #[default]
    Disable,
    #[cfg(feature = "test-support")]
    Mock,
    Rest,
}

pub struct IBFabricManagerImpl {
    config: IBFabricManagerConfig,
    credential_reader: Arc<dyn CredentialReader>,
    #[cfg(feature = "test-support")]
    mock_fabric: Arc<mock::MockIBFabric>,
    disable_fabric: Arc<dyn IBFabric>,
}

impl IBFabricManagerImpl {
    /// Gets the mocked fabric manager that is used within tests
    #[cfg(feature = "test-support")]
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
            max_partition_per_tenant: config::IBFabricConfig::default_max_partition_per_tenant(),
            mtu: IBMtu::default(),
            rate_limit: IBRateLimit::default(),
            service_level: IBServiceLevel::default(),
            fabric_manager_run_interval:
                config::IBFabricConfig::default_fabric_monitor_run_interval(),
        }
    }
}

pub fn create_ib_fabric_manager(
    credential_reader: Arc<dyn CredentialReader>,
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

    #[cfg(feature = "test-support")]
    let mock_fabric = Arc::new(mock::MockIBFabric::new());

    let disable_fabric = Arc::new(disable::DisableIBFabric {});

    Ok(IBFabricManagerImpl {
        credential_reader,
        config,
        #[cfg(feature = "test-support")]
        mock_fabric,
        disable_fabric,
    })
}

#[async_trait]
impl IBFabricManager for IBFabricManagerImpl {
    fn get_config(&self) -> IBFabricManagerConfig {
        self.config.clone()
    }

    async fn new_client(&self, fabric_name: &str) -> Result<Arc<dyn IBFabric>, IbError> {
        match self.config.manager_type {
            IBFabricManagerType::Disable => Ok(self.disable_fabric.clone()),
            #[cfg(feature = "test-support")]
            IBFabricManagerType::Mock => Ok(self.mock_fabric.clone()),
            IBFabricManagerType::Rest => {
                let endpoint = self
                    .config
                    .endpoints
                    .get(fabric_name)
                    .and_then(|fabric_endpoints| fabric_endpoints.first())
                    .ok_or_else(|| IbError::NotFoundError {
                        kind: "ib_fabric_endpoint",
                        id: fabric_name.to_string(),
                    })?;

                let key = &CredentialKey::UfmAuth {
                    fabric: fabric_name.to_string(),
                };
                let credentials = self
                    .credential_reader
                    .get_credentials(key)
                    .await
                    .map_err(|err| {
                        IbError::internal(format!(
                            "Cannot create UFM client: secret manager error: {err}"
                        ))
                    })?
                    .ok_or_else(|| {
                        IbError::internal(format!(
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

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use carbide_secrets::SecretsError;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::*;

    struct NoopCredentialReader;

    #[async_trait]
    impl CredentialReader for NoopCredentialReader {
        async fn get_credentials(
            &self,
            _key: &CredentialKey,
        ) -> Result<Option<Credentials>, SecretsError> {
            Ok(None)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ManagerCase {
        ValidDisabled,
        EmptyEndpointList,
        MultipleEndpoints,
        InvalidEndpoint,
    }

    #[derive(Debug, PartialEq)]
    struct ManagerConfigSummary {
        endpoint_count: usize,
        manager_type: &'static str,
        max_partition_per_tenant: i32,
        allow_insecure_fabric_configuration: bool,
        fabric_manager_run_interval_secs: u64,
    }

    fn credential_reader() -> Arc<dyn CredentialReader> {
        Arc::new(NoopCredentialReader)
    }

    fn manager_type_name(manager_type: IBFabricManagerType) -> &'static str {
        match manager_type {
            IBFabricManagerType::Disable => "disable",
            #[cfg(feature = "test-support")]
            IBFabricManagerType::Mock => "mock",
            IBFabricManagerType::Rest => "rest",
        }
    }

    fn summarize_manager_config(config: IBFabricManagerConfig) -> ManagerConfigSummary {
        ManagerConfigSummary {
            endpoint_count: config.endpoints.len(),
            manager_type: manager_type_name(config.manager_type),
            max_partition_per_tenant: config.max_partition_per_tenant,
            allow_insecure_fabric_configuration: config.allow_insecure_fabric_configuration,
            fabric_manager_run_interval_secs: config.fabric_manager_run_interval.as_secs(),
        }
    }

    fn config_for_case(case: ManagerCase) -> IBFabricManagerConfig {
        let mut config = IBFabricManagerConfig::default();
        match case {
            ManagerCase::ValidDisabled => {
                config.endpoints.insert(
                    "fabric-a".to_string(),
                    vec!["https://127.0.0.1:443".to_string()],
                );
            }
            ManagerCase::EmptyEndpointList => {
                config.endpoints.insert("fabric-a".to_string(), vec![]);
            }
            ManagerCase::MultipleEndpoints => {
                config.endpoints.insert(
                    "fabric-a".to_string(),
                    vec![
                        "https://127.0.0.1:443".to_string(),
                        "https://127.0.0.2:443".to_string(),
                    ],
                );
            }
            ManagerCase::InvalidEndpoint => {
                config
                    .endpoints
                    .insert("fabric-a".to_string(), vec!["not a uri".to_string()]);
            }
        }
        config
    }

    fn create_manager(case: ManagerCase) -> Result<ManagerConfigSummary, &'static str> {
        create_ib_fabric_manager(credential_reader(), config_for_case(case))
            .map(|manager| summarize_manager_config(manager.get_config()))
            .map_err(manager_error_kind)
    }

    fn manager_error_kind(error: eyre::Report) -> &'static str {
        let error = error.to_string();
        if error.contains("Exactly 1 endpoint") {
            "endpoint-count"
        } else if error.contains("not a valid HTTP(S) URI") {
            "invalid-uri"
        } else {
            "unknown"
        }
    }

    #[test]
    fn default_manager_config_uses_disabled_defaults() {
        assert_eq!(
            summarize_manager_config(IBFabricManagerConfig::default()),
            ManagerConfigSummary {
                endpoint_count: 0,
                manager_type: "disable",
                max_partition_per_tenant: config::IBFabricConfig::default_max_partition_per_tenant(
                ),
                allow_insecure_fabric_configuration: false,
                fabric_manager_run_interval_secs: 60,
            }
        );
    }

    #[test]
    fn validates_manager_endpoints() {
        scenarios!(create_manager:
            "valid config" {
                ManagerCase::ValidDisabled => Yields(ManagerConfigSummary {
                    endpoint_count: 1,
                    manager_type: "disable",
                    max_partition_per_tenant: config::IBFabricConfig::default_max_partition_per_tenant(),
                    allow_insecure_fabric_configuration: false,
                    fabric_manager_run_interval_secs: 60,
                }),
            }

            "invalid endpoints" {
                ManagerCase::EmptyEndpointList => FailsWith("endpoint-count"),
                ManagerCase::MultipleEndpoints => FailsWith("endpoint-count"),
                ManagerCase::InvalidEndpoint => FailsWith("invalid-uri"),
            }
        );
    }

    #[tokio::test]
    async fn disabled_manager_returns_disabled_client() {
        let manager =
            create_ib_fabric_manager(credential_reader(), IBFabricManagerConfig::default())
                .unwrap();
        let client = manager.new_client("fabric-a").await.unwrap();

        assert_eq!(
            client.get_fabric_config().await.unwrap_err().to_string(),
            "Failed to call IBFabricManager: ib fabric is disabled"
        );
    }
}
