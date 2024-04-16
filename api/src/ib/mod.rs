/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};

pub use self::iface::Filter;
pub use self::iface::IBFabric;
pub use self::iface::IBFabricManager;
pub use self::iface::IBFabricVersions;
use crate::cfg;
use crate::CarbideError;

mod disable;
mod iface;
mod mock;
mod rest;
mod ufmclient;

pub mod types;

pub const DEFAULT_IB_FABRIC_NAME: &str = "default";

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub enum IBFabricManagerType {
    #[default]
    Disable,
    Mock,
    Rest,
}

pub struct IBFabricManagerImpl<C> {
    config: IBFabricManagerConfig,
    credential_provider: Arc<C>,
    mock_fabric: Arc<dyn IBFabric>,
    disable_fabric: Arc<dyn IBFabric>,
}

#[derive(Clone)]
pub struct IBFabricManagerConfig {
    pub manager_type: IBFabricManagerType,
    pub max_partition_per_tenant: i32,
}

impl Default for IBFabricManagerConfig {
    fn default() -> Self {
        IBFabricManagerConfig {
            manager_type: IBFabricManagerType::default(),
            max_partition_per_tenant: cfg::IBFabricConfig::default_max_partition_per_tenant(),
        }
    }
}

pub fn create_ib_fabric_manager<C: CredentialProvider + 'static>(
    credential_provider: Arc<C>,
    config: IBFabricManagerConfig,
) -> IBFabricManagerImpl<C> {
    let mock_fabric = Arc::new(mock::MockIBFabric {
        ibsubnets: Arc::new(Mutex::new(HashMap::new())),
        ibports: Arc::new(Mutex::new(HashMap::new())),
    });

    let disable_fabric = Arc::new(disable::DisableIBFabric {});

    IBFabricManagerImpl {
        credential_provider,
        config,
        mock_fabric,
        disable_fabric,
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> IBFabricManager for IBFabricManagerImpl<C> {
    fn get_config(&self) -> IBFabricManagerConfig {
        self.config.clone()
    }

    async fn connect(&self, fabric_name: &str) -> Result<Arc<dyn IBFabric>, CarbideError> {
        match self.config.manager_type {
            IBFabricManagerType::Disable => Ok(self.disable_fabric.clone()),
            IBFabricManagerType::Mock => Ok(self.mock_fabric.clone()),
            IBFabricManagerType::Rest => {
                let credentials = self
                    .credential_provider
                    .get_credentials(CredentialKey::UfmAuth {
                        fabric: fabric_name.to_string(),
                    })
                    .await
                    .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                        Ok(vaultrs::error::ClientError::APIError { code: 404, .. }) => {
                            CarbideError::GenericError(format!(
                                "Vault key not found: ufm/{}/token",
                                fabric_name
                            ))
                        }
                        Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                        Err(err) => CarbideError::IBFabricError(format!(
                            "Error getting credentials for Ufm: {:?}",
                            err
                        )),
                    })?;
                let (address, token) = match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                };

                rest::connect(&address, &token).await
            }
        }
    }
}
