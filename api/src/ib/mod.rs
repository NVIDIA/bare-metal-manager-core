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

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::CarbideError;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};

pub use self::iface::Filter;
pub use self::iface::IBFabric;
pub use self::iface::IBFabricManager;

mod iface;
mod local;
mod rest;
mod ufmclient;

pub mod types;

pub const DEFAULT_IB_FABRIC_NAME: &str = "ib_default";

pub struct IBFabricManagerImpl<C> {
    rest_manager: bool,
    credential_provider: Arc<C>,
    local_fabric: Arc<dyn IBFabric>,
}

pub fn create_ib_fabric_manager<C: CredentialProvider + 'static>(
    credential_provider: Arc<C>,
    rest_manager: bool,
) -> IBFabricManagerImpl<C> {
    let local_fabric = Arc::new(local::LocalIBFabric {
        ibsubnets: Arc::new(Mutex::new(HashMap::new())),
        ibports: Arc::new(Mutex::new(HashMap::new())),
    });
    IBFabricManagerImpl {
        credential_provider,
        rest_manager,
        local_fabric,
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> IBFabricManager for IBFabricManagerImpl<C> {
    async fn connect(&self, fabric_name: String) -> Result<Arc<dyn IBFabric>, CarbideError> {
        if !self.rest_manager {
            Ok(self.local_fabric.clone())
        } else {
            let credentials = self
                .credential_provider
                .get_credentials(CredentialKey::UfmAuth {
                    fabric: fabric_name.clone(),
                })
                .await
                .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                    Ok(vaultrs::error::ClientError::APIError { code, .. }) if code == 404 => {
                        CarbideError::GenericError(format!(
                            "Vault key not found: ufm/{}/token",
                            fabric_name.clone()
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
