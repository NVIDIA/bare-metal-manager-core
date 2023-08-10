/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, CredentialType, Credentials};
use libredfish::{Endpoint, Redfish, RedfishError};

use crate::db::bmc_metadata::UserRoles;

#[derive(thiserror::Error, Debug)]
pub enum RedfishClientCreationError {
    #[error("Failed to look up credentials {0}")]
    MissingCredentials(eyre::Report),
    #[error("Failed redfish request {0}")]
    RedfishError(RedfishError),
    #[error("Failed subtask to create redfish client  {0}")]
    SubtaskError(tokio::task::JoinError),
}

#[derive(Debug, Clone)]
pub enum RedfishCredentialType {
    HardwareDefault,
    SiteDefault,
    Machine { machine_id: String },
}

/// Allows to create Redfish clients for a certain Redfish BMC endpoint
#[async_trait]
pub trait RedfishClientPool: Send + Sync + 'static {
    /// Creates a new Redfish client for a Machines BMC
    /// `host` is the IP address or hostname of the BMC
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_type: RedfishCredentialType,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;
}

#[derive(Debug)]
pub struct RedfishClientPoolImpl<C> {
    pool: libredfish::RedfishClientPool,
    credential_provider: Arc<C>,
}

impl<C: CredentialProvider + 'static> RedfishClientPoolImpl<C> {
    pub fn new(credential_provider: Arc<C>, pool: libredfish::RedfishClientPool) -> Self {
        RedfishClientPoolImpl {
            credential_provider,
            pool,
        }
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> RedfishClientPool for RedfishClientPoolImpl<C> {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_type: RedfishCredentialType,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let credentials_key: CredentialKey = match credential_type {
            RedfishCredentialType::HardwareDefault => CredentialKey::DpuRedfish {
                credential_type: CredentialType::HardwareDefault,
            },
            RedfishCredentialType::SiteDefault => CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            RedfishCredentialType::Machine { machine_id } => CredentialKey::Bmc {
                machine_id,
                user_role: UserRoles::Administrator.to_string(),
            },
        };
        let credentials = self
            .credential_provider
            .get_credentials(credentials_key)
            .await
            .map_err(RedfishClientCreationError::MissingCredentials)?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: Some(username),
            password: Some(password),
        };

        // Creating the client performs a HTTP request to determine the BMC vendor
        // The request is blocking - therefore we need to offload it into a ThreadPool
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || pool.create_client(endpoint))
            .await
            .map_err(RedfishClientCreationError::SubtaskError)?
            .map_err(RedfishClientCreationError::RedfishError)
    }
}

#[derive(Debug, Default)]
struct RedfishSimState {
    _hosts: HashMap<String, RedfishSimHostState>,
}

#[derive(Debug, Default)]
struct RedfishSimHostState {}

#[derive(Debug, Default)]
pub struct RedfishSim {
    state: Arc<Mutex<RedfishSimState>>,
}

#[derive(Debug)]
struct RedfishSimClient {
    _state: Arc<Mutex<RedfishSimState>>,
    _credentials_type: RedfishCredentialType,
    _host: String,
    _port: Option<u16>,
}

impl Redfish for RedfishSimClient {
    fn get_power_state(&self) -> Result<libredfish::PowerState, RedfishError> {
        todo!()
    }

    fn power(&self, _action: libredfish::SystemPowerControl) -> Result<(), RedfishError> {
        // TODO: Only return Ok if the machine is actually known
        Ok(())
    }

    fn forge_setup(&self) -> Result<(), RedfishError> {
        Ok(())
    }

    fn lockdown(&self, _target: libredfish::EnabledDisabled) -> Result<(), RedfishError> {
        Ok(())
    }

    fn lockdown_status(&self) -> Result<libredfish::Status, RedfishError> {
        // TODO: Return the real lockdown status based on the simulated host
        Err(RedfishError::NoContent)
    }

    fn setup_serial_console(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn serial_console_status(&self) -> Result<libredfish::Status, RedfishError> {
        todo!()
    }

    fn boot_once(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
        Ok(())
    }

    fn boot_first(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
        todo!()
    }

    fn clear_tpm(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn bios(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    fn pending(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
        todo!()
    }

    fn clear_pending(&self) -> Result<(), RedfishError> {
        todo!()
    }

    fn pcie_devices(&self) -> Result<Vec<libredfish::PCIeDevice>, RedfishError> {
        todo!()
    }
}

#[async_trait]
impl RedfishClientPool for RedfishSim {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        credential_type: RedfishCredentialType,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        Ok(Box::new(RedfishSimClient {
            _state: self.state.clone(),
            _credentials_type: credential_type,
            _host: host.to_string(),
            _port: port,
        }))
    }
}
