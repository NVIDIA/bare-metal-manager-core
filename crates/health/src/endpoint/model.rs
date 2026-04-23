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

use std::borrow::Cow;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use url::Url;

use crate::HealthError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait CredentialProvider: Send + Sync {
    fn fetch_credentials<'a>(
        &'a self,
        endpoint: &'a BmcAddr,
    ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>>;
}

#[derive(Clone)]
pub struct FixedCredentialProvider {
    credentials: BmcCredentials,
}

impl CredentialProvider for FixedCredentialProvider {
    fn fetch_credentials<'a>(
        &'a self,
        _endpoint: &'a BmcAddr,
    ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
        let credentials = self.credentials.clone();
        Box::pin(async move { Ok(credentials) })
    }
}

#[derive(Clone)]
pub struct BmcEndpoint {
    pub addr: BmcAddr,
    pub metadata: Option<EndpointMetadata>,
    pub rack_id: Option<RackId>,
    pub(crate) credentials: Arc<RwLock<BmcCredentials>>,
    pub(crate) provider: Arc<dyn CredentialProvider>,
}

impl BmcEndpoint {
    pub fn hash_key(&self) -> Cow<'static, str> {
        Cow::Owned(
            self.rack_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| self.addr.mac.to_string()),
        )
    }

    pub fn with_fixed_credentials(
        addr: BmcAddr,
        credentials: BmcCredentials,
        metadata: Option<EndpointMetadata>,
        rack_id: Option<RackId>,
    ) -> Self {
        let provider = Arc::new(FixedCredentialProvider {
            credentials: credentials.clone(),
        });

        Self {
            addr,
            metadata,
            rack_id,
            credentials: Arc::new(RwLock::new(credentials)),
            provider,
        }
    }

    pub fn log_identity(&self) -> Cow<'_, str> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => Cow::Owned(machine.machine_id.to_string()),
            Some(EndpointMetadata::Switch(switch)) => Cow::Borrowed(&switch.serial),
            None => Cow::Owned(self.addr.mac.to_string()),
        }
    }

    pub fn credentials(&self) -> BmcCredentials {
        self.credentials.read().expect("lock poisoned").to_owned()
    }

    pub async fn refresh(&self) -> Result<BmcCredentials, HealthError> {
        let credentials = self.provider.fetch_credentials(&self.addr).await?;
        self.credentials
            .write()
            .map(|mut current| *current = credentials.clone())
            .expect("lock poisoned");
        Ok(credentials)
    }
}

#[derive(Clone, Debug)]
pub enum EndpointMetadata {
    Machine(MachineData),
    Switch(SwitchData),
}

impl EndpointMetadata {
    pub fn serial_number(&self) -> Option<&str> {
        match self {
            EndpointMetadata::Machine(machine) => machine.machine_serial.as_deref(),
            EndpointMetadata::Switch(switch) => Some(switch.serial.as_str()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MachineData {
    pub machine_id: MachineId,
    pub machine_serial: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SwitchData {
    pub serial: String,
}

#[derive(Clone)]
pub enum BmcCredentials {
    UsernamePassword {
        username: String,
        password: Option<String>,
    },
    SessionToken {
        token: String,
    },
}

#[derive(Clone, Debug)]
pub struct BmcAddr {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub mac: MacAddress,
}

impl BmcAddr {
    pub fn to_url(&self) -> Result<Url, url::ParseError> {
        let scheme = if self.port.is_some_and(|v| v == 80) {
            "http"
        } else {
            "https"
        };
        let mut url = Url::parse(&format!("{}://{}", scheme, self.ip))?;
        let _ = url.set_port(self.port);
        Ok(url)
    }
}

impl From<BmcCredentials> for nv_redfish::bmc_http::BmcCredentials {
    fn from(value: BmcCredentials) -> Self {
        match value {
            BmcCredentials::UsernamePassword { username, password } => {
                nv_redfish::bmc_http::BmcCredentials::username_password(username, password)
            }
            BmcCredentials::SessionToken { token } => {
                nv_redfish::bmc_http::BmcCredentials::token(token)
            }
        }
    }
}

pub trait EndpointSource: Send + Sync {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>>;
}
