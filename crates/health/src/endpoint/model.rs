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
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use url::Url;

use crate::HealthError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub struct BmcEndpoint {
    pub addr: BmcAddr,
    pub credentials: BmcCredentials,
    pub metadata: Option<EndpointMetadata>,
}

impl BmcEndpoint {
    pub fn log_identity(&self) -> Cow<'_, str> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => Cow::Owned(machine.machine_id.to_string()),
            Some(EndpointMetadata::Switch(switch)) => Cow::Borrowed(&switch.serial),
            None => self.addr.hash_key(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum EndpointMetadata {
    Machine(MachineData),
    Switch(SwitchData),
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
pub struct BmcCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct BmcAddr {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub mac: MacAddress,
}

impl BmcAddr {
    pub fn hash_key(&self) -> Cow<'static, str> {
        Cow::Owned(self.mac.to_string())
    }

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

impl From<BmcCredentials> for nv_redfish_bmc_http::BmcCredentials {
    fn from(value: BmcCredentials) -> Self {
        nv_redfish_bmc_http::BmcCredentials::new(value.username, value.password)
    }
}

pub trait EndpointSource: Send + Sync {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>>;
}
