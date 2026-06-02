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
use std::net::IpAddr;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use carbide_uuid::nvlink::NvLinkDomainId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use mac_address::MacAddress;
use url::Url;

use crate::HealthError;
use crate::bmc::{BmcClient, BoxFuture};

#[derive(Clone)]
pub struct BmcEndpoint {
    pub addr: BmcAddr,
    pub metadata: Option<EndpointMetadata>,
    pub rack_id: Option<RackId>,
    pub bmc: Arc<BmcClient>,
}

impl BmcEndpoint {
    pub fn key(&self) -> String {
        self.addr.mac.to_string()
    }

    pub fn hash_key(&self) -> Cow<'static, str> {
        Cow::Owned(
            self.rack_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| self.key()),
        )
    }

    pub fn log_identity(&self) -> Cow<'_, str> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => Cow::Owned(machine.machine_id.to_string()),
            Some(EndpointMetadata::PowerShelf(power_shelf)) => Cow::Borrowed(&power_shelf.serial),
            Some(EndpointMetadata::Switch(switch)) => Cow::Borrowed(&switch.serial),
            None => Cow::Owned(self.addr.mac.to_string()),
        }
    }

    pub fn bmc(&self) -> &Arc<BmcClient> {
        &self.bmc
    }

    pub fn switch_data(&self) -> Option<&SwitchData> {
        self.metadata.as_ref().and_then(EndpointMetadata::as_switch)
    }
}

#[derive(Clone, Debug)]
pub enum EndpointMetadata {
    Machine(MachineData),
    PowerShelf(PowerShelfData),
    Switch(SwitchData),
}

impl EndpointMetadata {
    pub fn as_switch(&self) -> Option<&SwitchData> {
        match self {
            EndpointMetadata::Switch(switch) => Some(switch),
            _ => None,
        }
    }

    pub fn serial_number(&self) -> Option<&str> {
        match self {
            EndpointMetadata::Machine(machine) => machine.machine_serial.as_deref(),
            EndpointMetadata::PowerShelf(power_shelf) => Some(power_shelf.serial.as_str()),
            EndpointMetadata::Switch(switch) => Some(switch.serial.as_str()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MachineData {
    pub machine_id: MachineId,
    pub machine_serial: Option<String>,
    pub slot_number: Option<i32>,
    pub tray_index: Option<i32>,
    pub nvlink_domain_uuid: Option<NvLinkDomainId>,
}

#[derive(Clone, Debug)]
pub struct PowerShelfData {
    pub id: Option<PowerShelfId>,
    pub serial: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchEndpointRole {
    Bmc,
    Host,
}

#[derive(Clone, Debug)]
pub struct SwitchData {
    pub id: Option<SwitchId>,
    pub serial: String,
    pub slot_number: Option<i32>,
    pub tray_index: Option<i32>,
    pub endpoint_role: SwitchEndpointRole,
    pub is_primary: bool,
    pub nmxt_enabled: bool,
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
