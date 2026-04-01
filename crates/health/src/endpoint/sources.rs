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

use std::str::FromStr;
use std::sync::Arc;

use carbide_uuid::rack::RackId;
use mac_address::MacAddress;

use crate::HealthError;
use crate::config::StaticBmcEndpoint;
use crate::endpoint::{
    BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, EndpointMetadata, EndpointSource, MachineData,
    SwitchData,
};

pub struct StaticEndpointSource {
    endpoints: Vec<Arc<BmcEndpoint>>,
}

impl StaticEndpointSource {
    pub fn new(endpoints: Vec<BmcEndpoint>) -> Self {
        Self {
            endpoints: endpoints.into_iter().map(Arc::new).collect(),
        }
    }

    pub fn from_config(configs: &[StaticBmcEndpoint]) -> Self {
        let endpoints = configs
            .iter()
            .filter_map(|cfg| {
                let ip = match cfg.ip.parse() {
                    Ok(ip) => ip,
                    Err(error) => {
                        tracing::warn!(?error, ip = ?cfg.ip, "Invalid IP in static endpoint config");
                        return None;
                    }
                };

                let mac = MacAddress::from_str(&cfg.mac).ok()?;

                let metadata = if let Some(serial) = &cfg.switch_serial {
                    Some(EndpointMetadata::Switch(SwitchData {
                        serial: serial.clone(),
                    }))
                } else if let Some(machine_id_str) = &cfg.machine_id {
                    match machine_id_str.parse() {
                        Ok(machine_id) => Some(EndpointMetadata::Machine(MachineData {
                            machine_id,
                            machine_serial: None,
                        })),
                        Err(error) => {
                            tracing::warn!(?error, machine_id = ?machine_id_str, "Invalid machine_id in static endpoint config");
                            None
                        }
                    }
                } else {
                    None
                };

                let endpoint = BmcEndpoint::with_fixed_credentials(
                    BmcAddr {
                        ip,
                        port: cfg.port,
                        mac,
                    },
                    BmcCredentials::UsernamePassword {
                        username: cfg.username.clone(),
                        password: cfg.password.clone(),
                    },
                    metadata,
                    cfg.rack_id.as_ref().map(|id| RackId::new(id.as_str())),
                );

                Some(Arc::new(endpoint))
            })
            .collect();

        Self { endpoints }
    }
}

impl EndpointSource for StaticEndpointSource {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
        Box::pin(async move { Ok(self.endpoints.clone()) })
    }
}

pub struct CompositeEndpointSource {
    sources: Vec<Arc<dyn EndpointSource>>,
}

impl CompositeEndpointSource {
    pub fn new(sources: Vec<Arc<dyn EndpointSource>>) -> Self {
        Self { sources }
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

impl EndpointSource for CompositeEndpointSource {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
        Box::pin(async move {
            let mut all = Vec::new();

            for src in &self.sources {
                let mut endpoints = src.fetch_bmc_hosts().await?;
                all.append(&mut endpoints);
            }

            Ok(all)
        })
    }
}
