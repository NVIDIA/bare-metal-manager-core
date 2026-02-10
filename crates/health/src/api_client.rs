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

use std::net::IpAddr;
use std::sync::Arc;

use forge_tls::client_config::ClientCert;
use rpc::forge::{BmcRequestType, MachineSearchConfig, UserRoles};
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use url::Url;

use crate::HealthError;
use crate::endpoint::{
    BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, EndpointMetadata, EndpointSource, MachineData,
    SwitchData,
};

#[derive(Clone)]
pub struct ApiClientWrapper {
    client: ForgeApiClient,
    nmxt_enabled: bool,
}

impl ApiClientWrapper {
    pub fn new(
        root_ca: String,
        client_cert: String,
        client_key: String,
        api_url: &Url,
        nmxt_enabled: bool,
    ) -> Self {
        let client_config = ForgeClientConfig::new(
            root_ca,
            Some(ClientCert {
                cert_path: client_cert,
                key_path: client_key,
            }),
        );
        let api_config = ApiConfig::new(api_url.as_str(), &client_config);

        let client = ForgeApiClient::new(&api_config);

        Self {
            client,
            nmxt_enabled,
        }
    }

    pub async fn fetch_bmc_hosts(&self) -> Result<Vec<Arc<BmcEndpoint>>, HealthError> {
        let machine_ids = self
            .client
            .find_machine_ids(MachineSearchConfig {
                include_dpus: true,
                ..Default::default()
            })
            .await
            .map_err(HealthError::ApiInvocationError)?;

        tracing::info!("Found {} machines", machine_ids.machine_ids.len(),);

        let mut endpoints = Vec::new();

        for ids_chunk in machine_ids.machine_ids.chunks(100) {
            let request = ::rpc::forge::MachinesByIdsRequest {
                machine_ids: Vec::from(ids_chunk),
                ..Default::default()
            };
            let machines = self
                .client
                .find_machines_by_ids(request)
                .await
                .map_err(HealthError::ApiInvocationError)?;
            tracing::debug!(
                "Fetched details for {} machines with chunk size of 100",
                machines.machines.len(),
            );

            for machine in machines.machines {
                if let Some(endpoint) = self.extract_bmc_endpoint(&machine).await {
                    endpoints.push(Arc::new(endpoint));
                }
            }
        }

        // fetch switch endpoints for nmxt collection if enabled
        if self.nmxt_enabled {
            let switch_request = rpc::forge::SwitchQuery {
                name: None,
                switch_id: None,
            };

            match self.client.find_switches(switch_request).await {
                Ok(response) => {
                    let switch_endpoints: Vec<Arc<BmcEndpoint>> = response
                        .switches
                        .into_iter()
                        .filter_map(|s| {
                            let bmc = s.bmc_info?;
                            let ip = bmc.ip.as_ref()?.parse().ok()?;
                            let mac = bmc.mac?;
                            let serial = s.config?.name;

                            Some(Arc::new(BmcEndpoint {
                                addr: BmcAddr {
                                    ip,
                                    port: bmc.port.map(|p| p as u16),
                                    mac,
                                },
                                credentials: BmcCredentials {
                                    username: String::new(),
                                    password: String::new(),
                                },
                                metadata: Some(EndpointMetadata::Switch(SwitchData { serial })),
                            }))
                        })
                        .collect();

                    tracing::debug!(count = switch_endpoints.len(), "Fetched switch endpoints");
                    endpoints.extend(switch_endpoints);
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "Failed to fetch switch endpoints");
                }
            }
        }

        tracing::info!("Prepared total {} endpoints", endpoints.len());

        Ok(endpoints)
    }

    async fn extract_bmc_endpoint(&self, machine: &rpc::forge::Machine) -> Option<BmcEndpoint> {
        let bmc_info = machine.bmc_info.as_ref()?;
        let ip_str = bmc_info.ip.as_ref()?;
        let ip = ip_str.parse::<IpAddr>().ok()?;
        let mac = bmc_info.mac.as_ref()?.clone();
        let port = bmc_info.port.map(|v| v.try_into().unwrap_or(443));

        let addr = BmcAddr { ip, port, mac };
        let credentials = self.get_bmc_credentials(&addr).await.ok()?;

        Some(BmcEndpoint {
            addr,
            credentials,
            metadata: machine
                .id
                .zip(machine.discovery_info.clone())
                .map(|(machine_id, info)| {
                    EndpointMetadata::Machine(MachineData {
                        machine_id,
                        machine_serial: info.dmi_data.map(|dmi| dmi.chassis_serial),
                    })
                }),
        })
    }

    async fn get_bmc_credentials(&self, endpoint: &BmcAddr) -> Result<BmcCredentials, HealthError> {
        let request = rpc::forge::BmcMetaDataGetRequest {
            machine_id: None,
            bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
                ip_address: endpoint.ip.to_string(),
                mac_address: Some(endpoint.mac.clone()),
            }),
            role: UserRoles::Administrator.into(),
            request_type: BmcRequestType::Redfish.into(),
        };

        let response = self
            .client
            .get_bmc_meta_data(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(BmcCredentials {
            username: response.user,
            password: response.password,
        })
    }

    pub async fn submit_health_report(
        &self,
        machine_id: &carbide_uuid::machine::MachineId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let request = rpc::forge::HardwareHealthReport {
            machine_id: Some(*machine_id),
            report: Some(report.into()),
        };

        self.client
            .record_hardware_health_report(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(())
    }
}

impl EndpointSource for ApiClientWrapper {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
        Box::pin(self.fetch_bmc_hosts())
    }
}
