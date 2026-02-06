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

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use forge_tls::client_config::ClientCert;
use rpc::forge::{BmcRequestType, MachineSearchConfig, UserRoles};
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use url::Url;

use crate::HealthError;
use crate::config::StaticBmcEndpoint;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub struct BmcEndpoint {
    pub addr: BmcAddr,
    pub credentials: BmcCredentials,
    pub metadata: Option<EndpointMetadata>,
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
    pub mac: String,
}

impl BmcAddr {
    pub fn hash_key(&self) -> &str {
        &self.mac
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

pub trait HealthReportSink: Send + Sync {
    fn submit_health_report<'a>(
        &'a self,
        machine_id: &'a MachineId,
        report: health_report::HealthReport,
    ) -> BoxFuture<'a, Result<(), HealthError>>;
}

pub struct CompositeHealthReportSink {
    sinks: Vec<Arc<dyn HealthReportSink>>,
}

impl CompositeHealthReportSink {
    pub fn new(sinks: Vec<Arc<dyn HealthReportSink>>) -> Self {
        Self { sinks }
    }
}

impl HealthReportSink for CompositeHealthReportSink {
    fn submit_health_report<'a>(
        &'a self,
        machine_id: &'a MachineId,
        report: health_report::HealthReport,
    ) -> BoxFuture<'a, Result<(), HealthError>> {
        Box::pin(async move {
            for sink in &self.sinks {
                if let Err(e) = sink.submit_health_report(machine_id, report.clone()).await {
                    tracing::warn!(error=?e, "health report sink failed");
                }
            }
            Ok(())
        })
    }
}

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

impl HealthReportSink for ApiClientWrapper {
    fn submit_health_report<'a>(
        &'a self,
        machine_id: &'a MachineId,
        report: health_report::HealthReport,
    ) -> BoxFuture<'a, Result<(), HealthError>> {
        Box::pin(self.submit_health_report(machine_id, report))
    }
}

pub struct ConsleHealthSink {}

impl HealthReportSink for ConsleHealthSink {
    fn submit_health_report<'a>(
        &'a self,
        machine_id: &'a MachineId,
        report: health_report::HealthReport,
    ) -> BoxFuture<'a, Result<(), HealthError>> {
        tracing::info!(
            "Health report for machine {machine_id:?} has {} success and {} alerts",
            report.successes.len(),
            report.alerts.len()
        );
        for alert in report.alerts {
            tracing::warn!(machine_id=?machine_id, alert=?alert, "Health report alert");
        }
        Box::pin(async { Ok(()) })
    }
}

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
                    Err(e) => {
                        tracing::warn!(error=?e, ip=?cfg.ip, "Invalid IP in static endpoint config");
                        return None;
                    }
                };

                Some(Arc::new(BmcEndpoint {
                    addr: BmcAddr {
                        ip,
                        port: cfg.port,
                        mac: cfg.mac.clone(),
                    },
                    credentials: BmcCredentials {
                        username: cfg.username.clone(),
                        password: cfg.password.clone(),
                    },
                    metadata: None,
                }))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_endpoint(mac: &str) -> BmcEndpoint {
        BmcEndpoint {
            addr: BmcAddr {
                ip: "10.0.0.1".parse().unwrap(),
                port: Some(443),
                mac: mac.to_string(),
            },
            credentials: BmcCredentials {
                username: "admin".to_string(),
                password: "password".to_string(),
            },
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_static_endpoint_source_shares_arc_data() {
        let endpoints = vec![
            make_test_endpoint("00:11:22:33:44:55"),
            make_test_endpoint("aa:bb:cc:dd:ee:ff"),
        ];
        let source = StaticEndpointSource::new(endpoints);

        let first = source.fetch_bmc_hosts().await.unwrap();
        let second = source.fetch_bmc_hosts().await.unwrap();

        // Verify we get the same number of endpoints.
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);

        // Verify the Arcs point to the same underlying data,
        // since we're not cloning anymore.
        assert!(Arc::ptr_eq(&first[0], &second[0]));
        assert!(Arc::ptr_eq(&first[1], &second[1]));
    }

    #[tokio::test]
    async fn test_composite_endpoint_source_preserves_arc_sharing() {
        let endpoints1 = vec![make_test_endpoint("00:11:22:33:44:55")];
        let endpoints2 = vec![make_test_endpoint("aa:bb:cc:dd:ee:ff")];

        let source1 = Arc::new(StaticEndpointSource::new(endpoints1));
        let source2 = Arc::new(StaticEndpointSource::new(endpoints2));

        let composite = CompositeEndpointSource::new(vec![source1.clone(), source2.clone()]);

        let composite_result = composite.fetch_bmc_hosts().await.unwrap();
        let source1_result = source1.fetch_bmc_hosts().await.unwrap();
        let source2_result = source2.fetch_bmc_hosts().await.unwrap();

        // Verify composite returns endpoints from both sources.
        assert_eq!(composite_result.len(), 2);

        // Verify the Arcs point to the same data as the original sources,
        // since we're not cloning anymore.
        assert!(Arc::ptr_eq(&composite_result[0], &source1_result[0]));
        assert!(Arc::ptr_eq(&composite_result[1], &source2_result[0]));
    }
}
