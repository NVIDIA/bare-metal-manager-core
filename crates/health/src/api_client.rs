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

use std::convert::TryFrom;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use carbide_uuid::rack::RackId;
use forge_tls::client_config::ClientCert;
use mac_address::MacAddress;
use rpc::forge::MachineSearchConfig;
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use url::Url;

use crate::HealthError;
use crate::endpoint::{
    BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, CredentialProvider, EndpointMetadata,
    EndpointSource, MachineData, SwitchData,
};

#[derive(Clone)]
pub struct ApiClientWrapper {
    client: ForgeApiClient,
}

#[derive(Clone)]
struct ApiCredentialProvider {
    client: ForgeApiClient,
}

impl CredentialProvider for ApiCredentialProvider {
    fn fetch_credentials<'a>(
        &'a self,
        endpoint: &'a BmcAddr,
    ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
        Box::pin(async move {
            let request = rpc::forge::GetBmcCredentialsRequest {
                mac_addr: endpoint.mac.to_string(),
            };

            self.client
                .get_bmc_credentials(request)
                .await
                .map_err(HealthError::ApiInvocationError)?
                .credentials
                .and_then(|credentials| credentials.r#type)
                .map(Into::into)
                .ok_or_else(|| {
                    HealthError::GenericError("missing BMC credentials in API response".to_string())
                })
        })
    }
}

impl ApiClientWrapper {
    pub fn new(root_ca: String, client_cert: String, client_key: String, api_url: &Url) -> Self {
        let client_config = ForgeClientConfig::new(
            root_ca,
            Some(ClientCert {
                cert_path: client_cert,
                key_path: client_key,
            }),
        );
        let api_config = ApiConfig::new(api_url.as_str(), &client_config);

        let client = ForgeApiClient::new(&api_config);

        Self { client }
    }

    pub async fn fetch_bmc_hosts(&self) -> Result<Vec<Arc<BmcEndpoint>>, HealthError> {
        let mut endpoints = self.fetch_machine_endpoints().await?;
        endpoints.extend(self.fetch_switch_endpoints().await);

        tracing::info!("Prepared total {} endpoints", endpoints.len());

        Ok(endpoints)
    }

    async fn fetch_machine_endpoints(&self) -> Result<Vec<Arc<BmcEndpoint>>, HealthError> {
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
                match self.extract_machine_endpoint(&machine).await {
                    Ok(endpoint) => endpoints.push(Arc::new(endpoint)),
                    Err(error) => tracing::warn!(
                        ?machine,
                        ?error,
                        "Could not add machine endpoint due to error"
                    ),
                }
            }
        }

        Ok(endpoints)
    }

    async fn fetch_switch_endpoints(&self) -> Vec<Arc<BmcEndpoint>> {
        let switch_request = rpc::forge::SwitchQuery {
            name: None,
            switch_id: None,
        };

        match self.client.find_switches(switch_request).await {
            Ok(response) => {
                let mut endpoints = Vec::new();

                for switch in response.switches {
                    match self.extract_switch_endpoint(&switch).await {
                        Ok(endpoint) => endpoints.push(Arc::new(endpoint)),
                        Err(error) => tracing::warn!(
                            ?switch,
                            ?error,
                            "Could not add switch endpoint due to error"
                        ),
                    }
                }

                tracing::debug!(count = endpoints.len(), "Fetched switch endpoints");
                endpoints
            }
            Err(error) => {
                tracing::warn!(?error, "Failed to fetch switch endpoints");
                Vec::new()
            }
        }
    }

    async fn extract_machine_endpoint(
        &self,
        machine: &rpc::forge::Machine,
    ) -> Result<BmcEndpoint, HealthError> {
        let Some(bmc_info) = &machine.bmc_info else {
            return Err(HealthError::GenericError(
                "Could not extract machine endpoint without BMC Info".to_string(),
            ));
        };
        let addr = BmcAddr::try_from(bmc_info)?;
        let metadata = machine
            .id
            .zip(machine.discovery_info.clone())
            .map(|(machine_id, info)| {
                EndpointMetadata::Machine(MachineData {
                    machine_id,
                    machine_serial: info.dmi_data.map(|dmi| dmi.chassis_serial),
                })
            });

        self.endpoint_with_auth(addr, metadata, machine.rack_id.clone())
            .await
    }

    async fn extract_switch_endpoint(
        &self,
        switch: &rpc::forge::Switch,
    ) -> Result<BmcEndpoint, HealthError> {
        let Some(bmc_info) = &switch.bmc_info else {
            return Err(HealthError::GenericError(
                "Could not extract switch endpoint without BMC Info".to_string(),
            ));
        };
        let addr = BmcAddr::try_from(bmc_info)?;
        let serial = switch
            .config
            .as_ref()
            .map(|config| config.name.clone())
            .ok_or(HealthError::GenericError(
                "Switch endpont does not have serial".to_string(),
            ))?;

        self.endpoint_with_auth(
            addr,
            Some(EndpointMetadata::Switch(SwitchData { serial })),
            None,
        )
        .await
    }

    async fn endpoint_with_auth(
        &self,
        addr: BmcAddr,
        metadata: Option<EndpointMetadata>,
        rack_id: Option<RackId>,
    ) -> Result<BmcEndpoint, HealthError> {
        let provider = ApiCredentialProvider {
            client: self.client.clone(),
        };

        let credentials = provider.fetch_credentials(&addr).await?;

        Ok(BmcEndpoint {
            addr,
            provider: Arc::new(provider),
            metadata,
            rack_id,
            credentials: Arc::new(RwLock::new(credentials)),
        })
    }

    pub async fn submit_health_report(
        &self,
        machine_id: &carbide_uuid::machine::MachineId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let ovrd = rpc::forge::HealthReportEntry {
            report: Some(report.into()),
            mode: rpc::forge::HealthReportApplyMode::Merge.into(),
        };

        let request = rpc::forge::InsertMachineHealthReportRequest {
            machine_id: Some(*machine_id),
            health_report_entry: Some(ovrd),
        };

        self.client
            .insert_machine_health_report(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(())
    }

    pub async fn submit_rack_health_report(
        &self,
        rack_id: &carbide_uuid::rack::RackId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let ovrd = rpc::forge::HealthReportEntry {
            report: Some(report.into()),
            mode: rpc::forge::HealthReportApplyMode::Merge.into(),
        };

        let request = rpc::forge::InsertRackHealthReportRequest {
            rack_id: Some(rack_id.clone()),
            health_report_entry: Some(ovrd),
        };

        self.client
            .insert_rack_health_report(request)
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

impl TryFrom<&rpc::forge::BmcInfo> for BmcAddr {
    type Error = HealthError;

    fn try_from(bmc_info: &rpc::forge::BmcInfo) -> Result<Self, Self::Error> {
        let ip = bmc_info
            .ip
            .as_ref()
            .ok_or_else(|| HealthError::GenericError("missing BMC IP address".to_string()))?
            .parse::<IpAddr>()
            .map_err(|error| HealthError::GenericError(error.to_string()))?;
        let mac = bmc_info
            .mac
            .as_ref()
            .ok_or_else(|| HealthError::GenericError("missing BMC MAC address".to_string()))
            .and_then(|mac| {
                MacAddress::from_str(mac)
                    .map_err(|error| HealthError::GenericError(error.to_string()))
            })?;
        let port = bmc_info.port.map(|port| port.try_into().unwrap_or(443));

        Ok(Self { ip, port, mac })
    }
}

impl From<rpc::forge::UsernamePassword> for BmcCredentials {
    fn from(value: rpc::forge::UsernamePassword) -> Self {
        Self::UsernamePassword {
            username: value.username,
            password: Some(value.password),
        }
    }
}

impl From<rpc::forge::SessionToken> for BmcCredentials {
    fn from(value: rpc::forge::SessionToken) -> Self {
        Self::SessionToken { token: value.token }
    }
}

impl From<rpc::forge::bmc_credentials::Type> for BmcCredentials {
    fn from(value: rpc::forge::bmc_credentials::Type) -> Self {
        match value {
            rpc::forge::bmc_credentials::Type::UsernamePassword(value) => value.into(),
            rpc::forge::bmc_credentials::Type::SessionToken(value) => value.into(),
        }
    }
}
