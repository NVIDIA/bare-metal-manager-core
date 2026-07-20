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

use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::nvlink::NvLinkDomainId;
use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use nv_redfish::bmc_http::reqwest::Client as ReqwestClient;
use url::Url;

use crate::HealthError;
use crate::bmc::{BmcClient, FixedCredentialProvider};
use crate::config::{StaticBmcEndpoint, StaticSwitchEndpointRole};
use crate::endpoint::{
    BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, EndpointMetadata, EndpointSource, MachineData,
    PowerShelfData, SwitchData, SwitchEndpointRole,
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

    pub fn from_config(
        configs: &[StaticBmcEndpoint],
        reqwest: &ReqwestClient,
        proxy_url: Option<&Url>,
        cache_size: usize,
    ) -> Self {
        let mut endpoints = Vec::with_capacity(configs.len());

        for cfg in configs {
            let mac = match MacAddress::from_str(&cfg.mac) {
                Ok(mac) => mac,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        bmc_mac_address = ?cfg.mac,
                        "Invalid MAC in static endpoint config"
                    );
                    continue;
                }
            };

            let metadata = if let Some(power_shelf) = &cfg.power_shelf {
                let id = power_shelf.id.as_ref().and_then(|id| match id.parse() {
                    Ok(id) => Some(id),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            power_shelf_id = ?id,
                            "Invalid power_shelf.id in static endpoint config"
                        );
                        None
                    }
                });
                let serial = power_shelf
                    .serial
                    .clone()
                    .or_else(|| power_shelf.id.clone())
                    .unwrap_or_else(|| cfg.mac.clone());

                Some(EndpointMetadata::PowerShelf(PowerShelfData { id, serial }))
            } else if let Some(switch) = &cfg.switch {
                let id = switch.id.as_ref().and_then(|id| match id.parse() {
                    Ok(id) => Some(id),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            switch_id = ?id,
                            "Invalid switch.id in static endpoint config"
                        );
                        None
                    }
                });
                let serial = switch
                    .serial
                    .clone()
                    .or_else(|| switch.id.clone())
                    .unwrap_or_else(|| cfg.mac.clone());
                let endpoint_role = match switch.endpoint_role {
                    StaticSwitchEndpointRole::Bmc => SwitchEndpointRole::Bmc,
                    StaticSwitchEndpointRole::Host => SwitchEndpointRole::Host,
                };

                let nmxc_enabled = switch.nmxc_enabled.unwrap_or(switch.is_primary);
                let nmxt_enabled = switch.nmxt_enabled.unwrap_or(switch.is_primary);

                Some(EndpointMetadata::Switch(SwitchData {
                    id,
                    serial,
                    slot_number: switch.slot_number,
                    tray_index: switch.tray_index,
                    endpoint_role,
                    is_primary: switch.is_primary,
                    nmxc_enabled,
                    nmxt_enabled,
                }))
            } else if let Some(machine) = &cfg.machine {
                let machine_id = &machine.id;
                let nvlink_domain_uuid =
                    machine.nvlink_domain_uuid.as_ref().and_then(
                        |id| match NvLinkDomainId::from_str(id) {
                            Ok(id) => Some(id),
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    nvlink_domain_uuid = ?id,
                                    "Invalid machine.nvlink_domain_uuid in static endpoint config"
                                );
                                None
                            }
                        },
                    );

                let driver_version = machine
                    .driver_version
                    .as_deref()
                    .map(str::trim)
                    .none_if_empty()
                    .map(str::to_string);

                match machine_id.parse() {
                    Ok(machine_id) => Some(EndpointMetadata::Machine(MachineData {
                        machine_id,
                        machine_serial: machine.serial.clone(),
                        slot_number: machine.slot_number,
                        tray_index: machine.tray_index,
                        nvlink_domain_uuid,
                        driver_version,
                    })),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            ?machine_id,
                            "Invalid machine.id in static endpoint config"
                        );
                        None
                    }
                }
            } else {
                None
            };

            let addr = BmcAddr {
                ip: cfg.ip,
                port: cfg.port,
                mac,
            };
            let credentials = BmcCredentials::UsernamePassword {
                username: cfg.username.clone(),
                password: cfg.password.clone(),
            };
            let provider = Arc::new(FixedCredentialProvider::new(credentials));
            let bmc = match BmcClient::new(
                reqwest.clone(),
                addr.clone(),
                provider,
                proxy_url.cloned(),
                cache_size,
            ) {
                Ok(client) => Arc::new(client),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        bmc_address = ?addr,
                        "Failed to construct BmcClient for static endpoint"
                    );
                    continue;
                }
            };
            let endpoint = BmcEndpoint {
                addr,
                metadata,
                rack_id: cfg.rack_id.as_ref().map(|id| RackId::new(id.as_str())),
                bmc,
            };
            endpoints.push(Arc::new(endpoint));
        }

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
    use carbide_uuid::power_shelf::{PowerShelfIdSource, PowerShelfType};
    use carbide_uuid::switch::{SwitchIdSource, SwitchType};
    use nv_redfish::bmc_http::reqwest::ClientParams as ReqwestClientParams;

    use super::*;
    use crate::config::{
        StaticBmcEndpoint, StaticMachineEndpoint, StaticPowerShelfEndpoint, StaticSwitchEndpoint,
        StaticSwitchEndpointRole,
    };

    fn reqwest() -> ReqwestClient {
        ReqwestClient::with_params(ReqwestClientParams::new().accept_invalid_certs(true))
            .expect("reqwest client builds")
    }

    fn test_switch_id(label: &str) -> carbide_uuid::switch::SwitchId {
        let mut hash = [0u8; 32];
        let bytes = label.as_bytes();
        hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        carbide_uuid::switch::SwitchId::new(SwitchIdSource::Tpm, hash, SwitchType::NvLink)
    }

    fn test_power_shelf_id(label: &str) -> carbide_uuid::power_shelf::PowerShelfId {
        let mut hash = [0u8; 32];
        let bytes = label.as_bytes();
        hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        carbide_uuid::power_shelf::PowerShelfId::new(
            PowerShelfIdSource::ProductBoardChassisSerial,
            hash,
            PowerShelfType::Rack,
        )
    }

    fn ip(addr: &str) -> std::net::IpAddr {
        addr.parse().unwrap()
    }

    #[tokio::test]
    async fn test_static_endpoint_source_filters_invalid_mac() {
        let configs = vec![
            StaticBmcEndpoint {
                ip: ip("10.0.0.1"),
                port: Some(443),
                mac: "00:11:22:33:44:55".to_string(),
                username: "admin".to_string(),
                password: Some("pass".to_string()),
                machine: None,
                power_shelf: None,
                switch: None,
                rack_id: None,
            },
            StaticBmcEndpoint {
                ip: ip("10.0.0.2"),
                port: Some(443),
                mac: "not-a-mac".to_string(),
                username: "admin".to_string(),
                password: Some("pass".to_string()),
                machine: None,
                power_shelf: None,
                switch: None,
                rack_id: None,
            },
        ];

        let source = StaticEndpointSource::from_config(&configs, &reqwest(), None, 10);
        let endpoints = source.fetch_bmc_hosts().await.expect("fetch should work");

        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].addr.mac,
            MacAddress::from_str("00:11:22:33:44:55").unwrap()
        );
    }

    #[tokio::test]
    async fn test_static_endpoint_with_switch_serial_sets_metadata() {
        let switch_id = test_switch_id("switch-a");
        let configs = vec![StaticBmcEndpoint {
            ip: ip("10.0.1.1"),
            port: Some(443),
            mac: "11:22:33:44:55:66".to_string(),
            username: "cumulus".to_string(),
            password: Some("pass".to_string()),
            machine: None,
            power_shelf: None,
            switch: Some(StaticSwitchEndpoint {
                id: Some(switch_id.to_string()),
                serial: Some("SN-001".to_string()),
                slot_number: Some(7),
                tray_index: Some(3),
                endpoint_role: StaticSwitchEndpointRole::Host,
                is_primary: true,
                nmxc_enabled: None,
                nmxt_enabled: None,
            }),
            rack_id: None,
        }];

        let source = StaticEndpointSource::from_config(&configs, &reqwest(), None, 10);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        match &endpoints[0].metadata {
            Some(EndpointMetadata::Switch(s)) => {
                assert_eq!(s.id, Some(switch_id));
                assert_eq!(s.serial, "SN-001");
                assert_eq!(s.slot_number, Some(7));
                assert_eq!(s.tray_index, Some(3));
                assert_eq!(s.endpoint_role, SwitchEndpointRole::Host);
                assert!(s.is_primary);
                assert!(s.nmxc_enabled);
                assert!(s.nmxt_enabled);
            }
            other => panic!("expected Switch metadata, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_static_endpoint_with_power_shelf_metadata() {
        let power_shelf_id = test_power_shelf_id("power-shelf-a");
        let configs = vec![StaticBmcEndpoint {
            ip: ip("10.0.2.1"),
            port: Some(443),
            mac: "22:33:44:55:66:77".to_string(),
            username: "admin".to_string(),
            password: Some("pass".to_string()),
            machine: None,
            power_shelf: Some(StaticPowerShelfEndpoint {
                id: Some(power_shelf_id.to_string()),
                serial: Some("PS-001".to_string()),
            }),
            switch: None,
            rack_id: None,
        }];

        let source = StaticEndpointSource::from_config(&configs, &reqwest(), None, 10);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        match &endpoints[0].metadata {
            Some(EndpointMetadata::PowerShelf(power_shelf)) => {
                assert_eq!(power_shelf.id, Some(power_shelf_id));
                assert_eq!(power_shelf.serial, "PS-001");
            }
            other => panic!("expected PowerShelf metadata, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_static_machine_endpoint_sets_placement_and_nvlink_metadata() {
        let machine_id = "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0"
            .parse()
            .expect("valid machine id");
        let domain_uuid = "00000000-0000-0000-0000-000000000000"
            .parse()
            .expect("valid NVLink domain UUID");
        let configs = vec![StaticBmcEndpoint {
            ip: ip("10.0.1.2"),
            port: Some(443),
            mac: "11:22:33:44:55:11".to_string(),
            username: "admin".to_string(),
            password: Some("pass".to_string()),
            machine: Some(StaticMachineEndpoint {
                id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0".to_string(),
                serial: Some("MN-001".to_string()),
                slot_number: Some(15),
                tray_index: Some(5),
                nvlink_domain_uuid: Some("00000000-0000-0000-0000-000000000000".to_string()),
                driver_version: Some(" 570.82 ".to_string()),
            }),
            power_shelf: None,
            switch: None,
            rack_id: Some("RACK_1".to_string()),
        }];

        let source = StaticEndpointSource::from_config(&configs, &reqwest(), None, 10);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0]
                .rack_id
                .as_ref()
                .map(|rack_id| rack_id.as_str()),
            Some("RACK_1")
        );
        match &endpoints[0].metadata {
            Some(EndpointMetadata::Machine(machine)) => {
                assert_eq!(machine.machine_id, machine_id);
                assert_eq!(machine.machine_serial.as_deref(), Some("MN-001"));
                assert_eq!(machine.slot_number, Some(15));
                assert_eq!(machine.tray_index, Some(5));
                assert_eq!(machine.nvlink_domain_uuid, Some(domain_uuid));
                assert_eq!(machine.driver_version.as_deref(), Some("570.82"));
            }
            other => panic!("expected Machine metadata, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_static_machine_endpoint_omits_empty_driver_version() {
        let configs = vec![StaticBmcEndpoint {
            ip: ip("10.0.1.3"),
            port: Some(443),
            mac: "11:22:33:44:55:12".to_string(),
            username: "admin".to_string(),
            password: Some("pass".to_string()),
            machine: Some(StaticMachineEndpoint {
                id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0".to_string(),
                serial: None,
                slot_number: None,
                tray_index: None,
                nvlink_domain_uuid: None,
                driver_version: Some("  ".to_string()),
            }),
            power_shelf: None,
            switch: None,
            rack_id: None,
        }];

        let source = StaticEndpointSource::from_config(&configs, &reqwest(), None, 10);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        match &endpoints[0].metadata {
            Some(EndpointMetadata::Machine(machine)) => {
                assert_eq!(machine.driver_version, None);
            }
            other => panic!("expected Machine metadata, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_static_endpoint_without_switch_serial_has_no_metadata() {
        let configs = vec![StaticBmcEndpoint {
            ip: ip("10.0.0.1"),
            port: Some(443),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            username: "admin".to_string(),
            password: Some("pass".to_string()),
            machine: None,
            power_shelf: None,
            switch: None,
            rack_id: None,
        }];

        let source = StaticEndpointSource::from_config(&configs, &reqwest(), None, 10);
        let endpoints = source.fetch_bmc_hosts().await.unwrap();

        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0].metadata.is_none());
    }

    struct FailingSource;

    impl EndpointSource for FailingSource {
        fn fetch_bmc_hosts<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
            Box::pin(async {
                Err(HealthError::GenericError(
                    "simulated endpoint source failure".to_string(),
                ))
            })
        }
    }

    #[tokio::test]
    async fn test_composite_endpoint_source_propagates_errors() {
        let endpoints = vec![super::super::test_support::test_endpoint(
            MacAddress::from_str("00:11:22:33:44:55").unwrap(),
        )];
        let source_ok = Arc::new(StaticEndpointSource::new(endpoints));
        let source_fail = Arc::new(FailingSource);
        let composite = CompositeEndpointSource::new(vec![source_ok, source_fail]);

        let result = composite.fetch_bmc_hosts().await;

        assert!(result.is_err());
    }
}
