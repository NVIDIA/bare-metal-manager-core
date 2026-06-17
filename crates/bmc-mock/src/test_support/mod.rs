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

use std::sync::Arc;

use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use url::Url;

use crate::machine_info::DpuSettings;
use crate::{
    BmcState, Callbacks, DpuMachineInfo, HostHardwareType, HostMachineInfo, MacAddressPool,
    MachineInfo, MockMacAddressPoolConfig, MockPowerState, SetSystemPowerError, SystemPowerControl,
    machine_router,
};
pub mod axum_http_client;

use axum_http_client::AxumRouterHttpClient;

#[derive(Debug)]
struct NoopCallbacks;

impl Callbacks for NoopCallbacks {
    fn get_power_state(&self) -> MockPowerState {
        MockPowerState::On
    }

    fn send_power_command(
        &self,
        _reset_type: SystemPowerControl,
    ) -> Result<(), SetSystemPowerError> {
        Ok(())
    }

    fn state_refresh_indication(&self) {}
}

pub type TestBmc = HttpBmc<AxumRouterHttpClient>;

#[derive(Clone)]
pub struct TestBmcHandle {
    pub service_root: Arc<nv_redfish::ServiceRoot<TestBmc>>,
    pub state: BmcState,
}

async fn test_bmc((router, state): (axum::Router, BmcState)) -> TestBmcHandle {
    let client = AxumRouterHttpClient::new(router);
    let endpoint = Url::parse("https://bmc-mock.local").expect("valid URL");
    let credentials = BmcCredentials::new("root".to_string(), "password".to_string());
    let bmc = Arc::new(HttpBmc::new(
        client,
        endpoint,
        credentials,
        CacheSettings::with_capacity(32),
    ));
    TestBmcHandle {
        service_root: nv_redfish::ServiceRoot::new(bmc).await.unwrap().into(),
        state,
    }
}

fn default_mock_mac_pool() -> MacAddressPool {
    MacAddressPool::new(DEFAULT_MOCK_MAC_POOL_CONFIG)
}

const DEFAULT_MOCK_MAC_POOL_CONFIG: MockMacAddressPoolConfig = MockMacAddressPoolConfig {
    start: [0x02, 0x01, 0x0, 0x0, 0x0, 0x1],
    length: u32::MAX as usize,
};

pub async fn wiwynn_gb200_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(
                HostHardwareType::WiwynnGB200Nvl,
                vec![
                    DpuMachineInfo::allocate(
                        HostHardwareType::WiwynnGB200Nvl,
                        DpuSettings::default(),
                        &mac_pool,
                    )
                    .expect("default mock MAC address pool must have DPU addresses"),
                    DpuMachineInfo::allocate(
                        HostHardwareType::WiwynnGB200Nvl,
                        DpuSettings::default(),
                        &mac_pool,
                    )
                    .expect("default mock MAC address pool must have DPU addresses"),
                ],
                &mac_pool,
            )
            .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn lenovo_gb300_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(
                HostHardwareType::LenovoGB300Nvl,
                vec![
                    DpuMachineInfo::allocate(
                        HostHardwareType::LenovoGB300Nvl,
                        DpuSettings::default(),
                        &mac_pool,
                    )
                    .expect("default mock MAC address pool must have DPU addresses"),
                ],
                &mac_pool,
            )
            .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn dgx_gb300_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(
                HostHardwareType::NvidiaDgxGb300,
                vec![
                    DpuMachineInfo::allocate(
                        HostHardwareType::NvidiaDgxGb300,
                        DpuSettings::default(),
                        &mac_pool,
                    )
                    .expect("default mock MAC address pool must have DPU addresses"),
                ],
                &mac_pool,
            )
            .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn supermicro_gb300_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(
                HostHardwareType::SupermicroGb300Nvl,
                vec![
                    DpuMachineInfo::allocate(
                        HostHardwareType::SupermicroGb300Nvl,
                        DpuSettings::default(),
                        &mac_pool,
                    )
                    .expect("default mock MAC address pool must have DPU addresses"),
                ],
                &mac_pool,
            )
            .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn generic_supermicro_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(HostHardwareType::GenericSupermicro, vec![], &mac_pool)
                .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn liteon_powershelf_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(HostHardwareType::LiteOnPowerShelf, vec![], &mac_pool)
                .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn nvidia_switch_nd5200_ld_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(HostHardwareType::NvidiaSwitchNd5200Ld, vec![], &mac_pool)
                .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn dell_poweredge_r750_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(HostHardwareType::DellPowerEdgeR750, vec![], &mac_pool)
                .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn dell_poweredge_r750_bluefield3_bmc(settings: DpuSettings) -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Dpu(
            DpuMachineInfo::allocate(HostHardwareType::DellPowerEdgeR750, settings, &mac_pool)
                .expect("default mock MAC address pool must have DPU addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-dpu-id".to_string(),
        false,
    ))
    .await
}

pub async fn generic_ami_bmc() -> TestBmcHandle {
    let mac_pool = default_mock_mac_pool();
    test_bmc(machine_router(
        MachineInfo::Host(
            HostMachineInfo::allocate(HostHardwareType::GenericAmi, vec![], &mac_pool)
                .expect("default mock MAC address pool must have host addresses"),
        ),
        &mac_pool,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

#[cfg(test)]
mod test {

    use axum::Router;
    use nv_redfish::bmc_http::{BmcCredentials, HttpClient};
    use url::Url;

    use super::*;
    use crate::test_support::axum_http_client::Error;

    #[tokio::test]
    async fn transport_supports_expand_query_through_mock_expander() {
        let mac_pool = default_mock_mac_pool();
        let client = AxumRouterHttpClient::new(
            machine_router(
                MachineInfo::Host(
                    HostMachineInfo::allocate(
                        HostHardwareType::DellPowerEdgeR750,
                        vec![],
                        &mac_pool,
                    )
                    .expect("default mock MAC address pool must have host addresses"),
                ),
                &mac_pool,
                Arc::new(NoopCallbacks),
                "test-host-id".to_string(),
                false,
            )
            .0,
        );
        let url =
            Url::parse("https://bmc-mock.local/redfish/v1/Chassis?$expand=.($levels=1)").unwrap();

        let response: serde_json::Value = client
            .get(
                url,
                &BmcCredentials::new("root".to_string(), "password".to_string()),
                None,
                &axum::http::HeaderMap::new(),
            )
            .await
            .expect("expanded GET should succeed");

        let members = response
            .get("Members")
            .and_then(|m| m.as_array())
            .expect("expanded response should contain Members array");
        assert!(!members.is_empty(), "expanded Members must not be empty");
        assert!(
            members[0].get("@odata.id").is_some() && members[0].get("Name").is_some(),
            "expanded member should contain entity fields from expander router"
        );
    }

    #[tokio::test]
    async fn unroutable_request_returns_404_from_transport() {
        let client = AxumRouterHttpClient::new(Router::new());
        let url = Url::parse("https://bmc-mock.local/redfish/v1").unwrap();
        let err = client
            .get::<serde_json::Value>(
                url,
                &BmcCredentials::new("root".to_string(), "password".to_string()),
                None,
                &axum::http::HeaderMap::new(),
            )
            .await
            .expect_err("empty router should return transport error");

        match err {
            Error::InvalidResponse { status, .. } => {
                assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
            }
            other => panic!("expected invalid response error, got: {other}"),
        }
    }
}
