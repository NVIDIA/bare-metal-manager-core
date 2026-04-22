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
    BmcState, Callbacks, DpuMachineInfo, HostHardwareType, HostMachineInfo, MachineInfo,
    MockPowerState, SetSystemPowerError, SystemPowerControl, machine_router,
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

pub async fn wiwynn_gb200_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        MachineInfo::Host(HostMachineInfo::new(
            HostHardwareType::WiwynnGB200Nvl,
            vec![
                DpuMachineInfo::new(HostHardwareType::WiwynnGB200Nvl, DpuSettings::default()),
                DpuMachineInfo::new(HostHardwareType::WiwynnGB200Nvl, DpuSettings::default()),
            ],
        )),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
    ))
    .await
}

pub async fn liteon_powershelf_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        MachineInfo::Host(HostMachineInfo::new(
            HostHardwareType::LiteOnPowerShelf,
            vec![],
        )),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
    ))
    .await
}

pub async fn nvidia_switch_nd5200_ld_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        MachineInfo::Host(HostMachineInfo::new(
            HostHardwareType::NvidiaSwitchNd5200Ld,
            vec![],
        )),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
    ))
    .await
}

pub async fn dell_poweredge_r750_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        MachineInfo::Host(HostMachineInfo::new(
            HostHardwareType::DellPowerEdgeR750,
            vec![],
        )),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
    ))
    .await
}

pub async fn dell_poweredge_r750_bluefield3_bmc(settings: DpuSettings) -> TestBmcHandle {
    test_bmc(machine_router(
        MachineInfo::Dpu(DpuMachineInfo::new(
            HostHardwareType::DellPowerEdgeR750,
            settings,
        )),
        Arc::new(NoopCallbacks),
        "test-dpu-id".to_string(),
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
        let client = AxumRouterHttpClient::new(
            machine_router(
                MachineInfo::Host(HostMachineInfo::new(
                    HostHardwareType::DellPowerEdgeR750,
                    vec![],
                )),
                Arc::new(NoopCallbacks),
                "test-host-id".to_string(),
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
