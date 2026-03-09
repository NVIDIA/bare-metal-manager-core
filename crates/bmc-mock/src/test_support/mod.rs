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

use crate::{
    DpuFirmwareVersions, DpuMachineInfo, HostHardwareType, HostMachineInfo, MachineInfo,
    MockPowerState, PowerControl, SetSystemPowerError, SystemPowerControl, machine_router,
};

pub mod axum_http_client;

use axum_http_client::AxumRouterHttpClient;

#[derive(Debug)]
struct NoopPowerControl;

impl PowerControl for NoopPowerControl {
    fn get_power_state(&self) -> MockPowerState {
        MockPowerState::On
    }

    fn send_power_command(
        &self,
        _reset_type: SystemPowerControl,
    ) -> Result<(), SetSystemPowerError> {
        Ok(())
    }
}

pub type TestBmc = HttpBmc<AxumRouterHttpClient>;

pub fn wiwynn_gb200_router() -> axum::Router {
    let dpus = vec![
        DpuMachineInfo::new(
            HostHardwareType::WiwynnGB200Nvl,
            false,
            DpuFirmwareVersions::default(),
        ),
        DpuMachineInfo::new(
            HostHardwareType::WiwynnGB200Nvl,
            false,
            DpuFirmwareVersions::default(),
        ),
    ];
    let machine_info =
        MachineInfo::Host(HostMachineInfo::new(HostHardwareType::WiwynnGB200Nvl, dpus));
    machine_router(
        machine_info,
        Arc::new(NoopPowerControl),
        "test-host-id".to_string(),
    )
}

pub fn wiwynn_gb200_bmc() -> Arc<TestBmc> {
    let router = wiwynn_gb200_router();
    let client = AxumRouterHttpClient::new(router);
    let endpoint = Url::parse("https://bmc-mock.local").expect("valid URL");
    let credentials = BmcCredentials::new("root".to_string(), "password".to_string());
    Arc::new(HttpBmc::new(
        client,
        endpoint,
        credentials,
        CacheSettings::with_capacity(32),
    ))
}

pub fn dell_poweredge_r750_bmc() -> Arc<TestBmc> {
    let machine_info = MachineInfo::Host(HostMachineInfo::new(
        HostHardwareType::DellPowerEdgeR750,
        vec![],
    ));
    let router = machine_router(
        machine_info,
        Arc::new(NoopPowerControl),
        "test-host-id".to_string(),
    );
    let client = AxumRouterHttpClient::new(router);
    let endpoint = Url::parse("https://bmc-mock.local").expect("valid URL");
    let credentials = BmcCredentials::new("root".to_string(), "password".to_string());
    Arc::new(HttpBmc::new(
        client,
        endpoint,
        credentials,
        CacheSettings::with_capacity(32),
    ))
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
        let client = AxumRouterHttpClient::new(wiwynn_gb200_router());
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
