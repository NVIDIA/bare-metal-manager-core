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

use std::sync::{Arc, Mutex};

use axum_http_client::AxumRouterHttpClient;
use mac_address::MacAddress;
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use url::Url;

use crate::mac_address_pool::{
    Config as MacAddressConfig, MacAddressPool, PoolConfig as MacAddressPoolConfig,
    RangesConfig as MacAddressRangesConfig,
};
use crate::machine_info::DpuSettings;
use crate::{
    BmcState, Callbacks, DpuMachineInfo, HostHardwareType, HostMachineInfo, MachineInfo,
    MockPowerState, SetSystemPowerError, SystemPowerControl, machine_router,
};

pub mod axum_http_client;

#[derive(Debug)]
pub struct NoopCallbacks;

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

lazy_static::lazy_static! {
    pub static ref TEST_HW_MAC_POOL_CONFIG: MacAddressPoolConfig =
        MacAddressPoolConfig::new(MacAddress::new([2, 0, 0, 0, 0, 0]), 16).unwrap();

    pub static ref TEST_MAC_POOL: Arc<Mutex<MacAddressPool>> =
        Arc::new(Mutex::new(MacAddressPool::new(MacAddressConfig {
            pool: Some(MacAddressPoolConfig::new(MacAddress::new([2, 0, 0, 0, 0, 0]), 32).unwrap()),
            ranges: Some(MacAddressRangesConfig::new(MacAddress::new([6, 0, 0, 0, 0, 0]), 32, 8).unwrap()),
        })));
}

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

pub async fn bmc_for_machine(machine_info: MachineInfo) -> TestBmcHandle {
    let machine_id = match &machine_info {
        MachineInfo::Host(_) => "test-host-id",
        MachineInfo::Dpu(_) => "test-dpu-id",
    };
    test_bmc(machine_router(
        &machine_info,
        Arc::new(NoopCallbacks),
        machine_id.to_string(),
        false,
    ))
    .await
}

fn host_info(hw_type: HostHardwareType) -> MachineInfo {
    let ndpu = hw_type.fixed_number_of_dpu().unwrap_or(0);
    let mut pool = TEST_MAC_POOL.lock().unwrap();
    let ranges_config = pool.allocate_range_config().unwrap();
    MachineInfo::Host(HostMachineInfo::new(
        hw_type,
        (0..ndpu)
            .map(|_| DpuMachineInfo::new(hw_type, &mut pool, DpuSettings::default()))
            .collect(),
        &mut pool,
        ranges_config,
    ))
}

pub async fn wiwynn_gb200_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::WiwynnGB200Nvl),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn lenovo_gb300_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::LenovoGB300Nvl),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn dgx_gb300_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::NvidiaDgxGb300),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

/// Host-mode mock for the NvidiaDgxVr hardware type ("vr-tray" in machine-a-tron
/// configs). Unlike the other GB300-family types (Lenovo, Nvidia DGX GB300,
/// Supermicro), this one previously only had a DPU-mode helper
/// (`nvidia_dgx_vr_bluefield4_dpu_bmc`), so there was no way to test exploring
/// it as a host tray at all. Added while investigating #3159.
pub async fn nvidia_dgx_vr_host_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::NvidiaDgxVr),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn supermicro_gb300_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::SupermicroGb300Nvl),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn generic_supermicro_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::GenericSupermicro),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn liteon_powershelf_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::LiteOnPowerShelf),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn delta_powershelf_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::DeltaPowerShelf),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

/// Delta power shelf whose PSUs report the given per-bay on/off states under
/// `Oem.deltaenergysystems.Power`. Lets tests exercise off and mixed shelves
/// (the default [`delta_powershelf_bmc`] is an all-on six-bay shelf).
pub async fn delta_powershelf_bmc_with_psu_power(states: Vec<bool>) -> TestBmcHandle {
    let machine_info = match host_info(HostHardwareType::DeltaPowerShelf) {
        MachineInfo::Host(host) => MachineInfo::Host(host.with_delta_psu_power(states)),
        MachineInfo::Dpu(_) => unreachable!("Delta power shelf must be a host"),
    };
    test_bmc(machine_router(
        &machine_info,
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn nvidia_switch_nd5200_ld_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::NvidiaSwitchNd5200Ld),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn dell_poweredge_r750_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::DellPowerEdgeR750),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn dell_poweredge_r750_bluefield3_bmc(settings: DpuSettings) -> TestBmcHandle {
    let machine_info = {
        let mut mac_pool = TEST_MAC_POOL.lock().unwrap();
        MachineInfo::Dpu(DpuMachineInfo::new(
            HostHardwareType::DellPowerEdgeR750,
            &mut mac_pool,
            settings,
        ))
    };
    test_bmc(machine_router(
        &machine_info,
        Arc::new(NoopCallbacks),
        "test-dpu-id".to_string(),
        false,
    ))
    .await
}

pub async fn dell_poweredge_r760_bluefield4_bmc(dpu: DpuMachineInfo) -> TestBmcHandle {
    let machine_info = MachineInfo::Dpu(dpu);
    test_bmc(machine_router(
        &machine_info,
        Arc::new(NoopCallbacks),
        "test-dpu-id".to_string(),
        false,
    ))
    .await
}

pub async fn nvidia_dgx_vr_bluefield4_dpu_bmc(settings: DpuSettings) -> TestBmcHandle {
    let machine_info = {
        let mut mac_pool = TEST_MAC_POOL.lock().unwrap();
        MachineInfo::Dpu(DpuMachineInfo::new(
            HostHardwareType::NvidiaDgxVr,
            &mut mac_pool,
            settings,
        ))
    };
    test_bmc(machine_router(
        &machine_info,
        Arc::new(NoopCallbacks),
        "test-dpu-id".to_string(),
        false,
    ))
    .await
}

pub async fn hpe_proliant_dl380a_gen11_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::HpeProliantDl380aGen11),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

pub async fn generic_ami_bmc() -> TestBmcHandle {
    test_bmc(machine_router(
        &host_info(HostHardwareType::GenericAmi),
        Arc::new(NoopCallbacks),
        "test-host-id".to_string(),
        false,
    ))
    .await
}

#[cfg(test)]
mod test {

    use axum::Router;
    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use nv_redfish::bmc_http::{BmcCredentials, HttpClient};
    use serde_json::json;
    use tower::ServiceExt;
    use url::Url;

    use super::*;
    use crate::injection::{Action, InjectionStore, Rule, RuleId, Selector};
    use crate::test_support::axum_http_client::Error;
    use crate::test_support::host_info;

    async fn json_request(
        router: &Router,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder().method(method).uri(path);
        let body = if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&body).unwrap())
        } else {
            Body::empty()
        };
        let response = router
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, body)
    }

    #[tokio::test]
    async fn caller_provided_injection_store_is_active() {
        let injection = Arc::new(InjectionStore::new());
        injection.upsert(Rule {
            id: RuleId::from("unavailable"),
            selector: Selector::Path {
                method: Some("GET".to_string()),
                glob: "/redfish/v1".to_string(),
            },
            action: Action::Status(StatusCode::SERVICE_UNAVAILABLE.as_u16()),
            remaining: None,
        });
        let (router, state) = crate::machine_router_with_injection_store(
            &host_info(HostHardwareType::DellPowerEdgeR750),
            Arc::new(NoopCallbacks),
            "test-host-id".to_string(),
            false,
            injection.clone(),
        );

        assert!(Arc::ptr_eq(&injection, &state.injection));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/redfish/v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn transport_supports_expand_query_through_mock_expander() {
        let client = AxumRouterHttpClient::new(
            machine_router(
                &host_info(HostHardwareType::DellPowerEdgeR750),
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

    #[tokio::test]
    async fn ami_boot_option_settings_persist_enablement() {
        let router = machine_router(
            &host_info(HostHardwareType::LenovoGB300Nvl),
            Arc::new(NoopCallbacks),
            "test-host-id".to_string(),
            false,
        )
        .0;
        let resource = "/redfish/v1/Systems/System_0/BootOptions/0004";

        let (status, initial) = json_request(&router, Method::GET, resource, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(initial.get("BootOptionEnabled"), None);

        for enabled in [true, false] {
            let (status, _) = json_request(
                &router,
                Method::PATCH,
                &format!("{resource}/SD"),
                Some(json!({ "BootOptionEnabled": enabled })),
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);

            let (status, current) = json_request(&router, Method::GET, resource, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                current.get("BootOptionEnabled").and_then(|v| v.as_bool()),
                Some(enabled)
            );
        }
    }

    #[tokio::test]
    async fn hpe_boot_settings_persist_oem_order_separately() {
        let router = machine_router(
            &host_info(HostHardwareType::HpeProliantDl380aGen11),
            Arc::new(NoopCallbacks),
            "test-host-id".to_string(),
            false,
        )
        .0;
        let system_resource = "/redfish/v1/Systems/1";
        let boot_resource = "/redfish/v1/Systems/1/Bios/oem/hpe/boot";

        let (status, system) = json_request(&router, Method::GET, system_resource, None).await;
        assert_eq!(status, StatusCode::OK);
        let standard_order = system["Boot"]["BootOrder"].clone();

        let (status, initial) = json_request(&router, Method::GET, boot_resource, None).await;
        assert_eq!(status, StatusCode::OK);
        let initial_order = initial["PersistentBootConfigOrder"]
            .as_array()
            .expect("HPE persistent boot order must be an array");
        assert!(initial_order.iter().any(|entry| {
            entry
                .as_str()
                .is_some_and(|entry| entry.starts_with("NIC."))
        }));
        assert!(
            initial_order
                .iter()
                .any(|entry| { entry.as_str().is_some_and(|entry| entry.starts_with("HD.")) })
        );

        let new_order = json!(["HD.Slot.1.1", "NIC.Slot.1.1.Httpv4"]);
        let (status, _) = json_request(
            &router,
            Method::PATCH,
            &format!("{boot_resource}/settings"),
            Some(json!({ "PersistentBootConfigOrder": new_order })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, current) = json_request(&router, Method::GET, boot_resource, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            current["PersistentBootConfigOrder"],
            json!(["HD.Slot.1.1", "NIC.Slot.1.1.Httpv4"])
        );

        let (status, system) = json_request(&router, Method::GET, system_resource, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(system["Boot"]["BootOrder"], standard_order);
    }
}
