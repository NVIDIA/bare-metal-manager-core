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
use axum::body::Body;
use db::managed_host;
use http_body_util::BodyExt;
use hyper::http::StatusCode;
use model::hardware_info::HardwareInfo;
use model::machine::LoadSnapshotOptions;
use tower::ServiceExt;
use utils::ManagedHostOutput;

use crate::tests::common::api_fixtures::dpu::DpuConfig;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::{
    create_managed_host_multi_dpu, create_test_env, site_explorer,
};
use crate::tests::web::{authenticated_request_builder, make_test_app};
use crate::web::managed_host::ManagedHostRowDisplay;

#[crate::sqlx_test]
async fn test_ok(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let app = make_test_app(&env);
    _ = create_managed_host_multi_dpu(&env, 1).await;

    let response = app
        .oneshot(
            authenticated_request_builder()
                .uri("/admin/managed-host.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Empty response body?")
        .to_bytes();

    let body_str = std::str::from_utf8(&body_bytes).expect("Invalid UTF-8 in body");
    let hosts: Vec<ManagedHostOutput> =
        serde_json::from_str(body_str).expect("Could not deserialize response");

    assert_eq!(hosts.len(), 1, "One host should have been returned");
    let host = hosts.first().unwrap();
    assert_eq!(host.dpus.len(), 1, "Host should have 1 dpu");
    let dpu = host.dpus.first().unwrap();
    assert_ne!(
        dpu.machine_id, host.machine_id,
        "DPU should not have the same machine ID as the host"
    );
}

#[crate::sqlx_test]
async fn test_multi_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let app = make_test_app(&env);
    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await.host().id;

    let response = app
        .oneshot(
            authenticated_request_builder()
                .uri("/admin/managed-host.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Empty response body?")
        .to_bytes();

    let body_str = std::str::from_utf8(&body_bytes).expect("Invalid UTF-8 in body");
    let hosts: Vec<ManagedHostOutput> =
        serde_json::from_str(body_str).expect("Could not deserialize response");

    assert!(
        !hosts.is_empty(),
        "At least one host should have been returned"
    );
    let host = hosts
        .into_iter()
        .find(|h| {
            h.machine_id
                .as_ref()
                .map(|m| m == &host_machine_id.to_string())
                .unwrap_or(false)
        })
        .unwrap_or_else(|| {
            panic!("Could not find expected host {host_machine_id} in managed_hosts output")
        });
    assert!(host.hostname.is_some(), "Hostname should be set");
    assert_eq!(host.dpus.len(), 2, "Host should have 2 dpus");
    for dpu in host.dpus.iter() {
        assert_ne!(
            dpu.machine_id, host.machine_id,
            "DPU should not have the same machine ID as the host"
        );
    }
}

// Test the ManagedHostRowDisplay as a proxy for testing that the HTML has what we want in
// managed_host::show_html (parsing the HTML string is prohibitive)
#[crate::sqlx_test]
async fn test_managed_host_row_display(pool: sqlx::PgPool) -> eyre::Result<()> {
    let env = create_test_env(pool).await;
    let config = ManagedHostConfig::with_dpus((0..2).map(|_| DpuConfig::default()).collect());
    let hardware_info = HardwareInfo::from(&config);
    let mock_host = site_explorer::new_mock_host(&env, config).await?;

    // Get info from what we mocked for site explorer so we know what to assert on in the ManagedHostRowDisplay
    let machine_id = mock_host
        .discovered_machine_id()
        .expect("mock host should have gotten a machine ID");
    let host_bmc_ip = mock_host
        .host_bmc_ip
        .expect("mock host should have gotten a BMC IP");
    let dpu_1_bmc_ip = *mock_host
        .dpu_bmc_ips
        .get(&0)
        .expect("mock DPU should have gotten a BMC IP");
    let dpu_2_bmc_ip = *mock_host
        .dpu_bmc_ips
        .get(&1)
        .expect("mock DPU should have gotten a BMC IP");

    // Load snapshots the way
    let snapshots = managed_host::load_all(
        &env.pool,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: env.config.host_health,
        },
    )
    .await?;

    assert_eq!(
        snapshots.len(),
        1,
        "Unexpected number of managed host snapshots"
    );

    let snapshot = snapshots.into_iter().next().unwrap();
    assert_eq!(snapshot.host_snapshot.id, machine_id);

    let row = ManagedHostRowDisplay::from(snapshot.clone());

    assert!(row.maintenance_start_time.is_empty());
    assert!(row.maintenance_reference.is_empty());
    assert_eq!(row.state, "Ready");
    assert_eq!(row.num_ib_ifs, hardware_info.infiniband_interfaces.len());
    assert_eq!(row.num_gpus, hardware_info.gpus.len(),);
    assert!(!row.time_in_state_above_sla);
    assert!(!row.time_in_state.is_empty()); // Should match something like "0 seconds"
    assert_eq!(row.host_bmc_ip, host_bmc_ip.to_string());
    assert_eq!(
        row.host_bmc_mac,
        mock_host.managed_host.bmc_mac_address.to_string()
    );
    assert_eq!(
        row.vendor,
        hardware_info.dmi_data.as_ref().unwrap().sys_vendor
    );
    assert_eq!(
        row.model,
        hardware_info.dmi_data.as_ref().unwrap().product_name
    );
    assert_eq!(row.machine_id, machine_id.to_string());
    assert!(row.health_overrides.is_empty());
    assert!(row.health_probe_alerts.is_empty());
    assert!(!row.host_admin_ip.is_empty());
    assert_eq!(
        row.host_admin_mac,
        hardware_info
            .network_interfaces
            .first()
            .unwrap()
            .mac_address
            .to_string()
    );
    assert!(row.state_reason.is_empty());

    assert_eq!(row.dpus.len(), 2);

    assert_eq!(
        row.dpus[0].machine_id,
        snapshot.dpu_snapshots[0].id.to_string()
    );
    assert_eq!(row.dpus[0].bmc_ip, dpu_1_bmc_ip.to_string());
    assert_eq!(
        row.dpus[0].bmc_mac,
        mock_host.managed_host.dpus[0].bmc_mac_address.to_string()
    );
    assert_eq!(
        row.dpus[0].oob_mac,
        mock_host.managed_host.dpus[0].oob_mac_address.to_string()
    );
    assert!(!row.dpus[0].oob_ip.is_empty(), "dpu should show an oob ip");

    assert_eq!(
        row.dpus[1].machine_id,
        snapshot.dpu_snapshots[1].id.to_string()
    );
    assert_eq!(row.dpus[1].bmc_ip, dpu_2_bmc_ip.to_string());
    assert_eq!(
        row.dpus[1].bmc_mac,
        mock_host.managed_host.dpus[1].bmc_mac_address.to_string()
    );
    assert_eq!(
        row.dpus[1].oob_mac,
        mock_host.managed_host.dpus[1].oob_mac_address.to_string()
    );
    assert!(!row.dpus[1].oob_ip.is_empty(), "dpu should show an oob ip");

    Ok(())
}
