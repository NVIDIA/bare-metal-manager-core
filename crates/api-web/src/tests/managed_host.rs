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
use carbide_rpc_utils::ManagedHostOutput;
use carbide_test_harness::TestMachine as _;
use db::{machine, managed_host};
use http_body_util::BodyExt;
use hyper::http::StatusCode;
use model::machine::{InstanceState, LoadSnapshotOptions, ManagedHostState, RetryInfo};
use tower::ServiceExt;

use crate::managed_host::ManagedHostRowDisplay;
use crate::tests::env::TestEnv;
use crate::tests::{make_test_app, web_request_builder};

#[crate::sqlx_test]
async fn test_ok(pool: sqlx::PgPool) {
    let env = TestEnv::new(pool).await;
    let app = make_test_app(&env.test_harness);
    _ = env.create_ready_managed_host(1).await;

    let response = app
        .oneshot(
            web_request_builder()
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
    assert!(
        !host.discovery_info.network_interfaces.is_empty(),
        "Host discovery info should be populated and non-default"
    );
    assert_ne!(
        dpu.machine_id, host.machine_id,
        "DPU should not have the same machine ID as the host"
    );
    assert!(
        !dpu.discovery_info.network_interfaces.is_empty(),
        "DPU discovery info should be populated and non-default"
    );
}

#[crate::sqlx_test]
async fn test_multi_dpu(pool: sqlx::PgPool) {
    let env = TestEnv::new(pool).await;
    let app = make_test_app(&env.test_harness);
    let mh = env.create_ready_managed_host(2).await.0;
    let host_machine_id = mh.host.id;

    let response = app
        .oneshot(
            web_request_builder()
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
    let env = TestEnv::new(pool).await;
    let (mh, build_data) = env.create_ready_managed_host(2).await;
    let hardware_info = mh.host.hardware_info();
    let dpu_1 = mh.dpu(0);
    let dpu_2 = mh.dpu(1);

    // Get info from the test managed host so we know what to assert on in the ManagedHostRowDisplay.
    let machine_id = mh.host.id;

    let snapshots = managed_host::load_all(
        &env.api().database_connection,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: env.api().runtime_config.host_health,
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

    let sla_config = model::machine::slas::MachineSlaConfig::new(
        env.api()
            .runtime_config
            .machine_state_controller
            .failure_retry_time,
    );
    let row = ManagedHostRowDisplay::from_snapshot(snapshot.clone(), &sla_config);

    assert!(row.maintenance_start_time.is_empty());
    assert!(row.maintenance_reference.is_empty());
    assert_eq!(row.state, "Ready");
    assert_eq!(row.num_ib_ifs, hardware_info.infiniband_interfaces.len());
    assert_eq!(row.num_gpus, hardware_info.gpus.len(),);
    assert!(!row.time_in_state_above_sla);
    assert!(!row.time_in_state.is_empty()); // Should match something like "0 seconds"
    assert_eq!(row.host_bmc_ip, build_data.host_bmc_ip().to_string());
    assert_eq!(row.host_bmc_mac, mh.host.bmc_mac.to_string());
    assert_eq!(
        row.vendor,
        hardware_info.dmi_data.as_ref().unwrap().sys_vendor
    );
    assert_eq!(
        row.model,
        hardware_info.dmi_data.as_ref().unwrap().product_name
    );
    assert_eq!(row.machine_id, machine_id.to_string());
    assert!(!row.health_sources.is_empty());
    assert!(row.health_probe_alerts.is_empty());
    assert!(!row.host_admin_ip.is_empty());
    assert_eq!(row.host_admin_mac, mh.host.primary_mac().to_string());
    assert!(row.state_reason.is_empty());

    assert_eq!(row.dpus.len(), 2);

    assert_eq!(
        row.dpus[0].machine_id,
        snapshot.dpu_snapshots[0].id.to_string()
    );
    assert_eq!(row.dpus[0].bmc_ip, build_data.dpu_bmc_ip(0).to_string());
    assert_eq!(row.dpus[0].bmc_mac, dpu_1.bmc_mac.to_string());
    assert_eq!(row.dpus[0].oob_mac, dpu_1.oob_mac().to_string());
    assert!(!row.dpus[0].oob_ip.is_empty(), "dpu should show an oob ip");

    assert_eq!(
        row.dpus[1].machine_id,
        snapshot.dpu_snapshots[1].id.to_string()
    );
    assert_eq!(row.dpus[1].bmc_ip, build_data.dpu_bmc_ip(1).to_string());
    assert_eq!(row.dpus[1].bmc_mac, dpu_2.bmc_mac.to_string());
    assert_eq!(row.dpus[1].oob_mac, dpu_2.oob_mac().to_string());
    assert!(!row.dpus[1].oob_ip.is_empty(), "dpu should show an oob ip");

    Ok(())
}

#[crate::sqlx_test]
async fn test_managed_host_html_uses_runtime_sla_config(pool: sqlx::PgPool) {
    let env = TestEnv::new(pool).await;
    let mh = env.create_ready_managed_host(1).await.0;

    let assigned_booting_state = ManagedHostState::Assigned {
        instance_state: InstanceState::BootingWithDiscoveryImage {
            retry: RetryInfo { count: 0 },
        },
    };
    let state_changed_at = chrono::Utc::now() - chrono::Duration::minutes(5);
    let state_version: config_version::ConfigVersion =
        format!("V999-T{}", state_changed_at.timestamp_micros())
            .parse()
            .unwrap();

    let mut txn = env.test_harness.db_txn().await;
    let host_machine = mh.host.db_machine(&mut txn).await;
    machine::advance(
        &host_machine,
        &mut txn,
        &assigned_booting_state,
        Some(state_version),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let app = make_test_app(&env.test_harness);
    let response = app
        .oneshot(
            web_request_builder()
                .uri("/admin/managed-host?time-in-state-above-sla-filter=true")
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

    assert!(body_str.contains("Filtered Managed Hosts (1)"));
    assert!(body_str.contains("bubble warning"));
    assert!(body_str.contains("Assigned/BootingWithDiscoveryImage"));
}
