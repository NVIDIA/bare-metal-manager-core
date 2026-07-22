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

//! DPF happy-path and inventory integration tests.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ::rpc::forge as rpc;
use ::rpc::forge::forge_server::Forge;
use carbide_dpf::{DpfError, DpuDeploymentType, DpuPhase, DpuServiceVersion};
use carbide_machine_controller::dpf::{DpfOperations, MockDpfOperations};
use model::machine::ManagedHostState;
use tokio::time::timeout;
use tonic::Request;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host_with_dpf, create_test_env_with_overrides, get_config,
};

fn default_mock() -> MockDpfOperations {
    let mut mock = MockDpfOperations::new();
    mock.expect_register_dpu_device().returning(|_| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));
    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
    mock.expect_deployment_type_for_dpu()
        .returning(|_| Ok(DpuDeploymentType::Bf3));
    mock.expect_verify_node_labels().returning(|_, _| Ok(true));
    mock
}

#[crate::sqlx_test]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let dpf_sdk: Arc<dyn DpfOperations> = Arc::new(default_mock());

    let mut config = get_config();
    config.dpf = crate::cfg::file::DpfConfig {
        enabled: true,
        deployments: crate::cfg::file::DpfDeploymentsConfig {
            bf3: crate::cfg::file::DpfDeploymentConfig {
                bfb_url: Some("http://example.com/test.bfb".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;
    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(host.config.dpf.used_for_ingestion);
    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));

    let carbide_machines_per_state = env.test_meter.parsed_metrics("carbide_machines_per_state");

    assert!(carbide_machines_per_state.contains(&(
        "{fresh=\"true\",state=\"ready\",substate=\"\"}".to_string(),
        "3".to_string()
    )));
}

/// Verifies DPF inventory uses the host ingestion flag and composite DPU CR name,
/// and preserves the last complete operator inventory when a later lookup fails.
#[crate::sqlx_test]
async fn test_dpf_inventory_uses_host_context_and_preserves_last_good_value(pool: sqlx::PgPool) {
    let queried_dpu_names = Arc::new(Mutex::new(Vec::new()));
    let fail_inventory_lookup = Arc::new(AtomicBool::new(false));
    let mut mock = default_mock();
    let queried_dpu_names_for_mock = queried_dpu_names.clone();
    let fail_inventory_lookup_for_mock = fail_inventory_lookup.clone();
    mock.expect_get_service_versions_for_dpu()
        .returning(move |dpu_name| {
            queried_dpu_names_for_mock
                .lock()
                .expect("queried DPU names lock must not be poisoned")
                .push(dpu_name.to_string());
            if fail_inventory_lookup_for_mock.load(Ordering::SeqCst) {
                return Err(DpfError::InvalidState(
                    "referenced service template is unavailable".to_string(),
                ));
            }
            Ok(vec![DpuServiceVersion {
                name: "doca-hbn".to_string(),
                version: "operator-version".to_string(),
                url: "nvcr.io/nvidia/doca".to_string(),
            }])
        });

    // Ingest through DPF so only the host receives used_for_ingestion.
    let dpf_sdk: Arc<dyn DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = crate::cfg::file::DpfConfig {
        enabled: true,
        deployments: crate::cfg::file::DpfDeploymentsConfig {
            bf3: crate::cfg::file::DpfDeploymentConfig {
                bfb_url: Some("http://example.com/test.bfb".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;
    let managed_host = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    // Read both records through the public API and derive the expected CR name
    // independently from their reported BMC MAC addresses.
    let host = env.find_machine(managed_host.id).await.remove(0);
    let dpu = env.find_machine(managed_host.dpu_ids[0]).await.remove(0);
    assert!(
        host.config
            .as_ref()
            .and_then(|config| config.dpf.as_ref())
            .is_some_and(|dpf| dpf.used_for_ingestion)
    );
    assert!(
        !dpu.config
            .as_ref()
            .and_then(|config| config.dpf.as_ref())
            .is_some_and(|dpf| dpf.used_for_ingestion)
    );
    let host_node_id = host
        .bmc_info
        .as_ref()
        .and_then(|bmc| bmc.mac.as_deref())
        .expect("host BMC MAC must exist")
        .to_ascii_lowercase()
        .replace(':', "-");
    let dpu_device_id = dpu
        .bmc_info
        .as_ref()
        .and_then(|bmc| bmc.mac.as_deref())
        .expect("DPU BMC MAC must exist")
        .to_ascii_lowercase()
        .replace(':', "-");
    let expected_dpu_name = format!("node-{host_node_id}-device-{dpu_device_id}");
    queried_dpu_names
        .lock()
        .expect("queried DPU names lock must not be poisoned")
        .clear();

    // Report an incomplete agent inventory and confirm the operator value wins.
    let report = || {
        Request::new(rpc::DpuAgentInventoryReport {
            machine_id: Some(managed_host.dpu_ids[0]),
            inventory: Some(rpc::MachineInventory {
                components: vec![rpc::MachineInventorySoftwareComponent {
                    name: "agent-only".to_string(),
                    version: "incomplete".to_string(),
                    url: String::new(),
                }],
            }),
        })
    };
    env.api
        .update_agent_reported_inventory(report())
        .await
        .expect("DPF inventory update must succeed");
    assert_eq!(
        *queried_dpu_names
            .lock()
            .expect("queried DPU names lock must not be poisoned"),
        vec![expected_dpu_name]
    );
    let stored_inventory = env
        .find_machine(managed_host.dpu_ids[0])
        .await
        .remove(0)
        .inventory
        .expect("operator inventory must be persisted");
    assert_eq!(
        stored_inventory.components,
        vec![rpc::MachineInventorySoftwareComponent {
            name: "doca-hbn".to_string(),
            version: "operator-version".to_string(),
            url: "nvcr.io/nvidia/doca".to_string(),
        }]
    );

    // A later incomplete operator view must fail before replacing the complete value.
    fail_inventory_lookup.store(true, Ordering::SeqCst);
    env.api
        .update_agent_reported_inventory(report())
        .await
        .expect_err("incomplete DPF inventory must be rejected");
    let inventory_after_error = env
        .find_machine(managed_host.dpu_ids[0])
        .await
        .remove(0)
        .inventory
        .expect("last complete inventory must remain persisted");
    assert_eq!(inventory_after_error, stored_inventory);
}
