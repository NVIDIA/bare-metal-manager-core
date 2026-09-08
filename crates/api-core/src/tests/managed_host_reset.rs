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

//! Operator-requested managed host reset, as reached through
//! `managed-host reset set|clear|list`.

use std::sync::Arc;
use std::time::Duration;

use carbide_dpf::{DpuDeploymentType, DpuPhase};
use carbide_machine_controller::dpf::{DpfOperations, MockDpfOperations};
use carbide_uuid::machine::MachineId;
use rpc::forge::forge_server::Forge;
use rpc::forge::managed_host_reset_request::Mode;
use rpc::forge::{ManagedHostResetListRequest, ManagedHostResetRequest, UpdateInitiator};
use tokio::time::timeout;
use tonic::{Code, Request};

use crate::tests::common::api_fixtures::test_managed_host::TestManagedHost;
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, create_managed_host, create_managed_host_with_dpf, create_test_env,
    create_test_env_with_overrides, get_config,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A reset is only offered to DPF-ingested hosts, and `create_managed_host_with_dpf`
/// drives the real provisioning flow, so these tests need DPF enabled in config plus an
/// SDK for it to register against. Same starting point as the `dpf` suites.
async fn dpf_test_env(pool: sqlx::PgPool) -> TestEnv {
    let mut mock = MockDpfOperations::new();
    mock.expect_register_dpu_device().returning(|_, _| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));
    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
    mock.expect_deployment_type_for_dpu()
        .returning(|_, _| Ok(DpuDeploymentType::Bf3));
    mock.expect_verify_node_labels().returning(|_, _| Ok(true));
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

    create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await
}

async fn dpf_ingested_host(env: &TestEnv) -> TestManagedHost {
    timeout(TEST_TIMEOUT, create_managed_host_with_dpf(env))
        .await
        .expect("timed out during initial provisioning")
}

fn reset_request(machine_id: MachineId, mode: Mode) -> Request<ManagedHostResetRequest> {
    Request::new(ManagedHostResetRequest {
        machine_id: Some(machine_id),
        mode: mode.into(),
        initiator: UpdateInitiator::AdminCli.into(),
        allow_reset_with_instance: false,
    })
}

/// A `Set` has to land in `machines.reset_requested` and become visible to both the
/// controller and `reset list`. That column is the controller's only view of the request,
/// so a persistence or projection break does not surface as an error: the request is
/// accepted and the reset simply never happens. `started_at` must come back unset, since
/// an unstarted request is exactly what the controller hinge fires on.
#[crate::sqlx_test]
async fn reset_set_records_a_request_that_the_pending_list_reports(pool: sqlx::PgPool) {
    let env = dpf_test_env(pool).await;
    let managed_host = dpf_ingested_host(&env).await;
    managed_host.mark_machine_for_updates().await;
    let host_id: MachineId = managed_host.id.into();

    // Nothing is pending beforehand, so the list is selecting on the column rather than
    // returning every host.
    let listed = env
        .api
        .list_managed_hosts_waiting_for_reset(Request::new(ManagedHostResetListRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.hosts.is_empty());

    env.api
        .trigger_managed_host_reset(reset_request(host_id, Mode::Set))
        .await
        .unwrap();

    let mut txn = env.db_txn().await;
    let request = managed_host
        .host()
        .db_machine(&mut txn)
        .await
        .reset_requested
        .expect("the reset request should persist on the host row");
    assert_eq!(request.initiator, UpdateInitiator::AdminCli.as_str_name());
    assert!(
        request.started_at.is_none(),
        "a fresh request is unstarted, which is the condition the controller hinge fires on"
    );

    let listed = env
        .api
        .list_managed_hosts_waiting_for_reset(Request::new(ManagedHostResetListRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.hosts.len(), 1);
    assert_eq!(listed.hosts[0].id, Some(host_id));
    assert_eq!(
        listed.hosts[0].initiator,
        UpdateInitiator::AdminCli.as_str_name()
    );
    assert!(listed.hosts[0].requested_at.is_some());
    assert!(
        listed.hosts[0].started_at.is_none(),
        "the operator reads an absent Started At as 'the controller has not picked this up'"
    );
}

/// A reset tears down every DPU attached to a host, so it is only expressible against the
/// host; and the host-update alert is what takes the host out of allocation before its
/// data is destroyed. Neither refusal may leave a half-recorded reset behind.
#[crate::sqlx_test]
async fn reset_set_rejects_a_dpu_target_and_an_unacknowledged_host(pool: sqlx::PgPool) {
    let env = dpf_test_env(pool).await;
    let managed_host = dpf_ingested_host(&env).await;

    let error = env
        .api
        .trigger_managed_host_reset(reset_request(managed_host.dpu().id.into(), Mode::Set))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(
        error.message().contains("not a host machine"),
        "unexpected message: {}",
        error.message()
    );

    // DPF-ingested, but no operator has taken it out of service yet.
    let error = env
        .api
        .trigger_managed_host_reset(reset_request(managed_host.id.into(), Mode::Set))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(
        error.message().contains("HostUpdateInProgress"),
        "unexpected message: {}",
        error.message()
    );

    let mut txn = env.db_txn().await;
    assert!(
        managed_host
            .host()
            .db_machine(&mut txn)
            .await
            .reset_requested
            .is_none()
    );
}

/// Re-ingestion re-registers the host's DPF CRs, so a host that was never ingested through
/// DPF has nothing to come back as and is refused before anything is recorded.
#[crate::sqlx_test]
async fn reset_set_rejects_a_host_not_ingested_through_dpf(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let managed_host = create_managed_host(&env).await;
    // Carries the alert, so the DPF gate is the only precondition it can fail.
    managed_host.mark_machine_for_updates().await;

    let error = env
        .api
        .trigger_managed_host_reset(reset_request(managed_host.id.into(), Mode::Set))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        error.message().contains("not ingested via DPF"),
        "unexpected message: {}",
        error.message()
    );

    let mut txn = env.db_txn().await;
    assert!(
        managed_host
            .host()
            .db_machine(&mut txn)
            .await
            .reset_requested
            .is_none()
    );
}

/// `Clear` is the withdrawal path, and it closes once the controller stamps `started_at`
/// and begins tearing the host down. Both halves matter: an operator has to be able to take
/// back a request that has not started, and a late clear must not cancel a teardown that is
/// already deleting the tenant instance and the host's DPF CRs.
#[crate::sqlx_test]
async fn reset_clear_withdraws_only_a_reset_that_has_not_started(pool: sqlx::PgPool) {
    let env = dpf_test_env(pool).await;
    let managed_host = dpf_ingested_host(&env).await;
    managed_host.mark_machine_for_updates().await;
    let host_id: MachineId = managed_host.id.into();

    env.api
        .trigger_managed_host_reset(reset_request(host_id, Mode::Set))
        .await
        .unwrap();
    env.api
        .trigger_managed_host_reset(reset_request(host_id, Mode::Clear))
        .await
        .unwrap();

    let mut txn = env.db_txn().await;
    assert!(
        managed_host
            .host()
            .db_machine(&mut txn)
            .await
            .reset_requested
            .is_none()
    );
    drop(txn);

    // Request again, then stamp it started the way the controller hinge does when it moves
    // the host into `Reset`.
    env.api
        .trigger_managed_host_reset(reset_request(host_id, Mode::Set))
        .await
        .unwrap();
    let mut txn = env.db_txn().await;
    db::machine::update_managed_host_reset_start_time(&mut txn, &host_id)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let error = env
        .api
        .trigger_managed_host_reset(reset_request(host_id, Mode::Clear))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        error.message().contains("already started"),
        "unexpected message: {}",
        error.message()
    );

    let mut txn = env.db_txn().await;
    let request = managed_host
        .host()
        .db_machine(&mut txn)
        .await
        .reset_requested
        .expect("the started reset should survive a refused clear");
    assert!(request.started_at.is_some());
}
