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

use carbide_test_support::Outcome::Yields;
use carbide_test_support::{Case, check_cases_async};
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::network::NetworkSegmentId;
use config_version::ConfigVersion;
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    BootConfigSynchronizationRequest, BootConfigSynchronizationState, ManagedHostState,
};
use model::machine_interface_address::MachineInterfaceAssociation;
use model::network_segment::NetworkSegmentType;
use model::predicted_machine_interface::NewPredictedMachineInterface;
use model::test_support::ManagedHostConfig;
use rpc::forge;
use rpc::forge::forge_server::Forge;

use crate::test_support::fixture_config::{FixtureDefault as _, ManagedHostConfigExt as _};
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::TestEnv;
use crate::tests::common::api_fixtures::network_segment::FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY;

#[derive(Debug, sqlx::FromRow)]
struct BootSelectionState {
    boot_interface_selection_version: ConfigVersion,
    boot_config_synchronization_requested:
        Option<sqlx::types::Json<BootConfigSynchronizationRequest>>,
    network_config_version: ConfigVersion,
}

async fn boot_selection_state(env: &TestEnv, host_id: MachineId) -> BootSelectionState {
    sqlx::query_as(
        "SELECT boot_interface_selection_version, \
                boot_config_synchronization_requested, network_config_version \
         FROM machines WHERE id = $1",
    )
    .bind(host_id)
    .fetch_one(&env.pool)
    .await
    .expect("load boot-interface selection state")
}

fn zero_dpu_host_at_synchronization_entry() -> ManagedHostConfig {
    ManagedHostConfig::zero_dpu().with_expected_state(ManagedHostState::BootConfigSynchronization {
        synchronization_state: BootConfigSynchronizationState::Initialize { target: None },
        synchronization_retry_count: 0,
    })
}

// Unlike `set_primary_dpu`, `set_primary_interface` has no zero-DPU guard -- a
// zero-DPU host is a first-class target. So on a zero-DPU host the call must get
// PAST the would-be guard: it can still fail (here, because the interface id
// doesn't exist), but never with the `FailedPrecondition` "zero-DPU" rejection
// that `set_primary_dpu` returns for the same host.
#[crate::sqlx_test]
async fn test_set_primary_interface_does_not_apply_the_zero_dpu_guard(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env_with_host_inband(pool).await;

    // Stop at the Ready gate so this API validation test does not also depend
    // on driving the observer/controller synchronization fixture.
    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, zero_dpu_host_at_synchronization_entry())
            .await?;

    // A well-formed but non-existent interface id: the handler must try to look
    // it up -- which is only reachable once it's past the would-be zero-DPU
    // guard -- and then fail because the interface isn't there.
    let missing_interface_id =
        MachineInterfaceId::from_str("11111111-1111-1111-1111-111111111111").unwrap();

    let result = env
        .api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(zero_dpu_host.host_snapshot.id),
            interface_id: Some(missing_interface_id),
            reboot: false,
        }))
        .await;

    let err = result.expect_err("a non-existent interface id should still fail the request");
    // Getting PAST the (would-be) zero-DPU guard means we reach the interface
    // lookup and fail THERE -- an InvalidArgument about the missing interface,
    // never the FailedPrecondition "zero-DPU" rejection set_primary_dpu returns.
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "a zero-DPU host should reach the interface lookup, not be rejected by a zero-DPU guard; got {}: {}",
        err.code(),
        err.message(),
    );
    assert!(
        err.message().contains("not found"),
        "expected the missing-interface error, got: {}",
        err.message(),
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_set_primary_interface_uses_the_state_loaded_after_waiting_for_locks(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let host = api_fixtures::create_managed_host_with_config(
        &env,
        ManagedHostConfig::default().with_dpu_count(2),
    )
    .await;
    let host_id = host.id;
    let (bmc_ip, promote_interface_id) = {
        let mut txn = env.db_txn().await;
        let snapshot = host.snapshot(&mut txn).await;
        let bmc_ip = snapshot
            .host_snapshot
            .status
            .bmc_info
            .ip
            .expect("managed host should have a BMC IP");
        let promote_interface_id = snapshot
            .host_snapshot
            .status
            .interfaces
            .iter()
            .find(|interface| {
                !interface.primary_interface && interface.attached_dpu_machine_id.is_some()
            })
            .expect("managed host should have a non-primary host interface to promote")
            .id;
        (bmc_ip, promote_interface_id)
    };

    // Hold the endpoint row after the RPC's initial machine read but before its
    // machine-row lock. A normal controller transition remains free to commit
    // while the RPC waits.
    let mut blocker = env.db_txn().await;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(blocker.as_mut())
        .await?;
    db::explored_endpoints::find_by_ip_for_update(bmc_ip, blocker.as_mut()).await?;

    let request =
        env.api
            .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
                host_machine_id: Some(host_id),
                interface_id: Some(promote_interface_id),
                reboot: false,
            }));
    let pool = env.pool.clone();
    let transition_while_blocked = async move {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let request_is_blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM pg_stat_activity AS activity \
                         WHERE activity.datname = current_database() \
                           AND activity.wait_event_type = 'Lock' \
                           AND $1 = ANY(pg_blocking_pids(activity.pid)) \
                     )",
                )
                .bind(blocker_pid)
                .fetch_one(&pool)
                .await
                .unwrap();
                if request_is_blocked {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("set-primary-interface should wait on the explored endpoint");

        let next_state = ManagedHostState::BootConfigSynchronization {
            synchronization_state: BootConfigSynchronizationState::Initialize { target: None },
            synchronization_retry_count: 0,
        };
        let mut txn = pool.begin().await.unwrap();
        db::machine::update_state(txn.as_mut(), &host_id, &next_state)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        blocker.commit().await.unwrap();
    };
    let (request_result, ()) = tokio::join!(request, transition_while_blocked);
    request_result?;

    let machine = db::machine::find_one(&env.pool, &host_id, MachineSearchConfig::default())
        .await?
        .expect("managed host should still exist");
    assert_eq!(
        machine.current_state(),
        &ManagedHostState::BootConfigSynchronization {
            synchronization_state: BootConfigSynchronizationState::Initialize { target: None },
            synchronization_retry_count: 0,
        },
        "the RPC should use and preserve the state loaded after acquiring its locks",
    );

    let mut txn = env.db_txn().await;
    let primaries = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
        .await?
        .remove(&host_id)
        .expect("managed host should still have interface rows")
        .into_iter()
        .filter(|interface| interface.primary_interface)
        .map(|interface| interface.id)
        .collect::<Vec<_>>();
    assert_eq!(
        primaries,
        vec![promote_interface_id],
        "the RPC should promote the requested interface after waiting for its locks",
    );

    Ok(())
}

// Selecting a different interface commits desired state without disrupting an
// assigned host unless the caller explicitly authorizes synchronization.
#[crate::sqlx_test]
async fn test_set_primary_interface_persists_deferred_selection_without_redfish(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let tenant_segment_id = env.create_vpc_and_tenant_segment().await;

    let host = api_fixtures::create_managed_host_with_config(
        &env,
        ManagedHostConfig::default().with_dpu_count(2),
    )
    .await;
    let instance = host
        .instance_builer(&env)
        .single_interface_network_config(tenant_segment_id)
        .build()
        .await;
    let host_id = host.id;

    // One host interface is primary; pick a different (non-primary) host NIC to promote.
    let (original_primary_id, promote_id) = {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        let original_primary_id = interfaces
            .iter()
            .find(|i| i.primary_interface)
            .expect("host should start with a primary interface")
            .id;
        let promote_id = interfaces
            .iter()
            .find(|i| !i.primary_interface && i.attached_dpu_machine_id.is_some())
            .expect("host should have a non-primary host interface to promote")
            .id;
        (original_primary_id, promote_id)
    };

    let before = boot_selection_state(&env, host_id).await;
    let before_instance_network_version = {
        let mut txn = env.db_txn().await;
        instance.db_instance(&mut txn).await.network_config_version
    };
    let redfish_timepoint = env.redfish_sim.timepoint();

    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;

    // The selected row, generation, and network versions move together while
    // the assigned-host authorization remains empty.
    let after = {
        let mut txn = env.pool.begin().await?;
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should still have interface rows")
    };
    let primaries_now: Vec<_> = after
        .iter()
        .filter(|i| i.primary_interface)
        .map(|i| i.id)
        .collect();
    assert_eq!(
        primaries_now,
        vec![promote_id],
        "exactly the promoted interface should be primary",
    );
    assert!(
        !after
            .iter()
            .find(|i| i.id == original_primary_id)
            .unwrap()
            .primary_interface,
        "the previously-primary interface should no longer be primary",
    );

    let selected = boot_selection_state(&env, host_id).await;
    assert_eq!(
        selected.boot_interface_selection_version.version_nr(),
        before.boot_interface_selection_version.version_nr() + 1,
        "a changed selection should create a new generation",
    );
    assert_eq!(
        selected.network_config_version.version_nr(),
        before.network_config_version.version_nr() + 1,
        "a changed selection should publish a new machine network config",
    );
    let selected_instance_network_version = {
        let mut txn = env.db_txn().await;
        instance.db_instance(&mut txn).await.network_config_version
    };
    assert_eq!(
        selected_instance_network_version.version_nr(),
        before_instance_network_version.version_nr() + 1,
        "a changed selection should publish a new instance network config",
    );
    assert!(
        selected.boot_config_synchronization_requested.is_none(),
        "reboot=false should leave the changed assigned selection deferred",
    );
    assert!(
        env.redfish_sim
            .actions_since(&redfish_timepoint)
            .all_hosts()
            .is_empty(),
        "the API path must leave Redfish synchronization to machine-controller",
    );

    // The same already-primary selection can be authorized later without
    // pretending that desired state changed again.
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: true,
        }))
        .await?;
    let authorized = boot_selection_state(&env, host_id).await;
    let authorization = authorized
        .boot_config_synchronization_requested
        .as_deref()
        .expect("reboot=true should authorize the already-primary selection");
    assert_eq!(authorization.interface_id, promote_id);
    assert_eq!(
        authorization.selection_version, selected.boot_interface_selection_version,
        "the authorization must name the exact selected generation",
    );
    assert_eq!(
        authorized.boot_interface_selection_version,
        selected.boot_interface_selection_version,
    );
    assert_eq!(
        authorized.network_config_version,
        selected.network_config_version,
    );
    let authorized_instance_network_version = {
        let mut txn = env.db_txn().await;
        instance.db_instance(&mut txn).await.network_config_version
    };
    assert_eq!(
        authorized_instance_network_version,
        selected_instance_network_version,
    );

    // Re-selecting without authorization revokes the pending work without
    // publishing another selection or network version.
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;
    let cleared = boot_selection_state(&env, host_id).await;
    assert!(
        cleared.boot_config_synchronization_requested.is_none(),
        "reboot=false should clear a prior authorization",
    );
    assert_eq!(
        cleared.boot_interface_selection_version,
        selected.boot_interface_selection_version,
    );
    assert_eq!(
        cleared.network_config_version,
        selected.network_config_version,
    );
    let cleared_instance_network_version = {
        let mut txn = env.db_txn().await;
        instance.db_instance(&mut txn).await.network_config_version
    };
    assert_eq!(
        cleared_instance_network_version,
        selected_instance_network_version,
    );
    assert!(
        env.redfish_sim
            .actions_since(&redfish_timepoint)
            .all_hosts()
            .is_empty(),
        "selecting, authorizing, and revoking should not call Redfish from the API path",
    );

    Ok(())
}

// An integrated host may select its HostInband NIC while the DPU-backed Admin
// links remain present but dormant. Address reconciliation supports this
// configuration, so the API must not impose an Admin-only primary restriction.
#[crate::sqlx_test]
async fn test_set_primary_interface_allows_host_inband_interface_on_dpu_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env_with_host_inband(pool).await;

    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;
    let stale_prediction_mac = MacAddress::from_str("9a:9b:9c:9d:9e:b4")?;

    // Add a physical NIC owned directly by the host. Unlike the DPU-backed
    // Admin links, an integrated NIC has no attached DPU machine.
    let promote_id = {
        let mut txn = env.pool.begin().await?;
        let host_inband_gateway = FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.ip();
        let host_inband_segment = db::network_segment::for_segment_type_all(
            txn.as_mut(),
            std::slice::from_ref(&host_inband_gateway),
            NetworkSegmentType::HostInband,
        )
        .await?
        .into_iter()
        .next()
        .expect("the HostInband fixture segment should exist");
        let host_nic = db::machine_interface::create(
            txn.as_mut(),
            std::slice::from_ref(&host_inband_segment),
            &MacAddress::from_str("9a:9b:9c:9d:9e:b3")?,
            false,
            AddressSelectionStrategy::NextAvailableIp,
            None,
        )
        .await?;
        db::machine_interface::associate_interface_with_machine(
            &host_nic.id,
            MachineInterfaceAssociation::Machine(host_id),
            txn.as_mut(),
        )
        .await?;
        db::machine_interface::demote_primary_interfaces_for_machine(&host_id, txn.as_mut())
            .await?;
        db::machine_interface::set_primary_interface(&host_nic.id, true, txn.as_mut()).await?;
        db::machine_interface::reconcile_admin_addresses_for_host(txn.as_mut(), &host_id).await?;
        db::predicted_machine_interface::create(
            NewPredictedMachineInterface {
                machine_id: &host_id,
                mac_address: stale_prediction_mac,
                expected_network_segment_type: NetworkSegmentType::HostInband,
                boot_interface_id: Some("NIC.Integrated.9-1-1".to_string()),
                primary_interface: true,
            },
            txn.as_mut(),
        )
        .await?;
        txn.commit().await?;
        host_nic.id
    };

    {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        let integrated_nic = interfaces
            .iter()
            .find(|interface| interface.id == promote_id)
            .expect("the integrated NIC should belong to the host");
        assert!(integrated_nic.attached_dpu_machine_id.is_none());
        assert!(integrated_nic.primary_interface);
    }

    // Model a stale assigned-host authorization. Unassigned selection owns
    // synchronization through its parent state, so the API must clear this
    // request instead of leaving it reusable.
    let mut txn = env.pool.begin().await?;
    let selection_version =
        db::machine::lock_boot_interface_selection_version(&mut txn, host_id).await?;
    db::machine::set_boot_config_synchronization_request(
        &mut txn,
        host_id,
        selection_version,
        promote_id,
        false,
        true,
        Some("set-primary-interface-test".to_string()),
    )
    .await?;
    txn.commit().await?;

    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
        .await?
        .remove(&host_id)
        .expect("host should still have interface rows");
    let selected = interfaces
        .iter()
        .find(|interface| interface.primary_interface)
        .expect("host should have a selected primary interface");
    assert_eq!(selected.id, promote_id);
    assert!(selected.attached_dpu_machine_id.is_none());
    assert_eq!(
        selected.network_segment_type,
        Some(NetworkSegmentType::HostInband),
    );
    let dpu_admin_interfaces = interfaces
        .iter()
        .filter(|interface| {
            interface.network_segment_type == Some(NetworkSegmentType::Admin)
                && interface.attached_dpu_machine_id.is_some()
        })
        .collect::<Vec<_>>();
    assert_eq!(dpu_admin_interfaces.len(), 2);
    assert!(
        dpu_admin_interfaces
            .iter()
            .all(|interface| !interface.primary_interface && interface.addresses.is_empty()),
        "the DPU Admin links should remain present but dormant",
    );
    let stale_prediction =
        db::predicted_machine_interface::find_by_mac_address(txn.as_mut(), stale_prediction_mac)
            .await?
            .expect("the pending integrated-NIC prediction should remain available");
    assert!(
        !stale_prediction.primary_interface,
        "the explicit owned-row selection should clear older predicted primary intent",
    );

    let machine = db::machine::find_one(txn.as_mut(), &host_id, MachineSearchConfig::default())
        .await?
        .expect("host machine should still exist");
    assert_eq!(
        machine.boot_interface_selection_version.version_nr(),
        selection_version.version_nr() + 1,
        "clearing a higher-precedence primary prediction changes the effective selection",
    );
    assert!(
        machine.boot_config_synchronization_requested.is_none(),
        "an unassigned selection should clear assigned-host authorization",
    );
    match machine.current_state() {
        ManagedHostState::BootConfigSynchronization {
            synchronization_state:
                BootConfigSynchronizationState::WaitingForInitialObservation { target, .. },
            ..
        } => {
            assert_eq!(target.machine_interface_id, Some(promote_id));
            assert_eq!(
                target.selection_version,
                machine.boot_interface_selection_version,
            );
        }
        state => panic!("an unassigned selection should start synchronization, got {state:?}"),
    }

    Ok(())
}

/// Operator selection may target either supported host-management topology,
/// but it must never turn an infrastructure or tenant row into the host's
/// primary boot interface.
#[crate::sqlx_test]
async fn test_set_primary_interface_rejects_non_host_boot_segments(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone, Copy)]
    struct IneligibleSegment {
        id: NetworkSegmentId,
        segment_type: NetworkSegmentType,
    }

    let env = api_fixtures::create_test_env(pool).await;
    let tenant_segment_id = env.create_vpc_and_tenant_segment().await;
    let underlay_segment_id = {
        let mut txn = env.db_txn().await;
        db::network_segment::list_segment_ids(txn.as_mut(), Some(NetworkSegmentType::Underlay))
            .await?
            .into_iter()
            .next()
            .expect("the test environment must have an Underlay segment")
    };
    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;
    let (original_primary_id, candidate_id) = {
        let mut txn = env.db_txn().await;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("the host must have interface rows");
        (
            interfaces
                .iter()
                .find(|interface| interface.primary_interface)
                .expect("the host must have a primary interface")
                .id,
            interfaces
                .iter()
                .find(|interface| {
                    !interface.primary_interface && interface.attached_dpu_machine_id.is_some()
                })
                .expect("the host must have another selectable physical interface")
                .id,
        )
    };
    let selection_version = boot_selection_state(&env, host_id)
        .await
        .boot_interface_selection_version;

    check_cases_async(
        [
            Case {
                scenario: "Underlay infrastructure interface",
                input: IneligibleSegment {
                    id: underlay_segment_id,
                    segment_type: NetworkSegmentType::Underlay,
                },
                expect: Yields(()),
            },
            Case {
                scenario: "Tenant workload interface",
                input: IneligibleSegment {
                    id: tenant_segment_id,
                    segment_type: NetworkSegmentType::Tenant,
                },
                expect: Yields(()),
            },
        ],
        |case| {
            let env = &env;
            async move {
                sqlx::query("UPDATE machine_interfaces SET segment_id = $1 WHERE id = $2")
                    .bind(case.id)
                    .bind(candidate_id)
                    .execute(&env.pool)
                    .await
                    .expect("move the candidate onto the segment under test");

                let error = env
                    .api
                    .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
                        host_machine_id: Some(host_id),
                        interface_id: Some(candidate_id),
                        reboot: false,
                    }))
                    .await
                    .expect_err("a non-host segment must be rejected");
                assert_eq!(error.code(), tonic::Code::InvalidArgument);
                assert!(
                    error.message().contains(&case.segment_type.to_string()),
                    "the error should identify the rejected segment: {}",
                    error.message(),
                );

                let mut txn = env.db_txn().await;
                let interfaces =
                    db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
                        .await
                        .expect("reload the host interfaces")
                        .remove(&host_id)
                        .expect("the host must still have interface rows");
                assert_eq!(
                    interfaces
                        .iter()
                        .find(|interface| interface.primary_interface)
                        .map(|interface| interface.id),
                    Some(original_primary_id),
                    "a rejected selection must preserve the current primary interface",
                );
                assert_eq!(
                    boot_selection_state(env, host_id)
                        .await
                        .boot_interface_selection_version,
                    selection_version,
                    "a rejected selection must not publish a new desired generation",
                );

                Ok::<_, ()>(())
            }
        },
    )
    .await;

    Ok(())
}

// Success path on a zero-DPU host: it has no DPU-backed Admin interface, and
// set_primary_interface can select its plain HostInband NIC. A zero-DPU host
// has no primary flag at ingestion, so this records the first selection.
#[crate::sqlx_test]
async fn test_set_primary_interface_promotes_a_zero_dpu_host_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env_with_host_inband(pool).await;

    // Stop at the Ready gate so this test can inspect the database handoff
    // independently from the controller synchronization tests.
    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, zero_dpu_host_at_synchronization_entry())
            .await?;
    let host_id = zero_dpu_host.host_snapshot.id;

    // A zero-DPU host's plain NIC lands on the HostInband segment and is not flagged
    // primary at ingestion -- promote it by id.
    let promote_id = {
        let mut txn = env.pool.begin().await?;
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("zero-DPU host should have interface rows")
            .into_iter()
            .find(|i| {
                i.network_segment_type == Some(NetworkSegmentType::HostInband)
                    && !i.primary_interface
            })
            .expect("zero-DPU host should have a non-primary HostInband interface")
            .id
    };

    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;

    // Exactly the promoted interface is now primary.
    let primaries_now: Vec<_> = {
        let mut txn = env.pool.begin().await?;
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("zero-DPU host should still have interface rows")
            .into_iter()
            .filter(|i| i.primary_interface)
            .map(|i| i.id)
            .collect()
    };
    assert_eq!(
        primaries_now,
        vec![promote_id],
        "exactly the promoted zero-DPU interface should be primary",
    );

    Ok(())
}

// Regression for the pre-move reconcile ordering: on a DPU-backed host left with
// no Admin primary, selecting a valid Admin interface must succeed rather than
// fail before address ownership can be restored.
#[crate::sqlx_test]
async fn test_set_primary_interface_restores_dpu_host_with_no_admin_primary(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;

    // The current Admin primary, plus a non-primary Admin interface to promote.
    let (current_primary_id, promote_id) = {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        let current_primary_id = interfaces
            .iter()
            .find(|i| i.primary_interface)
            .expect("host should start with a primary interface")
            .id;
        let promote_id = interfaces
            .iter()
            .find(|i| !i.primary_interface && i.attached_dpu_machine_id.is_some())
            .expect("host should have a non-primary DPU-backed interface")
            .id;
        (current_primary_id, promote_id)
    };

    // Break the happy path: clear the host's primary flag, leaving its DPU-backed
    // admin interfaces with no primary -- the state the pre-move reconcile chokes on.
    sqlx::query("UPDATE machine_interfaces SET primary_interface = false WHERE id = $1")
        .bind(current_primary_id)
        .execute(&env.pool)
        .await?;

    // Selecting the Admin interface must restore the primary designation.
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;

    // The promoted interface is now the only primary.
    let primaries_now: Vec<_> = {
        let mut txn = env.pool.begin().await?;
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should still have interface rows")
            .into_iter()
            .filter(|i| i.primary_interface)
            .map(|i| i.id)
            .collect()
    };
    assert_eq!(
        primaries_now,
        vec![promote_id],
        "exactly the promoted interface should be primary after the repair",
    );

    Ok(())
}
