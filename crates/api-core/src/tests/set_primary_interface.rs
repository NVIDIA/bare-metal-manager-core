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

use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_uuid::machine::MachineInterfaceId;
use ipnetwork::IpNetwork;
use model::machine::{InstanceState, ManagedHostState};
use model::machine_boot_interface::MachineBootInterfaceTarget;
use model::network_segment::NetworkSegmentType;
use model::test_support::ManagedHostConfig;
use rpc::forge;
use rpc::forge::forge_server::Forge;
use sqlx::types::Json;

use crate::test_support::fixture_config::{FixtureDefault as _, ManagedHostConfigExt as _};
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY, create_admin_network_segment,
    create_host_inband_network_segment, create_underlay_network_segment,
};

// Unlike `set_primary_dpu`, `set_primary_interface` has no zero-DPU guard -- a
// zero-DPU host is a first-class target. So on a zero-DPU host the call must get
// PAST the would-be guard: it can still fail (here, because the interface id
// doesn't exist), but never with the `FailedPrecondition` "zero-DPU" rejection
// that `set_primary_dpu` returns for the same host.
#[crate::sqlx_test]
async fn test_set_primary_interface_does_not_apply_the_zero_dpu_guard(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Zero-DPU host ingestion needs a HostInband network segment whose CIDR
    // covers the relay address; the default test env doesn't define one.
    let env = api_fixtures::create_test_env_with_overrides(
        pool,
        api_fixtures::TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;
    // HostInband segments must live in a Flat VPC. The test doesn't otherwise
    // need a non-Flat VPC, so create only a Flat one for the segment.
    let flat_vpc_id = api_fixtures::network_segment::create_default_flat_vpc(
        &env.api,
        "set-primary-interface flat vpc",
    )
    .await;
    create_underlay_network_segment(&env.api).await;
    create_admin_network_segment(&env.api).await;
    create_host_inband_network_segment(&env.api, Some(flat_vpc_id)).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::zero_dpu()).await?;

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
            force_reconcile: false,
            ..Default::default()
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

// `set_primary_interface` commits the primary row and desired target together.
// Redfish is deliberately absent from this request path: machine-controller
// picks the pending generation up after the transaction commits.
#[crate::sqlx_test]
#[allow(deprecated)] // The test verifies the compatibility behavior of `reboot`.
async fn test_set_primary_interface_promotes_a_non_primary_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;

    // One host interface is primary; pick a different (non-primary) host NIC to promote.
    let (original_primary_id, promote_id, promote_target) = {
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
        let promote = interfaces
            .iter()
            .find(|i| !i.primary_interface && i.attached_dpu_machine_id.is_some())
            .expect("host should have a non-primary host interface to promote");
        let promote_target = MachineBootInterfaceTarget::from_parts(
            Some(promote.mac_address),
            promote.boot_interface_id.clone(),
        )
        .expect("a host interface always supplies a MAC");
        (original_primary_id, promote.id, promote_target)
    };

    let timepoint = env.redfish_sim.timepoint();
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: false,
            ..Default::default()
        }))
        .await?;

    let actions = env.redfish_sim.actions_since(&timepoint).all_hosts();
    assert_eq!(
        actions,
        Vec::<RedfishSimAction>::new(),
        "the managed request should leave Redfish convergence to machine-controller",
    );

    // The primary flag moved onto the promoted interface, and off the old one.
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
    let desired = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("the selected target should be persisted");
    assert_eq!(desired.value, promote_target);

    let error = env
        .api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: false,
            ..Default::default()
        }))
        .await
        .expect_err("selecting the current primary without force should retain the API guard");
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(
        error.message().contains("already primary"),
        "expected the already-primary guard error, got: {}",
        error.message(),
    );

    sqlx::query("DELETE FROM machine_state_controller_queued_objects WHERE object_id = $1")
        .bind(host_id.to_string())
        .execute(&env.pool)
        .await?;
    let timepoint = env.redfish_sim.timepoint();
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: true,
            ..Default::default()
        }))
        .await?;
    let forced = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("the forced request should retain the desired target");
    assert_eq!(forced.value, promote_target);
    assert_eq!(
        forced.version.version_nr(),
        desired.version.version_nr() + 1,
    );
    let forced_is_queued: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM machine_state_controller_queued_objects
            WHERE object_id = $1
        )",
    )
    .bind(host_id.to_string())
    .fetch_one(&env.pool)
    .await?;
    assert!(
        forced_is_queued,
        "a forced generation must wake the controller",
    );
    assert!(
        env.redfish_sim
            .actions_since(&timepoint)
            .all_hosts()
            .is_empty(),
        "force_reconcile should schedule controller work, not write Redfish directly",
    );

    // `reboot` remains a compatibility spelling for the same fresh controller
    // pass. It no longer means an unconditional restart in the RPC path.
    let timepoint = env.redfish_sim.timepoint();
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: true,
            force_reconcile: false,
        }))
        .await?;
    let legacy_forced = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("the legacy alias should retain the desired target");
    assert_eq!(legacy_forced.value, promote_target);
    assert_eq!(
        legacy_forced.version.version_nr(),
        forced.version.version_nr() + 1,
    );
    assert!(
        env.redfish_sim
            .actions_since(&timepoint)
            .all_hosts()
            .is_empty(),
        "the deprecated reboot alias should not restart from the request path",
    );

    Ok(())
}

// `set_primary_interface` changes interface rows before it writes the desired
// target. A late database error must roll the whole transaction back so the
// machine controller can never see a primary/target mismatch.
#[crate::sqlx_test]
async fn test_set_primary_interface_rolls_back_primary_and_desired_together(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;

    let (original_primary_id, promote_id) = {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        let original_primary_id = interfaces
            .iter()
            .find(|interface| interface.primary_interface)
            .expect("host should start with a primary interface")
            .id;
        let promote_id = interfaces
            .iter()
            .find(|interface| {
                !interface.primary_interface && interface.attached_dpu_machine_id.is_some()
            })
            .expect("host should have a non-primary DPU-backed interface")
            .id;
        txn.commit().await?;
        (original_primary_id, promote_id)
    };
    let desired_before = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("ingestion should initialize the desired target");

    sqlx::raw_sql(
        r#"
        CREATE FUNCTION reject_desired_boot_interface_write()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'forced desired boot interface failure';
        END;
        $$;

        CREATE TRIGGER reject_desired_boot_interface_write
        BEFORE INSERT OR UPDATE ON machine_boot_interfaces
        FOR EACH ROW
        EXECUTE FUNCTION reject_desired_boot_interface_write();
        "#,
    )
    .execute(&env.pool)
    .await?;

    let error = env
        .api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: false,
            ..Default::default()
        }))
        .await
        .expect_err("the injected desired-target write must fail the request");
    assert_eq!(error.code(), tonic::Code::Internal);

    let primary_ids = {
        let mut txn = env.pool.begin().await?;
        let primary_ids = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should still have interface rows")
            .into_iter()
            .filter(|interface| interface.primary_interface)
            .map(|interface| interface.id)
            .collect::<Vec<_>>();
        txn.commit().await?;
        primary_ids
    };
    assert_eq!(primary_ids, vec![original_primary_id]);

    let desired_after = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("the original desired target should remain");
    assert_eq!(desired_after.value, desired_before.value);
    assert_eq!(desired_after.version, desired_before.version);

    Ok(())
}

// `set_primary_interface` wakes an unassigned Ready host only after its intent
// commits. Assigned hosts keep the same durable pending intent, but their
// current lifecycle owns when it is safe to act on it.
#[crate::sqlx_test]
async fn test_set_primary_interface_hands_ready_intent_to_the_controller(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;
    assert_eq!(host.managed_state, ManagedHostState::Ready);

    let (original_primary_id, original_target, promote_id) = {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        let original = interfaces
            .iter()
            .find(|interface| interface.primary_interface)
            .expect("host should start with a primary interface");
        let promote = interfaces
            .iter()
            .find(|interface| {
                !interface.primary_interface && interface.attached_dpu_machine_id.is_some()
            })
            .expect("host should have a non-primary DPU-backed interface");
        let original_target = MachineBootInterfaceTarget::from_parts(
            Some(original.mac_address),
            original.boot_interface_id.clone(),
        )
        .expect("a host interface always supplies a MAC");
        txn.commit().await?;
        (original.id, original_target, promote.id)
    };

    sqlx::query("DELETE FROM machine_state_controller_queued_objects WHERE object_id = $1")
        .bind(host_id.to_string())
        .execute(&env.pool)
        .await?;
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: false,
            ..Default::default()
        }))
        .await?;

    let ready_is_queued: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM machine_state_controller_queued_objects
            WHERE object_id = $1
        )",
    )
    .bind(host_id.to_string())
    .fetch_one(&env.pool)
    .await?;
    assert!(ready_is_queued, "the Ready host should be queued");
    let ready_pending: bool = sqlx::query_scalar(
        "SELECT desired_version IS DISTINCT FROM verified_version
         FROM machine_boot_interfaces
         WHERE machine_id = $1",
    )
    .bind(host_id)
    .fetch_one(&env.pool)
    .await?;
    assert!(ready_pending, "the committed target should remain pending");
    let ready_state: Json<ManagedHostState> =
        sqlx::query_scalar("SELECT controller_state FROM machines WHERE id = $1")
            .bind(host_id)
            .fetch_one(&env.pool)
            .await?;
    assert_eq!(ready_state.0, ManagedHostState::Ready);
    let ready_desired = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("the Ready request should persist its target");

    sqlx::query("DELETE FROM machine_state_controller_queued_objects WHERE object_id = $1")
        .bind(host_id.to_string())
        .execute(&env.pool)
        .await?;
    let assigned_state = ManagedHostState::Assigned {
        instance_state: InstanceState::Ready,
    };
    sqlx::query("UPDATE machines SET controller_state = $1 WHERE id = $2")
        .bind(Json(assigned_state.clone()))
        .bind(host_id)
        .execute(&env.pool)
        .await?;

    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(original_primary_id),
            force_reconcile: false,
            ..Default::default()
        }))
        .await?;

    let assigned_is_queued: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM machine_state_controller_queued_objects
            WHERE object_id = $1
        )",
    )
    .bind(host_id.to_string())
    .fetch_one(&env.pool)
    .await?;
    assert!(
        !assigned_is_queued,
        "the Assigned host should stay with its current lifecycle",
    );
    let assigned_pending: bool = sqlx::query_scalar(
        "SELECT desired_version IS DISTINCT FROM verified_version
         FROM machine_boot_interfaces
         WHERE machine_id = $1",
    )
    .bind(host_id)
    .fetch_one(&env.pool)
    .await?;
    assert!(
        assigned_pending,
        "the Assigned host should retain its pending target",
    );
    let assigned_state_after: Json<ManagedHostState> =
        sqlx::query_scalar("SELECT controller_state FROM machines WHERE id = $1")
            .bind(host_id)
            .fetch_one(&env.pool)
            .await?;
    assert_eq!(assigned_state_after.0, assigned_state);
    let assigned_desired = db::machine_desired_boot_interface::get(&env.pool, &host_id)
        .await?
        .expect("the Assigned request should persist its target");
    assert_eq!(assigned_desired.value, original_target);
    assert_eq!(
        assigned_desired.version.version_nr(),
        ready_desired.version.version_nr() + 1,
    );

    Ok(())
}

// A DPU-managed host's primary must stay on the Admin segment (the admin DHCP
// address + DNS identity follow it, and admin-address reconciliation requires a
// primary among the host's DPU-backed admin interfaces). set_primary_interface
// rejects a non-admin target up-front -- BEFORE touching the BMC -- rather than
// failing deeper in reconciliation with the boot order already changed.
#[crate::sqlx_test]
async fn test_set_primary_interface_rejects_non_admin_interface_on_dpu_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(2))
            .await?;
    let host_id = host.host_snapshot.id;

    // A non-primary host interface to target. The host's other DPU interface
    // stays the Admin primary, so the host still has a DPU-backed admin link.
    let promote_id = {
        let mut txn = env.pool.begin().await?;
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows")
            .into_iter()
            .find(|i| !i.primary_interface && i.attached_dpu_machine_id.is_some())
            .expect("host should have a non-primary host interface")
            .id
    };

    // Craft the (off-happy-path) mixed shape: move that interface onto a
    // non-admin segment so it is no longer Admin-segment.
    sqlx::query(
        "UPDATE machine_interfaces SET segment_id = \
         (SELECT id FROM network_segments WHERE network_segment_type <> 'admin' LIMIT 1) \
         WHERE id = $1",
    )
    .bind(promote_id)
    .execute(&env.pool)
    .await?;

    let err = env
        .api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: false,
            ..Default::default()
        }))
        .await
        .expect_err("promoting a non-admin interface on a DPU host should be rejected");

    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected an up-front InvalidArgument, got {}: {}",
        err.code(),
        err.message(),
    );
    assert!(
        err.message().contains("admin segment"),
        "expected the Admin-segment guard message, got: {}",
        err.message(),
    );

    Ok(())
}

// Success path on a ZERO-DPU host -- the case this feature exists to enable. A
// zero-DPU host has no DPU-backed admin interface, so neither the zero-DPU guard
// nor the Admin-segment constraint applies, and set_primary_interface can promote
// its plain HostInband NIC. (A zero-DPU host has no primary flag set at ingestion,
// so this records the first primary.)
#[crate::sqlx_test]
async fn test_set_primary_interface_promotes_a_zero_dpu_host_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Zero-DPU host ingestion needs a HostInband segment whose CIDR covers the
    // relay address; the default test env doesn't define one.
    let env = api_fixtures::create_test_env_with_overrides(
        pool,
        api_fixtures::TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;
    // HostInband segments must live in a Flat VPC.
    let flat_vpc_id = api_fixtures::network_segment::create_default_flat_vpc(
        &env.api,
        "set-primary-interface zero-dpu flat vpc",
    )
    .await;
    create_underlay_network_segment(&env.api).await;
    create_admin_network_segment(&env.api).await;
    create_host_inband_network_segment(&env.api, Some(flat_vpc_id)).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::zero_dpu()).await?;
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
            force_reconcile: false,
            ..Default::default()
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

// A DPU-backed host can be left with no admin primary after an interrupted
// repair. Promoting a valid Admin interface must rebuild that ownership rather
// than fail the pre-move reconciliation on the already-broken state.
#[crate::sqlx_test]
async fn test_set_primary_interface_repairs_dpu_host_with_no_admin_primary(
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

    // Promoting the Admin interface must succeed (repair), not error after the BMC call.
    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            force_reconcile: false,
            ..Default::default()
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
