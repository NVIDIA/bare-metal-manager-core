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

use carbide_uuid::machine::MachineInterfaceId;
use ipnetwork::IpNetwork;
use model::network_segment::NetworkSegmentType;
use rpc::forge;
use rpc::forge::forge_server::Forge;

use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::dpu::DpuConfig;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
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
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::with_dpus(vec![])).await?;

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

// Success path: `set_primary_interface` promotes any interface (by id) to be the
// host's primary boot interface. A two-DPU host starts with one primary host
// interface and one non-primary one; promoting the non-primary by id must move
// the primary flag onto it. The handler sets the host's boot order on the BMC
// *before* moving the flag, so a successful promotion already implies the
// boot-order call ran (it would have errored out before the flag move otherwise).
#[crate::sqlx_test]
async fn test_set_primary_interface_promotes_a_non_primary_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host = api_fixtures::site_explorer::new_host(
        &env,
        ManagedHostConfig::with_dpus(vec![DpuConfig::default(), DpuConfig::default()]),
    )
    .await?;
    let host_id = host.host_snapshot.id;

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

    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;

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

    let host = api_fixtures::site_explorer::new_host(
        &env,
        ManagedHostConfig::with_dpus(vec![DpuConfig::default(), DpuConfig::default()]),
    )
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
            reboot: false,
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
        err.message().contains("Admin segment"),
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
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::with_dpus(vec![])).await?;
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

// Regression for the pre-move reconcile ordering: on a DPU-backed host left with NO
// admin primary (an off-happy-path state), promoting a valid Admin interface must
// SUCCEED -- repairing the host -- rather than erroring in admin reconciliation
// after the BMC boot order was already changed. set_primary_interface skips the
// pre-move reconcile when there is no admin primary to preserve.
#[crate::sqlx_test]
async fn test_set_primary_interface_repairs_dpu_host_with_no_admin_primary(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host = api_fixtures::site_explorer::new_host(
        &env,
        ManagedHostConfig::with_dpus(vec![DpuConfig::default(), DpuConfig::default()]),
    )
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
