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

//! Admin boot-interface resolution: the by-BMC-endpoint admin RPCs
//! (`machine_setup`, `set_dpu_first_boot_order`) resolve a host's boot
//! interface from the machine's own `machine_interfaces` rows -- the same
//! designation every other flow acts on -- and use site-explorer's explored
//! default only for endpoints no machine owns. (Owned endpoints with no
//! candidate rows -- DPU machines, BMC-only hosts -- fall through to that
//! default too, but the explorer never records one for them, so in practice
//! they run with no target, matching the machine-controller.)
//!
//! The Redfish sim records the MAC each boot-order call targeted, so these
//! tests assert the *selection* end to end; the pair-vs-MAC-only upgrade
//! details are unit-tested next to the resolver itself.

use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_uuid::machine::MachineId;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use model::network_segment::NetworkSegmentType;
use model::test_support::{DpuConfig, ManagedHostConfig};
use rpc::forge;
use rpc::forge::forge_server::Forge;

use crate::handlers::bmc_endpoint_explorer::boot_interface_candidates;
use crate::test_support::fixture_config::{FixtureDefault as _, ManagedHostConfigExt as _};
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY, create_admin_network_segment,
    create_host_inband_network_segment, create_underlay_network_segment,
};

/// Creates a two-DPU host and moves its primary to a different host interface
/// via `set_primary_interface`, returning the host id and the promoted
/// interface's MAC -- the boot interface the admin actions under test must now
/// target.
async fn host_with_moved_primary(
    env: &api_fixtures::TestEnv,
) -> Result<(MachineId, MacAddress), Box<dyn std::error::Error>> {
    let host = api_fixtures::site_explorer::new_host(
        env,
        ManagedHostConfig::with_dpus(vec![DpuConfig::default(), DpuConfig::default()]),
    )
    .await?;
    let host_id = host.host_snapshot.id;

    let (promote_id, promote_mac) = {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        let promote = interfaces
            .iter()
            .find(|i| !i.primary_interface && i.attached_dpu_machine_id.is_some())
            .expect("host should have a non-primary host interface to promote");
        (promote.id, promote.mac_address)
    };

    env.api
        .set_primary_interface(tonic::Request::new(forge::SetPrimaryInterfaceRequest {
            host_machine_id: Some(host_id),
            interface_id: Some(promote_id),
            reboot: false,
        }))
        .await?;

    Ok((host_id, promote_mac))
}

// An operator-moved primary is the boot interface the admin path must target:
// after set-primary-interface, a no-MAC set_dpu_first_boot_order resolves the
// promoted interface from the machine's own rows. (It used to resolve
// site-explorer's explored default, which still names the original NIC --
// re-applying the very boot order the operator just moved away from.)
#[crate::sqlx_test]
async fn test_set_dpu_first_targets_an_operator_moved_primary(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let (host_id, promote_mac) = host_with_moved_primary(&env).await?;

    // Only observe the admin RPC below, not the promotion's own boot-order call.
    let timepoint = env.redfish_sim.timepoint();

    env.api
        .set_dpu_first_boot_order(tonic::Request::new(forge::SetDpuFirstBootOrderRequest {
            machine_id: Some(host_id.to_string()),
            bmc_endpoint_request: None,
            boot_interface_mac: None,
        }))
        .await?;

    let actions = env.redfish_sim.actions_since(&timepoint).all_hosts();
    assert_eq!(
        actions,
        vec![RedfishSimAction::SetBootOrderDpuFirst {
            boot_interface_mac: promote_mac.to_string(),
        }],
        "the admin path should target the operator-moved primary, not the explored default",
    );

    Ok(())
}

// machine_setup shares the resolver with set_dpu_first_boot_order but has its
// own downstream semantics (BIOS boot-device pinning rather than boot-order
// promotion) -- assert its resolved target end to end as well: after
// set-primary-interface, an admin machine_setup configures BIOS for the
// promoted NIC, not the explored default.
#[crate::sqlx_test]
async fn test_machine_setup_targets_an_operator_moved_primary(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let (host_id, promote_mac) = host_with_moved_primary(&env).await?;

    let timepoint = env.redfish_sim.timepoint();

    env.api
        .machine_setup(tonic::Request::new(forge::MachineSetupRequest {
            machine_id: Some(host_id.to_string()),
            bmc_endpoint_request: None,
            boot_interface_mac: None,
        }))
        .await?;

    let actions = env.redfish_sim.actions_since(&timepoint).all_hosts();
    let targeted = actions
        .iter()
        .find_map(|action| match action {
            RedfishSimAction::MachineSetup {
                boot_interface_mac, ..
            } => Some(boot_interface_mac.clone()),
            _ => None,
        })
        .expect("machine_setup should have been called");
    assert_eq!(
        targeted,
        Some(promote_mac.to_string()),
        "machine_setup should configure BIOS for the operator-moved primary",
    );

    Ok(())
}

// A zero-DPU host has no explored default (site-explorer's automatic pick only
// resolves for DPU-mode hosts), so a no-MAC set_dpu_first_boot_order used to
// fail with "explore the host first". The machine's own interface rows resolve
// it now: the HostInband NIC -- the same row the machine-controller boots the
// host from -- is the target.
#[crate::sqlx_test]
async fn test_set_dpu_first_resolves_a_zero_dpu_host_without_an_explored_default(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Zero-DPU ingestion needs a HostInband segment with a routable relay
    // address; the default test env doesn't define one.
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
        "boot-interface-resolution zero-dpu flat vpc",
    )
    .await;
    create_underlay_network_segment(&env.api).await;
    create_admin_network_segment(&env.api).await;
    create_host_inband_network_segment(&env.api, Some(flat_vpc_id)).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::with_dpus(vec![])).await?;
    let host_id = host.host_snapshot.id;

    let inband_mac = {
        let mut txn = env.pool.begin().await?;
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("zero-DPU host should have interface rows")
            .into_iter()
            .find(|i| i.network_segment_type == Some(NetworkSegmentType::HostInband))
            .expect("zero-DPU host should have a HostInband interface")
            .mac_address
    };

    let timepoint = env.redfish_sim.timepoint();

    env.api
        .set_dpu_first_boot_order(tonic::Request::new(forge::SetDpuFirstBootOrderRequest {
            machine_id: Some(host_id.to_string()),
            bmc_endpoint_request: None,
            boot_interface_mac: None,
        }))
        .await?;

    let actions = env.redfish_sim.actions_since(&timepoint).all_hosts();
    assert_eq!(
        actions,
        vec![RedfishSimAction::SetBootOrderDpuFirst {
            boot_interface_mac: inband_mac.to_string(),
        }],
        "the zero-DPU host's NIC should resolve from its machine_interfaces row",
    );

    Ok(())
}

// Machine-row resolution applies to hosts (confirmed or predicted) only: a
// DPU machine's endpoint must not resolve a boot-interface target from
// interface rows -- a DPU's own setup runs without one, exactly like the
// machine-controller path.
#[crate::sqlx_test]
async fn test_boot_interface_candidates_skips_dpu_machines(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host = api_fixtures::site_explorer::new_host(
        &env,
        ManagedHostConfig::with_dpus(vec![DpuConfig::default()]),
    )
    .await?;
    let host_id = host.host_snapshot.id;
    let dpu_id = host
        .dpu_snapshots
        .first()
        .expect("host should have a DPU snapshot")
        .id;

    let mut txn = env.pool.begin().await?;
    assert!(
        boot_interface_candidates(txn.as_mut(), Some(dpu_id))
            .await?
            .is_none(),
        "a DPU machine should not resolve boot-interface rows",
    );
    assert!(
        boot_interface_candidates(txn.as_mut(), None)
            .await?
            .is_none(),
        "an unowned endpoint should not resolve boot-interface rows",
    );
    let candidates = boot_interface_candidates(txn.as_mut(), Some(host_id))
        .await?
        .expect("a host machine should resolve its boot-interface candidates");
    assert!(
        candidates.interfaces.iter().any(|i| i.primary_interface),
        "the host's rows should include its primary interface",
    );
    assert!(
        candidates.predicted.is_empty(),
        "a fully-leased DPU host should have no pending predictions",
    );

    Ok(())
}

// The window this PR exists for: a zero-DPU machine has been ingested, but its
// in-band NIC has not taken its first DHCP lease -- no machine_interfaces row
// exists yet, and site-explorer records no explored default for zero-DPU
// hosts, so a no-MAC set_dpu_first_boot_order used to have nothing to resolve.
// The machine's predicted interface (mac + report-derived Redfish id, kept
// fresh every exploration since #2448) now answers.
#[crate::sqlx_test]
async fn test_set_dpu_first_resolves_a_machine_awaiting_its_first_lease(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env_with_host_inband(pool.clone()).await;

    let mock_host = ManagedHostConfig {
        dpus: vec![],
        ..ManagedHostConfig::default()
    };
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();

    let _mock =
        api_fixtures::site_explorer::ingest_zero_dpu_host_awaiting_first_lease(&env, mock_host)
            .await?;

    // Precondition: the machine owns a prediction for the NIC and no real
    // interface row. (The prediction's content is the site-explorer ingest
    // tests' contract; here it only locates the machine.)
    let machine_id = {
        let mut txn = env.pool.begin().await?;
        let predicted = db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
            .await?
            .expect("zero-DPU ingest should have minted a predicted interface");
        assert!(
            db::machine_interface::find_by_mac_address(txn.as_mut(), inband_mac)
                .await?
                .is_empty(),
            "the in-band NIC should not have a machine_interfaces row yet",
        );
        predicted.machine_id
    };

    let timepoint = env.redfish_sim.timepoint();

    env.api
        .set_dpu_first_boot_order(tonic::Request::new(forge::SetDpuFirstBootOrderRequest {
            machine_id: Some(machine_id.to_string()),
            bmc_endpoint_request: None,
            boot_interface_mac: None,
        }))
        .await?;

    let actions = env.redfish_sim.actions_since(&timepoint).all_hosts();
    assert_eq!(
        actions,
        vec![RedfishSimAction::SetBootOrderDpuFirst {
            boot_interface_mac: inband_mac.to_string(),
        }],
        "the machine awaiting its first lease should resolve from its predicted interface",
    );

    Ok(())
}
