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
use std::sync::Arc;
use std::time::Duration;

use carbide_site_explorer::SiteExplorer;
use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_site_explorer::test_support::{MockEndpointExplorer, TestSiteExplorer};
use carbide_test_harness::network::segment::TestNetworkSegment;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use mac_address::MacAddress;
use model::expected_machine::{DpuMode, ExpectedHostNic, ExpectedMachine, ExpectedMachineData};
use model::test_support::ManagedHostConfig;

struct ZeroDpuEnv {
    pool: PgPool,
    test_harness: TestHarness,
    underlay_segment: TestNetworkSegment,
    host_inband_segment: TestNetworkSegment,
    site_explorer: TestSiteExplorer,
}

impl ZeroDpuEnv {
    fn api(&self) -> &Api {
        self.test_harness.api()
    }
}

async fn init(pool: PgPool) -> ZeroDpuEnv {
    let test_harness = TestHarness::builder(pool.clone()).build().await;
    let domain = test_harness.test_domain().await;
    let network_controller = test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    let host_inband_segment = network_controller.create_host_inband_segment(&domain).await;
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let api = test_harness.api();
    let site_explorer = TestSiteExplorer::new(
        SiteExplorer::new(
            api.database_connection.clone(),
            SiteExplorerConfig {
                enabled: Arc::new(true.into()),
                retained_boot_interface_window: None,
                explorations_per_run: 1,
                concurrent_explorations: 1,
                run_interval: Duration::from_secs(1),
                create_machines: Arc::new(true.into()),
                ..Default::default()
            },
            test_harness.test_meter.meter(),
            endpoint_explorer.clone(),
            Arc::new(api.runtime_config.get_firmware_config()),
            api.common_pools().clone(),
            api.work_lock_manager_handle(),
            carbide_site_explorer::EndpointExplorationLocks::default(),
            api.runtime_config.rack_profiles.clone(),
            None,
            api.credential_manager().clone(),
        ),
        endpoint_explorer,
    );

    ZeroDpuEnv {
        pool,
        test_harness,
        underlay_segment,
        host_inband_segment,
        site_explorer,
    }
}

async fn register_zero_dpu_expected_machine(
    env: &ZeroDpuEnv,
    managed_host: &ManagedHostConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: managed_host.bmc_mac_address,
            data: ExpectedMachineData {
                serial_number: managed_host.serial.clone(),
                dpu_mode: DpuMode::NoDpu,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    Ok(())
}

fn zero_dpu_host() -> ManagedHostConfig {
    ManagedHostConfig {
        dpus: vec![],
        ..ManagedHostConfig::default()
    }
}

/// A zero-DPU host whose only NIC is a plain (non-DPU) host NIC.
/// We expect to walk over the report ethernet interfaces and record
/// the NIC's Redfish-reported interface id onto its machine_interface
/// row, matched/paired with its MAC address.
#[sqlx_test]
async fn test_site_explorer_records_boot_interface_id_onto_non_dpu_nic(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let non_dpu_mac = MacAddress::from_str("d4:04:e6:84:13:98").unwrap();
    let mock_host = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![non_dpu_mac],
        ..ManagedHostConfig::default()
    };
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;

    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    let host_dhcp_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(non_dpu_mac, env.host_inband_segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await?
        .into_inner();
    let machine_id = host_dhcp_response
        .machine_id
        .expect("the in-band NIC DHCP should promote the zero-DPU host prediction");

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_machine_ids(&mut txn, &[machine_id]).await?;
    let nic = interfaces
        .get(&machine_id)
        .into_iter()
        .flatten()
        .find(|i| i.mac_address == non_dpu_mac)
        .expect("the non-DPU host NIC should have a machine_interface row");
    assert_eq!(
        nic.boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "exploration should record a non-DPU NIC's Redfish interface id on its row",
    );
    txn.rollback().await?;

    Ok(())
}

/// Site-explorer hands a boot interface id to the predicted interfaces it
/// mints for zero-DPU hosts (from the live report here), and DHCP promotion
/// passes it on to the machine_interfaces row -- so the host's boot
/// target is a full MAC + Redfish-id pair from its first owned interface.
#[sqlx_test]
async fn test_predicted_interface_hands_boot_interface_id_to_real_row(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let mock_host = zero_dpu_host();
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;

    // Site-explorer runs BEFORE the in-band NIC ever DHCPs, so ingestion
    // mints a predicted interface for it.
    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    let mut txn = env.pool.begin().await?;
    let predicted = db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
        .await?
        .expect("zero-DPU ingest should have minted a predicted interface");
    // The fixture report names the embedded NIC's Redfish id.
    assert_eq!(
        predicted.boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "predicted interface should hold the report-derived boot interface id"
    );
    txn.rollback().await?;

    // The in-band NIC's first DHCP promotes the prediction into a
    // machine_interfaces row.
    let host_dhcp_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(inband_mac, env.host_inband_segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await?
        .into_inner();
    assert!(host_dhcp_response.machine_id.is_some());

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_mac_address(txn.as_mut(), inband_mac).await?;
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        interfaces[0].boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "promotion should land the predicted boot interface id on the promoted row"
    );
    assert!(
        db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
            .await?
            .is_none(),
        "the prediction should be consumed by promotion"
    );
    txn.rollback().await?;

    Ok(())
}

/// When a retained boot interface id AND a prediction with a live-report
/// id both exist for a MAC, DHCP promotion lands the LIVE id on the
/// promoted row -- the prediction is refreshed every exploration cycle,
/// while the retained id predates the deletion that recorded it. The
/// retention record is consumed either way.
#[sqlx_test]
async fn test_predicted_live_boot_interface_id_outranks_retained_at_promotion(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let mock_host = zero_dpu_host();
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    // A prior row for this MAC was deleted with its boot pair retained --
    // the id names a slot the NIC occupied before the migration.
    let mut txn = env.pool.begin().await?;
    db::retained_boot_interface::upsert(txn.as_mut(), inband_mac, "NIC.Old.9-9-9").await?;
    txn.commit().await?;

    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;

    // Ingestion mints a predicted interface holding the CURRENT id
    // from the live report.
    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    let mut txn = env.pool.begin().await?;
    let predicted = db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
        .await?
        .expect("zero-DPU ingest should have minted a predicted interface");
    assert_eq!(
        predicted.boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "the prediction holds the live-report id, never the retained one"
    );
    txn.rollback().await?;

    // The in-band NIC's first DHCP promotes the prediction. Creation
    // recovers the retained id onto the brand-new row first -- the
    // prediction's live id must still win.
    env.api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(inband_mac, env.host_inband_segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await?;

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_mac_address(txn.as_mut(), inband_mac).await?;
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        interfaces[0].boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "the live predicted id outranks the retained id on the promoted row"
    );
    assert!(
        db::retained_boot_interface::find_by_mac(txn.as_mut(), inband_mac, None)
            .await?
            .is_none(),
        "the retention record is consumed by promotion regardless"
    );
    txn.rollback().await?;

    Ok(())
}

/// A zero-DPU host with no declared primary recovers its primary (boot)
/// interface from the boot pair preserved across `--delete-interfaces` in
/// `retained_boot_interfaces`. This is the DPU->NIC flip re-registration case:
/// the operator patches `dpu_mode = nic_mode` and force-deletes, declaring no
/// primary, and the host comes back with no managed DPU -- so neither the
/// declared-primary nor the DPU-host-PF path names a primary. Without the
/// retained fallback the re-ingested host would come up with no primary at all,
/// leaving the machine-controller no boot target to set a boot order from.
#[sqlx_test]
async fn test_zero_dpu_recovers_primary_from_retained_boot_interface(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let mock_host = zero_dpu_host();
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    // The host's boot interface was retained by a prior `--delete-interfaces`,
    // keyed by its MAC. Assert the precondition this test turns on: the
    // registered machine declares no primary, so the retained fallback -- not
    // the declared-primary path -- is what settles the boot interface below.
    let mut txn = env.pool.begin().await?;
    let registered =
        db::expected_machine::find_by_bmc_mac_address(&mut *txn, mock_host.bmc_mac_address)
            .await?
            .expect("registered zero-DPU expected machine");
    assert!(
        registered.data.declared_primary_mac().is_none(),
        "test precondition: no declared primary, so the retained fallback is the path under test",
    );
    db::retained_boot_interface::upsert(txn.as_mut(), inband_mac, "NIC.Embedded.1-1-1").await?;
    txn.commit().await?;

    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;

    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    // The predicted interface for the retained boot MAC is flagged primary, so
    // the controller has a boot target before the host's first DHCP.
    let mut txn = env.pool.begin().await?;
    let predicted = db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
        .await?
        .expect("zero-DPU ingest should mint a predicted interface for the host NIC");
    assert!(
        predicted.primary_interface,
        "a zero-DPU host with no declared primary should recover its primary from \
         retained_boot_interfaces, so the controller has a boot target",
    );
    txn.rollback().await?;

    Ok(())
}

/// If a static preallocation creates the machine_interfaces row while a
/// prediction is still pending (an ExpectedMachine `fixed_ip` recorded in
/// between), the prediction's live-report id still outranks the retained
/// id the preallocated row recovered.
#[sqlx_test]
async fn test_predicted_live_boot_interface_id_outranks_preallocated_retained_row_at_promotion(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let mock_host = zero_dpu_host();
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    // A prior row retained an obsolete boot interface id for this MAC.
    let mut txn = env.pool.begin().await?;
    db::retained_boot_interface::upsert(txn.as_mut(), inband_mac, "NIC.Old.9-9-9").await?;
    txn.commit().await?;

    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;

    // Site-explorer mints a pending prediction with the current Redfish id.
    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    let static_ip: std::net::IpAddr = "192.0.3.77".parse()?;
    let mut txn = env.pool.begin().await?;

    // A `fixed_ip` declaration creates the row on the same
    // HostInband segment before the NIC ever DHCPs; creation
    // recovers the retained (obsolete) id onto it.
    db::machine_interface::preallocate_machine_interface(txn.as_mut(), inband_mac, static_ip, None)
        .await?;

    let interfaces = db::machine_interface::find_by_mac_address(txn.as_mut(), inband_mac).await?;
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        interfaces[0].boot_interface_id.as_deref(),
        Some("NIC.Old.9-9-9")
    );
    txn.commit().await?;

    // DHCP promotion must overwrite the preallocated row with the live id.
    env.api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(inband_mac, env.host_inband_segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await?;

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_mac_address(txn.as_mut(), inband_mac).await?;
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        interfaces[0].boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "the live predicted id outranks the preallocation-recovered retained id"
    );
    txn.rollback().await?;

    Ok(())
}

/// A newly DHCP-created machine_interface recovers a retained boot
/// interface id -- recorded when a prior row for its MAC was deleted (e.g.
/// admin force-delete during a DPU-to-NIC mode migration) -- and consumes
/// the retention record.
#[sqlx_test]
async fn test_dhcp_created_interface_recovers_retained_boot_interface_id(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let mock_host = zero_dpu_host();
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    // A prior interface row for this MAC was deleted with its boot pair
    // retained; seed that record directly.
    let mut txn = env.pool.begin().await?;
    db::retained_boot_interface::upsert(txn.as_mut(), inband_mac, "NIC.Retained.7-1-1").await?;
    txn.commit().await?;

    // DHCP arrives before site-explorer ever runs: the brand-new row
    // recovers the retained boot interface id on creation.
    env.api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(inband_mac, env.host_inband_segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await?;

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_mac_address(txn.as_mut(), inband_mac).await?;
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        interfaces[0].boot_interface_id.as_deref(),
        Some("NIC.Retained.7-1-1"),
        "the new row should recover the retained boot interface id"
    );
    assert!(
        db::retained_boot_interface::find_by_mac(txn.as_mut(), inband_mac, None)
            .await?
            .is_none(),
        "the retention record should be consumed once applied"
    );
    txn.rollback().await?;

    Ok(())
}

/// A prediction minted before the BMC report resolved the NIC's Redfish id
/// is refreshed by the next exploration that does resolve it -- pending
/// predictions stay as current as the live report until DHCP promotes them.
#[sqlx_test]
async fn test_exploration_refreshes_pending_predicted_boot_interface_id(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let mock_host = zero_dpu_host();
    let inband_mac = *mock_host.non_dpu_macs.first().unwrap();
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    // First exploration: the BMC reports the NIC's MAC but no Redfish id
    // yet, so the minted prediction has no boot interface id.
    let mut id_less_report: model::site_explorer::EndpointExplorationReport =
        mock_host.clone().into();
    for system in id_less_report.systems.iter_mut() {
        for iface in system.ethernet_interfaces.iter_mut() {
            iface.id = None;
        }
    }

    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;
    env.site_explorer
        .insert_endpoint_result(host_bmc_ip, Ok(id_less_report));

    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    let mut txn = env.pool.begin().await?;
    let predicted = db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
        .await?
        .expect("zero-DPU ingest should have minted a predicted interface");
    assert!(
        predicted.boot_interface_id.is_none(),
        "an id-less report can't give the prediction a boot interface id"
    );
    txn.rollback().await?;

    // Second exploration: the BMC now resolves the id; the pending
    // prediction picks it up.
    env.site_explorer
        .insert_endpoint_result(host_bmc_ip, Ok(mock_host.clone().into()));
    env.site_explorer.run_single_iteration().await?;

    let mut txn = env.pool.begin().await?;
    let predicted = db::predicted_machine_interface::find_by_mac_address(&mut txn, inband_mac)
        .await?
        .expect("the prediction should still be pending");
    assert_eq!(
        predicted.boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "the next exploration that resolves the id refreshes the prediction"
    );
    txn.rollback().await?;

    Ok(())
}

/// Two NICs on a zero-DPU host that lease before site-explorer ingests it both
/// land as anonymous primary rows (the DHCP creation default). With no declared
/// primary, ingestion still adopts both -- demoting the extras so at most one
/// primary survives -- rather than colliding on the
/// `one_primary_interface_per_machine` index. (Regression: a second primary
/// adoption previously failed the host's ingestion outright.)
#[sqlx_test]
async fn test_zero_dpu_multi_nic_no_declaration_adopts_without_primary_collision(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let nic_a = MacAddress::from_str("d4:04:e6:84:20:01").unwrap();
    let nic_b = MacAddress::from_str("d4:04:e6:84:20:02").unwrap();
    let mock_host = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![nic_a, nic_b],
        ..ManagedHostConfig::default()
    };
    // No declared primary: NoDpu with empty host_nics.
    register_zero_dpu_expected_machine(&env, &mock_host).await?;

    // Both NICs lease before site-explorer runs -> two anonymous primary rows.
    for nic in [nic_a, nic_b] {
        env.api()
            .discover_dhcp(
                rpc::forge::DhcpDiscovery::builder(nic, env.host_inband_segment.relay_address)
                    .vendor_string("Bluefield")
                    .tonic_request(),
            )
            .await?;
    }

    let mut txn = env.pool.begin().await?;
    for nic in [nic_a, nic_b] {
        let row = db::machine_interface::find_by_mac_address(txn.as_mut(), nic)
            .await?
            .into_iter()
            .next()
            .expect("pre-ingestion DHCP should have created an anonymous row");
        assert!(
            row.machine_id.is_none(),
            "the row should be anonymous before ingestion"
        );
        assert!(
            row.primary_interface,
            "anonymous DHCP rows default to primary"
        );
    }
    txn.rollback().await?;

    // Ingest the host. Adoption must reconcile the two primary rows.
    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;
    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    // Both NICs are now owned by the same host, with at most one primary.
    let mut txn = env.pool.begin().await?;
    let row_a = db::machine_interface::find_by_mac_address(txn.as_mut(), nic_a)
        .await?
        .into_iter()
        .next()
        .expect("nic_a should still have a row after ingestion");
    let row_b = db::machine_interface::find_by_mac_address(txn.as_mut(), nic_b)
        .await?
        .into_iter()
        .next()
        .expect("nic_b should still have a row after ingestion");
    txn.rollback().await?;
    let machine_a = row_a
        .machine_id
        .expect("ingestion should have adopted nic_a onto the host");
    let machine_b = row_b
        .machine_id
        .expect("ingestion should have adopted nic_b onto the host");
    assert_eq!(
        machine_a, machine_b,
        "both NICs should be adopted by the same host machine"
    );
    let primary_count = [row_a.primary_interface, row_b.primary_interface]
        .into_iter()
        .filter(|primary| *primary)
        .count();
    assert!(
        primary_count <= 1,
        "at most one interface may be primary after adoption, got {primary_count}"
    );

    Ok(())
}

/// A zero-DPU host that declares one of its NICs `primary` mints that intent
/// onto the prediction, and DHCP promotion lands it: the declared NIC promotes
/// as primary and the other as non-primary -- even when the non-declared NIC
/// leases first.
#[sqlx_test]
async fn test_zero_dpu_declared_primary_promotes_as_primary(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = init(pool).await;
    let primary_nic = MacAddress::from_str("d4:04:e6:84:21:01").unwrap();
    let other_nic = MacAddress::from_str("d4:04:e6:84:21:02").unwrap();
    let mock_host = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![primary_nic, other_nic],
        ..ManagedHostConfig::default()
    };

    // Register the host declaring `primary_nic` as its boot interface.
    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: mock_host.bmc_mac_address,
            data: ExpectedMachineData {
                serial_number: mock_host.serial.clone(),
                dpu_mode: DpuMode::NoDpu,
                host_nics: vec![
                    ExpectedHostNic {
                        mac_address: primary_nic,
                        primary: Some(true),
                        ..Default::default()
                    },
                    ExpectedHostNic {
                        mac_address: other_nic,
                        primary: None,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    // Ingest before either NIC leases, so both get predictions carrying the
    // declared intent.
    let host_bmc_response = env
        .api()
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(
                mock_host.bmc_mac_address,
                env.underlay_segment.relay_address,
            )
            .vendor_string("SomeVendor")
            .tonic_request(),
        )
        .await?
        .into_inner();
    let host_bmc_ip = host_bmc_response.address.parse()?;
    env.site_explorer.insert_endpoints(
        mock_host
            .exploration_results(Some(host_bmc_ip), &[])?
            .into_endpoints(),
    );
    env.site_explorer.run_single_iteration().await?;
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn).await?;
    txn.commit().await?;
    env.site_explorer.run_single_iteration().await?;

    let mut txn = env.pool.begin().await?;
    let predicted_primary =
        db::predicted_machine_interface::find_by_mac_address(&mut txn, primary_nic)
            .await?
            .expect("the declared NIC should have a prediction");
    assert!(
        predicted_primary.primary_interface,
        "the declared NIC's prediction should carry the primary intent"
    );
    let predicted_other = db::predicted_machine_interface::find_by_mac_address(&mut txn, other_nic)
        .await?
        .expect("the non-declared NIC should have a prediction");
    assert!(
        !predicted_other.primary_interface,
        "the non-declared NIC's prediction should be non-primary"
    );
    txn.rollback().await?;

    // Promote with the non-declared NIC leasing first.
    for nic in [other_nic, primary_nic] {
        env.api()
            .discover_dhcp(
                rpc::forge::DhcpDiscovery::builder(nic, env.host_inband_segment.relay_address)
                    .vendor_string("Bluefield")
                    .tonic_request(),
            )
            .await?;
    }

    let mut txn = env.pool.begin().await?;
    let primary_row = db::machine_interface::find_by_mac_address(txn.as_mut(), primary_nic)
        .await?
        .into_iter()
        .next()
        .expect("the declared NIC should be promoted to a row");
    let other_row = db::machine_interface::find_by_mac_address(txn.as_mut(), other_nic)
        .await?
        .into_iter()
        .next()
        .expect("the non-declared NIC should be promoted to a row");
    txn.rollback().await?;
    assert!(
        primary_row.primary_interface,
        "the declared NIC should promote as the primary interface"
    );
    assert!(
        !other_row.primary_interface,
        "the non-declared NIC should promote as non-primary"
    );
    assert_eq!(
        primary_row.machine_id, other_row.machine_id,
        "both NICs should belong to the same host"
    );

    Ok(())
}
