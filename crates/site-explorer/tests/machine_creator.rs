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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use carbide_site_explorer::MachineCreator;
use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_test_harness::network::segment::TestNetworkSegment;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::{
    DpuConfigExt as _, FixtureDefault as _, ManagedHostConfigExt as _,
};
use carbide_utils::arch::CpuArchitecture;
use carbide_uuid::machine::MachineId;
use db::ObjectFilter;
use itertools::Itertools;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::machine::ManagedHostState;
use model::machine::machine_search_config::MachineSearchConfig;
use model::resource_pool::ResourcePoolStats;
use model::site_explorer::{EndpointExplorationReport, ExploredDpu, ExploredManagedHost};
use model::test_support::{DpuConfig, ManagedHostConfig};
use rpc::forge::forge_server::Forge;
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use tonic::Request;

struct ExploredHostFixture {
    host: ExploredManagedHost,
    host_report: EndpointExplorationReport,
    dpu_machine_ids: HashMap<u8, MachineId>,
}

struct Env {
    pool: PgPool,
    underlay_segment: TestNetworkSegment,
    test_harness: TestHarness,
}

impl Env {
    async fn new(pool: PgPool) -> Self {
        let test_harness = TestHarness::builder(pool.clone()).build().await;
        let domain = test_harness.test_domain().await;
        let network_controller = test_harness.network_controller();
        let underlay_segment = network_controller.create_underlay_segment(&domain).await;
        network_controller.create_admin_segment(&domain).await;
        Self {
            pool,
            underlay_segment,
            test_harness,
        }
    }

    fn api(&self) -> &Api {
        self.test_harness.api()
    }
}

fn machine_creator_config(allocate_secondary_vtep_ip: bool) -> SiteExplorerConfig {
    SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    }
}

fn machine_creator(env: &Env, config: SiteExplorerConfig) -> MachineCreator {
    MachineCreator::new(
        env.pool.clone(),
        config,
        env.api().common_pools().clone(),
        None,
        env.api().credential_manager().clone(),
    )
}

fn expected_machine(managed_host: &ManagedHostConfig) -> ExpectedMachine {
    ExpectedMachine {
        id: Some(uuid::Uuid::new_v4()),
        bmc_mac_address: managed_host.bmc_mac_address,
        data: managed_host
            .expected_machine_data
            .clone()
            .unwrap_or_default(),
    }
}

async fn discover_bmc(
    api: &Api,
    segment: TestNetworkSegment,
    mac_address: MacAddress,
    vendor_string: &str,
) -> IpAddr {
    api.discover_dhcp(
        rpc::forge::DhcpDiscovery::builder(mac_address, segment.relay_address)
            .vendor_string(vendor_string)
            .tonic_request(),
    )
    .await
    .expect("BMC DHCP discovery should succeed")
    .into_inner()
    .address
    .parse()
    .expect("DHCP response address should be an IP address")
}

async fn dhcp_discover_dpu_oob_iface(
    api: &Api,
    segment: TestNetworkSegment,
    mac_address: MacAddress,
) {
    api.discover_dhcp(
        rpc::forge::DhcpDiscovery::builder(mac_address, segment.relay_address)
            .vendor_string("bluefield")
            .tonic_request(),
    )
    .await
    .expect("DPU OOB DHCP discovery should succeed");
}

async fn explored_host_fixture(env: &Env, managed_host: &ManagedHostConfig) -> ExploredHostFixture {
    let host_bmc_ip = discover_bmc(
        env.api(),
        env.underlay_segment,
        managed_host.bmc_mac_address,
        "NVIDIA/OOB",
    )
    .await;

    let mut dpu_bmc_ips = Vec::new();
    for (dpu_index, dpu) in managed_host.dpus.iter().enumerate() {
        let dpu_index = dpu_index.try_into().expect("DPU index should fit into u8");
        let dpu_bmc_ip = discover_bmc(
            env.api(),
            env.underlay_segment,
            dpu.bmc_mac_address,
            "NVIDIA/BF/BMC",
        )
        .await;
        dpu_bmc_ips.push((dpu_index, dpu_bmc_ip));
    }

    let results = managed_host
        .exploration_results(Some(host_bmc_ip), &dpu_bmc_ips)
        .expect("managed host exploration results should be generated");
    let dpu_machine_ids = results.dpu_machine_ids();
    let (_, host_report) = results
        .host_report
        .expect("host exploration report should exist");
    let dpus = results
        .dpu_reports
        .into_iter()
        .map(|dpu| ExploredDpu {
            bmc_ip: dpu.bmc_ip,
            host_pf_mac_address: managed_host
                .dpus
                .get(dpu.dpu_index as usize)
                .map(|config| config.host_mac_address),
            report: Arc::new(dpu.report),
        })
        .collect();

    ExploredHostFixture {
        host: ExploredManagedHost { host_bmc_ip, dpus },
        host_report,
        dpu_machine_ids,
    }
}

#[sqlx_test]
async fn test_machine_creator_creates_managed_host(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let creator = machine_creator(&env, machine_creator_config(false));

    // Use a known DPU serial so we can assert on the generated MachineId.
    let dpu_serial = "MT2328XZ185R".to_string();
    let expected_machine_id =
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string();

    let mock_dpu = DpuConfig::with_serial(dpu_serial.clone());
    dhcp_discover_dpu_oob_iface(env.api(), env.underlay_segment, mock_dpu.oob_mac_address).await;
    let mock_host = ManagedHostConfig::with_dpus(vec![mock_dpu.clone()]);
    let mut fixture = explored_host_fixture(&env, &mock_host).await;

    assert_eq!(fixture.dpu_machine_ids[&0].to_string(), expected_machine_id,);

    assert!(
        creator
            .create_managed_host(
                &fixture.host,
                &mut fixture.host_report,
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    let mut txn = env.pool.begin().await?;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &fixture.dpu_machine_ids[&0],
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await?
    .expect("DPU machine should exist");
    txn.commit().await?;
    assert!(
        matches!(
            dpu_machine.current_state(),
            ManagedHostState::DpuDiscoveringState { .. }
        ),
        "expected DpuDiscoveringState, got {:?}",
        dpu_machine.current_state(),
    );
    assert_eq!(
        dpu_machine.hardware_info.as_ref().unwrap().machine_type,
        CpuArchitecture::Aarch64,
    );
    assert_eq!(
        dpu_machine
            .hardware_info
            .as_ref()
            .unwrap()
            .dmi_data
            .clone()
            .unwrap()
            .product_serial,
        dpu_serial
    );
    assert_eq!(
        dpu_machine
            .hardware_info
            .as_ref()
            .unwrap()
            .dpu_info
            .clone()
            .unwrap()
            .part_number,
        "900-9D3B6-00CV-AA0".to_string()
    );
    assert_eq!(
        dpu_machine
            .hardware_info
            .as_ref()
            .unwrap()
            .dpu_info
            .clone()
            .unwrap()
            .part_description,
        "Bluefield 3 SmartNIC Main Card".to_string()
    );

    let mut txn = env.pool.begin().await?;
    let host_machine = db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine.id)
        .await?
        .expect("host machine should exist");
    txn.commit().await?;
    assert!(
        matches!(
            host_machine.current_state(),
            ManagedHostState::DpuDiscoveringState { .. }
        ),
        "expected DpuDiscoveringState, got {:?}",
        host_machine.current_state(),
    );
    assert!(host_machine.bmc_info.ip.is_some());

    // 2nd creation does nothing.
    assert!(
        !creator
            .create_managed_host(
                &fixture.host,
                &mut EndpointExplorationReport::default(),
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    let mut txn = env.pool.begin().await?;
    let machine_interfaces =
        db::machine_interface::find_by_mac_address(txn.as_mut(), mock_dpu.oob_mac_address).await?;
    assert!(!machine_interfaces.is_empty());
    let topologies = db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machine.id]).await?;
    assert!(topologies.contains_key(&dpu_machine.id));

    let pairs =
        db::machine_topology::find_machine_bmc_pairs_by_machine_id(&mut txn, vec![dpu_machine.id])
            .await?;
    txn.commit().await?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].1, Some(fixture.host.dpus[0].bmc_ip.to_string()));

    let topology = &topologies[&dpu_machine.id][0];
    assert!(topology.topology_update_needed());
    assert!(
        topology
            .topology()
            .discovery_data
            .info
            .block_devices
            .is_empty()
    );

    Ok(())
}

#[sqlx_test]
async fn test_machine_creator_creates_multi_dpu_managed_host(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let resource_pools = ResourcePoolBuilder::default()
        .with_secondary_vtep_ip("172.21.0.0/29")
        .build();
    let test_harness = TestHarness::builder(pool.clone())
        .with_resource_pools(resource_pools)
        .build()
        .await;
    let domain = test_harness.test_domain().await;
    let network_controller = test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let env = Env {
        pool,
        underlay_segment,
        test_harness,
    };
    let creator = machine_creator(&env, machine_creator_config(true));

    const NUM_DPUS: usize = 2;
    let mut txn = env.pool.begin().await?;
    let initial_loopback_pool_stats = db::resource_pool::stats(
        &mut *txn,
        env.api().common_pools().ethernet.pool_loopback_ip.name(),
    )
    .await?;

    let initial_secondary_vtep_pool_stats = db::resource_pool::stats(
        &mut *txn,
        env.api()
            .common_pools()
            .ethernet
            .pool_secondary_vtep_ip
            .name(),
    )
    .await?;
    txn.commit().await?;

    let mut oob_interfaces = Vec::new();
    let mock_host =
        ManagedHostConfig::with_dpus((0..NUM_DPUS).map(|_| DpuConfig::default()).collect());
    for dpu in &mock_host.dpus {
        dhcp_discover_dpu_oob_iface(env.api(), env.underlay_segment, dpu.oob_mac_address).await;
        let mut txn = env.pool.begin().await?;
        let oob_interface =
            db::machine_interface::find_by_mac_address(txn.as_mut(), dpu.oob_mac_address).await?;
        txn.commit().await?;
        assert!(oob_interface[0].primary_interface);
        oob_interfaces.push(oob_interface[0].clone());
    }
    let mut fixture = explored_host_fixture(&env, &mock_host).await;

    assert!(
        creator
            .create_managed_host(
                &fixture.host,
                &mut fixture.host_report,
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    // a second create attempt on the same machine should return false.
    assert!(
        !creator
            .create_managed_host(
                &fixture.host,
                &mut EndpointExplorationReport::default(),
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    let mut txn = env.pool.begin().await?;
    let expected_loopback_count = NUM_DPUS;
    assert_eq!(
        db::resource_pool::stats(
            &mut *txn,
            env.api().common_pools().ethernet.pool_loopback_ip.name()
        )
        .await?,
        ResourcePoolStats {
            used: expected_loopback_count,
            free: initial_loopback_pool_stats.free - expected_loopback_count,
            auto_assign_free: initial_loopback_pool_stats.free - expected_loopback_count,
            auto_assign_used: expected_loopback_count,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    let mut host_machine_id: Option<MachineId> = None;
    let mut dpu_machines = Vec::new();
    let mut host_machine = None;

    for dpu_index in 0..NUM_DPUS {
        let dpu_index = dpu_index.try_into().expect("DPU index should fit into u8");
        let mut txn = env.pool.begin().await?;
        let dpu_machine = db::machine::find_one(
            txn.as_mut(),
            &fixture.dpu_machine_ids[&dpu_index],
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?
        .expect("DPU machine should exist");
        txn.commit().await?;

        let expected_loopback_ip = dpu_machine.network_config.loopback_ip.unwrap().to_string();
        let expected_secondary_overlay_vtep_ip = dpu_machine
            .network_config
            .secondary_overlay_vtep_ip
            .unwrap()
            .to_string();

        let network_config_response = env
            .api()
            .get_managed_host_network_config(Request::new(
                rpc::forge::ManagedHostNetworkConfigRequest {
                    dpu_machine_id: Some(dpu_machine.id),
                },
            ))
            .await?
            .into_inner();

        assert_eq!(
            expected_loopback_ip,
            network_config_response
                .managed_host_config
                .unwrap()
                .loopback_ip
        );

        assert_eq!(
            expected_secondary_overlay_vtep_ip,
            network_config_response
                .traffic_intercept_config
                .unwrap()
                .additional_overlay_vtep_ip
                .unwrap()
        );

        if host_machine.is_none() {
            let mut txn = env.pool.begin().await?;
            host_machine =
                db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine.id).await?;
            txn.commit().await?;
        }
        let hm = host_machine.clone().unwrap();
        assert!(hm.bmc_info.ip.is_some());
        if host_machine_id.is_none() {
            host_machine_id = Some(hm.id);
        }

        assert_eq!(&hm.id, host_machine_id.as_ref().unwrap());
        dpu_machines.push(dpu_machine);
    }

    // And make sure resource pool stats agree with how many
    // secondary vteps should have been assigned.
    let expected_secondary_vtep_count = NUM_DPUS;
    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(
            &mut *txn,
            env.api()
                .common_pools()
                .ethernet
                .pool_secondary_vtep_ip
                .name()
        )
        .await?,
        ResourcePoolStats {
            used: expected_loopback_count,
            free: initial_secondary_vtep_pool_stats.free - expected_secondary_vtep_count,
            auto_assign_free: initial_secondary_vtep_pool_stats.free
                - expected_secondary_vtep_count,
            auto_assign_used: expected_loopback_count,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    assert!(
        matches!(
            host_machine.unwrap().current_state(),
            ManagedHostState::DpuDiscoveringState { .. }
        ),
        "expected DpuDiscoveringState for host",
    );

    for dpu in &dpu_machines {
        assert!(
            matches!(
                dpu.current_state(),
                ManagedHostState::DpuDiscoveringState { .. }
            ),
            "expected DpuDiscoveringState for DPU {:?}",
            dpu.id,
        );
    }

    let mut txn = env.pool.begin().await?;
    let mut interfaces_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[*host_machine_id.as_ref().unwrap()])
            .await?;
    txn.commit().await?;
    let interfaces = interfaces_map
        .remove(host_machine_id.as_ref().unwrap())
        .unwrap();
    assert_eq!(interfaces.len(), NUM_DPUS);
    assert_eq!(
        interfaces
            .iter()
            .filter(|i| i.primary_interface)
            .collect::<Vec<_>>()
            .len(),
        1
    );
    assert_eq!(
        interfaces
            .iter()
            .filter(|i| !i.primary_interface)
            .collect::<Vec<_>>()
            .len(),
        NUM_DPUS - 1
    );

    // Try to discover machine with multiple DPUs
    for (i, dpu_machine) in dpu_machines.iter().enumerate() {
        let mut txn = env.pool.begin().await?;
        let topologies =
            db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machine.id]).await?;
        txn.commit().await?;

        let topology = &topologies[&dpu_machine.id][0];
        let hardware_info = &topology.topology().discovery_data.info;
        let discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();

        let response = env
            .api()
            .discover_machine(Request::new(MachineDiscoveryInfo {
                machine_interface_id: Some(oob_interfaces[i].id),
                discovery_data: Some(DiscoveryData::Info(discovery_info)),
                create_machine: true,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.machine_id.is_some());
    }

    Ok(())
}

#[sqlx_test]
async fn test_mi_attach_dpu_if_mi_exists_during_machine_creation(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let creator = machine_creator(&env, machine_creator_config(false));

    let mock_host = ManagedHostConfig::default();
    let mock_dpu = mock_host.dpus.first().unwrap();

    // Create MI now.
    dhcp_discover_dpu_oob_iface(env.api(), env.underlay_segment, mock_dpu.oob_mac_address).await;

    let mut fixture = explored_host_fixture(&env, &mock_host).await;

    // Machine interface should not have any machine id associated with it right now.
    let mut txn = env.pool.begin().await?;
    let mi =
        db::machine_interface::find_by_mac_address(txn.as_mut(), mock_dpu.oob_mac_address).await?;
    assert!(mi[0].attached_dpu_machine_id.is_none());
    assert!(mi[0].machine_id.is_none());
    txn.rollback().await?;

    assert!(
        creator
            .create_managed_host(
                &fixture.host,
                &mut fixture.host_report,
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    // At this point, create_managed_host must have updated the associated machine id in
    // machine_interfaces table.
    let mut txn = env.pool.begin().await?;
    let mi =
        db::machine_interface::find_by_mac_address(txn.as_mut(), mock_dpu.oob_mac_address).await?;
    assert!(mi[0].attached_dpu_machine_id.is_some());
    assert!(mi[0].machine_id.is_some());
    txn.rollback().await?;

    Ok(())
}

#[sqlx_test]
async fn test_mi_attach_dpu_if_mi_created_after_machine_creation(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let creator = machine_creator(&env, machine_creator_config(false));
    let mock_host = ManagedHostConfig::default();
    let mock_dpu = mock_host.dpus.first().unwrap();
    let mut fixture = explored_host_fixture(&env, &mock_host).await;
    let dpu_machine_id = fixture.dpu_machine_ids[&0];

    // No way to find a machine_interface using machine id as machine id is not yet associated with
    // interface (right now no machine interface is created yet).
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id]).await?;
    assert!(mi.is_empty());
    txn.rollback().await?;

    assert!(
        creator
            .create_managed_host(
                &fixture.host,
                &mut fixture.host_report,
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    // At this point, create_managed_host must have created machine but can not associate it with to
    // any interface as interface does not exist.
    let mut txn = env.pool.begin().await?;
    let machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?;
    assert!(machine.is_some());

    // No way to find a machine_interface using machine id as machine id is not yet associated with
    // interface (right now no machine interface is created yet).
    let mi = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id]).await?;
    assert!(mi.is_empty());
    txn.rollback().await?;

    // Create MI now.
    dhcp_discover_dpu_oob_iface(env.api(), env.underlay_segment, mock_dpu.oob_mac_address).await;

    // Machine is already created, create_managed_host should return false.
    assert!(
        !creator
            .create_managed_host(
                &fixture.host,
                &mut EndpointExplorationReport::default(),
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    // At this point, create_managed_host must have updated the associated machine id in
    // machine_interfaces table.
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id]).await?;
    assert!(!mi.is_empty());
    let value = mi.values().collect_vec()[0].clone()[0].clone();
    assert_eq!(value.attached_dpu_machine_id.unwrap(), dpu_machine_id);
    assert_eq!(value.machine_id.unwrap(), dpu_machine_id);
    txn.rollback().await?;

    Ok(())
}

#[sqlx_test]
async fn test_machine_creator_creates_managed_host_with_dpf_disabled(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let creator = machine_creator(&env, machine_creator_config(false));

    let mock_dpu = DpuConfig::with_serial("MT2328XZ185R".to_string());
    let mock_host = ManagedHostConfig {
        expected_machine_data: Some(ExpectedMachineData {
            dpf_enabled: Some(false),
            ..Default::default()
        }),
        ..ManagedHostConfig::with_dpus(vec![mock_dpu.clone()])
    };
    let mut fixture = explored_host_fixture(&env, &mock_host).await;

    assert!(
        creator
            .create_managed_host(
                &fixture.host,
                &mut fixture.host_report,
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    let machines = db::machine::find(
        &env.pool,
        ObjectFilter::All,
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await?;

    assert_eq!(machines.len(), 2);
    for machine in machines {
        if machine.is_dpu() {
            // DPU has no expected-machine entry, so it always defaults to `true`.
            assert!(machine.dpf.enabled);
        } else {
            // Host has expected-machine entry with `dpf_enabled: Some(false)`.
            assert!(!machine.dpf.enabled);
        }
    }

    Ok(())
}

#[sqlx_test]
async fn test_machine_creator_creates_managed_host_with_dpf_enabled(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let creator = machine_creator(&env, machine_creator_config(false));

    let mock_dpu = DpuConfig::with_serial("MT2328XZ185R".to_string());
    let mock_host = ManagedHostConfig {
        expected_machine_data: Some(ExpectedMachineData {
            dpf_enabled: Some(true),
            ..Default::default()
        }),
        ..ManagedHostConfig::with_dpus(vec![mock_dpu.clone()])
    };
    let mut fixture = explored_host_fixture(&env, &mock_host).await;

    assert!(
        creator
            .create_managed_host(
                &fixture.host,
                &mut fixture.host_report,
                Some(&expected_machine(&mock_host)),
                &env.pool,
            )
            .await?
    );

    let machines = db::machine::find(
        &env.pool,
        ObjectFilter::All,
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await?;

    assert_eq!(machines.len(), 2);
    for machine in machines {
        assert!(machine.dpf.enabled);
    }

    Ok(())
}

/// `create_managed_host` must refuse to create a Managed Host when no
/// `expected_machines` entry is supplied.
#[sqlx_test]
async fn test_machine_creator_rejects_unexpected_host(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let creator = machine_creator(&env, machine_creator_config(false));

    let mock_host = ManagedHostConfig::default();
    let mut fixture = explored_host_fixture(&env, &mock_host).await;

    assert!(
        !creator
            .create_managed_host(&fixture.host, &mut fixture.host_report, None, &env.pool,)
            .await?
    );

    let machines = db::machine::find(
        &env.pool,
        ObjectFilter::All,
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(
        machines.len(),
        0,
        "expected no Machine rows for an unexpected host, got {machines:#?}"
    );

    Ok(())
}
