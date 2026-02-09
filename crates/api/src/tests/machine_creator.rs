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
use std::str::FromStr;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use itertools::Itertools;
use mac_address::MacAddress;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    DpuDiscoveringState, DpuInitState, InstallDpuOsState, ManagedHostState, SetSecureBootState,
};
use model::resource_pool::ResourcePoolStats;
use model::site_explorer::{EndpointExplorationReport, ExploredDpu, ExploredManagedHost};
use rpc::forge::forge_server::Forge;
use rpc::{BlockDevice, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use tonic::Request;
use utils::models::arch::CpuArchitecture;

use crate::CarbideError;
use crate::cfg::file::{DpuConfig as InitialDpuConfig, SiteExplorerConfig};
use crate::site_explorer::MachineCreator;
use crate::state_controller::machine::handler::MachineStateHandlerBuilder;
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use crate::tests::common::api_fixtures::dpu::DpuConfig;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::rpc_builder::DhcpDiscovery;

#[crate::sqlx_test]
async fn test_site_explorer_reject_zero_dpu_hosts(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = common::api_fixtures::get_config();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };
    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:98")?;
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(host_bmc_mac, "192.0.1.1")
                .vendor_string("SomeVendor")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: vec![],
    };

    let Err(CarbideError::NoDpusInMachine(_)) = machine_creator
        .create_managed_host(
            &exploration_report,
            &mut EndpointExplorationReport::default(),
            None,
            &env.pool,
        )
        .await
    else {
        panic!("explorer.create_managed_host should have failed with a NoDpusInMachine error")
    };
    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_creates_managed_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prevent Firmware update here, since we test it in other method
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());

    let oob_mac = MacAddress::from_str("a0:88:c2:08:80:95")?;
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(oob_mac, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert!(!response.address.is_empty());

    // Use a known DPU serial so we can assert on the generated MachineId
    let dpu_serial = "MT2328XZ185R".to_string();
    let expected_machine_id =
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string();

    let mock_dpu = DpuConfig::with_serial(dpu_serial.clone());
    let mock_host = ManagedHostConfig::with_dpus(vec![mock_dpu.clone()]);
    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;

    assert!(dpu_report.machine_id.as_ref().is_some());
    assert_eq!(
        dpu_report.machine_id.as_ref().unwrap().to_string(),
        expected_machine_id,
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mock_host.bmc_mac_address, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let dpu_report = Arc::new(dpu_report);
    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: vec![ExploredDpu {
            bmc_ip: IpAddr::from_str(response.address.as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        }],
    };

    assert!(
        machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
                &env.pool,
            )
            .await?
    );

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = db::machine::find_one(
        &mut txn,
        dpu_report.machine_id.as_ref().unwrap(),
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DpuDiscoveringState {
            dpu_states: model::machine::DpuDiscoveringStates {
                states: HashMap::from([(dpu_machine.id, DpuDiscoveringState::Initializing)]),
            },
        }
    );
    assert_eq!(
        dpu_machine.hardware_info.as_ref().unwrap().machine_type,
        CpuArchitecture::Aarch64,
    );
    assert_eq!(
        dpu_machine.bmc_info.ip.clone().unwrap(),
        response.address.to_string()
    );

    assert_eq!(
        format!(
            "BF-{}",
            dpu_machine.bmc_info.firmware_version.clone().unwrap()
        ),
        InitialDpuConfig::default()
            .find_bf3_entry()
            .unwrap()
            .version,
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

    let host_machine = db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine.id)
        .await?
        .unwrap();
    assert_eq!(
        host_machine.current_state(),
        &ManagedHostState::DpuDiscoveringState {
            dpu_states: model::machine::DpuDiscoveringStates {
                states: HashMap::from([(dpu_machine.id, DpuDiscoveringState::Initializing)]),
            },
        }
    );
    assert!(host_machine.bmc_info.ip.is_some());

    // 2nd creation does nothing
    assert!(
        !machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
                &env.pool,
            )
            .await?
    );

    let handler = MachineStateHandlerBuilder::builder()
        .dpu_up_threshold(chrono::Duration::minutes(1))
        .hardware_models(env.config.get_firmware_config())
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .dpu_enable_secure_boot(env.config.dpu_config.dpu_enable_secure_boot)
        .power_options_config(env.config.power_manager_options.clone().into())
        .build();
    env.override_machine_state_controller_handler(handler).await;
    env.run_machine_state_controller_iteration().await;

    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DpuDiscoveringState {
            dpu_states: model::machine::DpuDiscoveringStates {
                states: HashMap::from([(dpu_machine.id, DpuDiscoveringState::Configuring)]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DpuDiscoveringState {
            dpu_states: model::machine::DpuDiscoveringStates {
                states: HashMap::from([(dpu_machine.id, DpuDiscoveringState::EnableRshim,)]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DpuDiscoveringState {
            dpu_states: model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id,
                    DpuDiscoveringState::EnableSecureBoot {
                        enable_secure_boot_state: SetSecureBootState::CheckSecureBootStatus,
                        count: 0,
                    },
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DpuDiscoveringState {
            dpu_states: model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id,
                    DpuDiscoveringState::EnableSecureBoot {
                        enable_secure_boot_state: SetSecureBootState::SetSecureBoot,
                        count: 0,
                    },
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    // EnableSecureBoot: RebootDPU
    env.run_machine_state_controller_iteration().await;
    // CheckSecureBootStatus:
    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;
    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DPUInit {
            dpu_states: model::machine::DpuInitStates {
                states: HashMap::from([(
                    dpu_machine.id,
                    DpuInitState::InstallDpuOs {
                        substate: InstallDpuOsState::InstallingBFB
                    }
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    // Wait for installComplete
    env.run_machine_state_controller_iteration().await;

    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        &ManagedHostState::DPUInit {
            dpu_states: model::machine::DpuInitStates {
                states: HashMap::from([(dpu_machine.id, DpuInitState::Init,)]),
            },
        },
    );

    let machine_interfaces = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(!machine_interfaces.is_empty());
    let topologies = db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machine.id]).await?;
    assert!(topologies.contains_key(&dpu_machine.id));

    let pairs =
        db::machine_topology::find_machine_bmc_pairs_by_machine_id(&mut txn, vec![dpu_machine.id])
            .await?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].1, Some("192.0.1.4".to_string()));

    let topology = &topologies[&dpu_machine.id][0];
    assert!(topology.topology_update_needed());

    let hardware_info = &topology.topology().discovery_data.info;
    assert!(hardware_info.block_devices.is_empty());

    let mut discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
    discovery_info.block_devices = vec![BlockDevice {
        model: "Fake block device".to_string(),
        ..Default::default()
    }];

    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interfaces[0].id),
            discovery_data: Some(DiscoveryData::Info(discovery_info.clone())),
            create_machine: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.machine_id.is_some());

    // Now let's check that DPU and host updated states and updated hardware information.
    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert!(dpu_machine.network_config.loopback_ip.is_some());

    let machine_interfaces = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(
        machine_interfaces[0]
            .machine_id
            .as_ref()
            .is_some_and(|id| id == &dpu_machine.id)
    );

    let host_machine =
        db::machine::find_one(&mut txn, &host_machine.id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        host_machine.current_state(),
        &ManagedHostState::DPUInit {
            dpu_states: model::machine::DpuInitStates {
                states: HashMap::from([(dpu_machine.id, DpuInitState::Init,)]),
            },
        }
    );

    let topologies = db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machine.id]).await?;
    let topology = &topologies[&dpu_machine.id][0];
    assert!(!topology.topology_update_needed());

    let hardware_info = &topology.topology().discovery_data.info;
    assert!(!hardware_info.block_devices.is_empty());
    assert_eq!(
        hardware_info.block_devices[0].model,
        "Fake block device".to_string()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_creates_multi_dpu_managed_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());
    let mut txn = env.pool.begin().await.unwrap();
    const NUM_DPUS: usize = 2;
    let initial_loopback_pool_stats =
        db::resource_pool::stats(&mut *txn, env.common_pools.ethernet.pool_loopback_ip.name())
            .await
            .expect("failed to get inital pool stats");

    let initial_secondary_vtep_pool_stats = db::resource_pool::stats(
        &mut *txn,
        env.common_pools.ethernet.pool_secondary_vtep_ip.name(),
    )
    .await
    .expect("failed to get inital secondary-vtep-ip pool stats");

    let mut oob_interfaces = Vec::new();
    let mut explored_dpus = Vec::new();

    let mock_host =
        ManagedHostConfig::with_dpus((0..NUM_DPUS).map(|_| DpuConfig::default()).collect());

    for (i, mock_dpu) in mock_host.dpus.iter().enumerate() {
        let oob_mac = mock_dpu.oob_mac_address;
        let response = env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(oob_mac, "192.0.1.1")
                    .vendor_string("NVIDIA/OOB")
                    .tonic_request(),
            )
            .await
            .unwrap()
            .into_inner();

        assert!(!response.address.is_empty());
        let oob_interface = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
        assert!(oob_interface[0].primary_interface);
        oob_interfaces.push(oob_interface[0].clone());

        let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
        dpu_report.generate_machine_id(false)?;
        let dpu_report = Arc::new(dpu_report);
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        })
    }

    let host_bmc_mac = mock_host.bmc_mac_address;
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(host_bmc_mac, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: explored_dpus.clone(),
    };

    assert!(
        machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
                &env.pool,
            )
            .await?
    );

    // a second create attempt on the same machine should return false.
    assert!(
        !machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
                &env.pool,
            )
            .await?
    );

    let expected_loopback_count = NUM_DPUS;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, env.common_pools.ethernet.pool_loopback_ip.name())
            .await?,
        ResourcePoolStats {
            used: expected_loopback_count,
            free: initial_loopback_pool_stats.free - expected_loopback_count
        }
    );

    let mut host_machine_id: Option<MachineId> = None;
    let mut dpu_machines = Vec::new();
    let mut host_machine = None;

    for dpu in explored_dpus.iter() {
        let dpu_machine = db::machine::find_one(
            &mut txn,
            dpu.report.machine_id.as_ref().unwrap(),
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

        let expected_loopback_ip = dpu_machine.network_config.loopback_ip.unwrap().to_string();
        let expected_secondary_overlay_vtep_ip = dpu_machine
            .network_config
            .secondary_overlay_vtep_ip
            .unwrap()
            .to_string();

        let network_config_response = env
            .api
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
            host_machine =
                db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine.id).await?;
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
    assert_eq!(
        db::resource_pool::stats(
            &mut *txn,
            env.common_pools.ethernet.pool_secondary_vtep_ip.name()
        )
        .await?,
        ResourcePoolStats {
            used: expected_loopback_count,
            free: initial_secondary_vtep_pool_stats.free - expected_secondary_vtep_count
        }
    );

    let expected_state = ManagedHostState::DpuDiscoveringState {
        dpu_states: model::machine::DpuDiscoveringStates {
            states: dpu_machines
                .iter()
                .map(|x| (x.id, DpuDiscoveringState::Initializing))
                .collect::<HashMap<MachineId, DpuDiscoveringState>>(),
        },
    };

    assert_eq!(host_machine.unwrap().current_state(), &expected_state);

    for dpu in &dpu_machines {
        assert_eq!(dpu.current_state(), &expected_state);
    }

    let mut interfaces_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[*host_machine_id.as_ref().unwrap()])
            .await?;
    let interfaces = interfaces_map
        .remove(host_machine_id.clone().as_ref().unwrap())
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
    for i in 0..NUM_DPUS {
        let topologies =
            db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machines[i].id]).await?;

        let topology = &topologies[&dpu_machines[i].id][0];

        let hardware_info = &topology.topology().discovery_data.info;

        let discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
        let response = env
            .api
            .discover_machine(Request::new(MachineDiscoveryInfo {
                machine_interface_id: Some(oob_interfaces[i].id),
                discovery_data: Some(DiscoveryData::Info(discovery_info.clone())),
                create_machine: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.machine_id.is_some());
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_mi_attach_dpu_if_mi_exists_during_machine_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;

    let mock_host = ManagedHostConfig::default();
    let mock_dpu = mock_host.dpus.first().unwrap();
    let oob_mac = mock_dpu.oob_mac_address;

    // Create mi now.
    let _response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(oob_mac, "192.0.2.1")
                .vendor_string("bluefield")
                .tonic_request(),
        )
        .await?
        .into_inner();

    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;
    let dpu_report = Arc::new(dpu_report);

    let explored_dpus = vec![ExploredDpu {
        bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(mock_dpu.host_mac_address),
        report: dpu_report.clone(),
    }];

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mock_host.bmc_mac_address, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: explored_dpus.clone(),
    };

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());

    // Machine interface should not have any machine id associated with it right now.
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(mi[0].attached_dpu_machine_id.is_none());
    assert!(mi[0].machine_id.is_none());
    txn.rollback().await?;

    assert!(
        machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
                &env.pool
            )
            .await?
    );

    // At this point, create_managed_host must have updated the associated machine id in
    // machine_interfaces table.
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(mi[0].attached_dpu_machine_id.is_some());
    assert!(mi[0].machine_id.is_some());
    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_mi_attach_dpu_if_mi_created_after_machine_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let mock_host = ManagedHostConfig::default();
    let mock_dpu = mock_host.dpus.first().unwrap();

    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;
    let dpu_report = Arc::new(dpu_report);
    let dpu_machine_id = dpu_report.machine_id.unwrap();

    let explored_dpus = vec![ExploredDpu {
        bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(mock_dpu.host_mac_address),
        report: dpu_report.clone(),
    }];

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mock_host.bmc_mac_address, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: explored_dpus.clone(),
    };

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());

    // No way to find a machine_interface using machine id as machine id is not yet associated with
    // interface (right now no machine interface is created yet).
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id]).await?;
    assert!(mi.is_empty());
    txn.rollback().await?;

    assert!(
        machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
                &env.pool,
            )
            .await?
    );

    // At this point, create_managed_hostmust have created machine but can not associate it with to
    // any interface as interface does not exist.
    let mut txn = env.pool.begin().await?;
    let machine = db::machine::find_one(
        &mut txn,
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

    // Create mi now.
    let _response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mock_dpu.oob_mac_address, "192.0.2.1")
                .vendor_string("bluefield")
                .tonic_request(),
        )
        .await?
        .into_inner();

    // Machine is already created, create_managed_host should return false.
    assert!(
        !machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                None,
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

#[crate::sqlx_test]
async fn test_site_explorer_creates_managed_host_with_dpf_disable(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prevent Firmware update here, since we test it in other method
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());

    let oob_mac = MacAddress::from_str("a0:88:c2:08:80:95")?;
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(oob_mac, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert!(!response.address.is_empty());

    // Use a known DPU serial so we can assert on the generated MachineId
    let dpu_serial = "MT2328XZ185R".to_string();
    let expected_machine_id =
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string();

    let mock_dpu = DpuConfig::with_serial(dpu_serial.clone());
    let mock_host = ManagedHostConfig::with_dpus(vec![mock_dpu.clone()]);
    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;

    assert!(dpu_report.machine_id.as_ref().is_some());
    assert_eq!(
        dpu_report.machine_id.as_ref().unwrap().to_string(),
        expected_machine_id,
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mock_host.bmc_mac_address, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let dpu_report = Arc::new(dpu_report);
    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: vec![ExploredDpu {
            bmc_ip: IpAddr::from_str(response.address.as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        }],
    };

    let expected_machine = model::expected_machine::ExpectedMachine {
        id: Some(uuid::Uuid::new_v4()),
        bmc_mac_address: mock_host.bmc_mac_address,
        data: model::expected_machine::ExpectedMachineData {
            dpf_enabled: false,
            ..Default::default()
        },
    };

    assert!(
        machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                Some(&expected_machine),
                &env.pool,
            )
            .await?
    );

    let mut txn = env.pool.begin().await.unwrap();
    let machines = db::machine::find(
        &mut txn,
        db::ObjectFilter::All,
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(machines.len(), 2);
    for machine in machines {
        assert!(!machine.dpf.enabled);
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_creates_managed_host_with_dpf_enabled(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prevent Firmware update here, since we test it in other method
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let machine_creator =
        MachineCreator::new(env.pool.clone(), explorer_config, env.common_pools.clone());

    let oob_mac = MacAddress::from_str("a0:88:c2:08:80:95")?;
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(oob_mac, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert!(!response.address.is_empty());

    // Use a known DPU serial so we can assert on the generated MachineId
    let dpu_serial = "MT2328XZ185R".to_string();
    let expected_machine_id =
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string();

    let mock_dpu = DpuConfig::with_serial(dpu_serial.clone());
    let mock_host = ManagedHostConfig::with_dpus(vec![mock_dpu.clone()]);
    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;

    assert!(dpu_report.machine_id.as_ref().is_some());
    assert_eq!(
        dpu_report.machine_id.as_ref().unwrap().to_string(),
        expected_machine_id,
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mock_host.bmc_mac_address, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let dpu_report = Arc::new(dpu_report);
    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: vec![ExploredDpu {
            bmc_ip: IpAddr::from_str(response.address.as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        }],
    };

    let expected_machine = model::expected_machine::ExpectedMachine {
        id: Some(uuid::Uuid::new_v4()),
        bmc_mac_address: mock_host.bmc_mac_address,
        data: model::expected_machine::ExpectedMachineData {
            dpf_enabled: true,
            ..Default::default()
        },
    };

    assert!(
        machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                Some(&expected_machine),
                &env.pool,
            )
            .await?
    );

    let mut txn = env.pool.begin().await.unwrap();
    let machines = db::machine::find(
        &mut txn,
        db::ObjectFilter::All,
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(machines.len(), 2);
    for machine in machines {
        assert!(machine.dpf.enabled);
    }

    Ok(())
}
