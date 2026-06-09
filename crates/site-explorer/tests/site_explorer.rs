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

use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_test_harness::network::segment::TestNetworkSegment;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::endpoint_explorer::MockEndpointExplorer;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::metadata::Metadata;
use model::site_explorer::{
    ComputerSystem, EndpointExplorationError, EndpointExplorationReport, EndpointType,
};
use tonic::IntoRequest;

use crate::env::Env;

mod env;

trait EnvExt {
    fn new_machine(&self, mac: &str, vendor: &str) -> FakeMachine;
}

impl EnvExt for Env {
    fn new_machine(&self, mac: &str, vendor: &str) -> FakeMachine {
        FakeMachine {
            mac: mac.parse().unwrap(),
            dhcp_vendor: vendor.to_string(),
            ip: String::new(),
            segment: self.underlay_segment,
        }
    }
}

trait DiscoverDhcp {
    async fn discover_dhcp(&mut self, env: &Env) -> Result<(), Box<dyn std::error::Error>>;
}

impl DiscoverDhcp for FakeMachine {
    async fn discover_dhcp(&mut self, env: &Env) -> Result<(), Box<dyn std::error::Error>> {
        let response = env
            .api()
            .discover_dhcp(
                rpc::forge::DhcpDiscovery {
                    mac_address: self.mac.to_string(),
                    relay_address: self.segment.relay_address.to_string(),
                    vendor_string: Some(self.dhcp_vendor.clone()),
                    link_address: None,
                    circuit_id: None,
                    remote_id: None,
                    desired_address: None,
                }
                .into_request(),
            )
            .await?
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            self.mac,
            response.address
        );
        self.ip = response.address;
        Ok(())
    }
}

impl DiscoverDhcp for Vec<FakeMachine> {
    async fn discover_dhcp(&mut self, env: &Env) -> Result<(), Box<dyn std::error::Error>> {
        for machine in self.iter_mut() {
            machine.discover_dhcp(env).await?
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct FakeMachine {
    pub mac: MacAddress,
    pub dhcp_vendor: String,
    pub segment: TestNetworkSegment,
    pub ip: String,
}

#[sqlx_test]
async fn test_handle_redfish_error_powers_on_machine(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;

    let mut machine = env.new_machine("6a:6b:6c:6d:6e:70", "Vendor1");
    machine.discover_dhcp(&env).await?;
    let bmc_ip: IpAddr = machine.ip.parse()?;

    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machine.mac,
            data: ExpectedMachineData {
                serial_number: "host-needs-power-on".to_string(),
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    endpoint_explorer.insert_endpoint_result(
        bmc_ip,
        Err(EndpointExplorationError::RedfishError {
            details: "transient redfish failure".to_string(),
            response_body: None,
            response_code: Some(500),
        }),
    );
    endpoint_explorer
        .power_states
        .lock()
        .unwrap()
        .insert(bmc_ip, libredfish::PowerState::Off);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

    explorer.run_single_iteration().await?;

    {
        let calls = endpoint_explorer
            .redfish_power_control_calls
            .lock()
            .unwrap();
        assert_eq!(
            calls.as_slice(),
            &[(
                std::net::SocketAddr::new(bmc_ip, 443),
                libredfish::SystemPowerControl::On
            )]
        );
    }

    let mut txn = env.pool.begin().await?;
    let endpoints = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
    txn.commit().await?;
    assert_eq!(endpoints.len(), 1, "expected one explored endpoint");
    Ok(())
}

/// Strict ingestion gate: a host whose BMC reports no DPU PCIe devices
/// and whose `ExpectedMachine` does not declare `NoDpu` is skipped (with
/// a warning + a `NoDpuReportedByHost` pairing-blocker metric) rather
/// than ingested. Operators must explicitly opt in to zero-DPU.
#[sqlx_test]
async fn test_site_explorer_skips_unexpected_zero_dpu_host(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;

    let mut machine = env.new_machine("AA:AB:AC:AD:AA:11", "Vendor1");
    machine.discover_dhcp(&env).await?;

    // expected_machine WITHOUT a NoDpu declaration -- the host is
    // "expected to have DPUs" by default.
    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machine.mac,
            data: ExpectedMachineData {
                serial_number: "host-expected-dpus-but-has-none".to_string(),
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    // BMC report with no PCIe devices / no chassis -- the gate sees
    // zero DPUs.
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    endpoint_explorer.insert_endpoint_results(vec![(
        machine.ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            vendor: Some(bmc_vendor::BMCVendor::Lenovo),
            systems: vec![ComputerSystem {
                serial_number: Some("0123456789".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )]);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);
    let test_meter = &env.test_harness.test_meter;

    // First iteration populates `explored_endpoints`; second runs
    // `identify_managed_hosts` after preingestion is complete.
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(machine.ip.parse().unwrap(), &mut txn)
        .await?;
    txn.commit().await?;
    explorer.run_single_iteration().await.unwrap();

    // No managed host should have been identified.
    let explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    assert!(
        explored_managed_hosts.is_empty(),
        "strict gate should refuse to ingest a zero-DPU host without a `NoDpu` declaration, got {:?}",
        explored_managed_hosts,
    );

    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "0"
    );

    // The pairing-blocker metric should have ticked for `NoDpuReportedByHost`.
    let blocker_metric = test_meter
        .formatted_metric("carbide_host_dpu_pairing_blockers_count")
        .expect("expected `carbide_host_dpu_pairing_blockers_count` to be emitted");
    assert!(
        blocker_metric.contains("no_dpu_reported_by_host"),
        "expected pairing-blocker metric to mention `no_dpu_reported_by_host`, got {blocker_metric}",
    );

    Ok(())
}

/// Companion to `test_site_explorer_skips_unexpected_zero_dpu_host`: when
/// the operator explicitly declares `dpu_mode = "nic_mode"`, a host whose
/// BMC reports zero usable DPU PCIe devices (because anything that is a
/// BlueField has been stripped as "DPU in NIC mode") should be ingested as
/// a zero-DPU managed host -- the operator has already opted into "treat
/// as zero-DPU" semantics by declaring NicMode.
#[sqlx_test]
async fn test_site_explorer_ingests_nic_mode_host_with_no_observed_dpus(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;

    let mut machine = env.new_machine("AA:AB:AC:AD:AA:22", "Vendor1");
    machine.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machine.mac,
            data: ExpectedMachineData {
                serial_number: "host-nic-mode-no-observed-dpus".to_string(),
                dpu_mode: model::expected_machine::DpuMode::NicMode,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    endpoint_explorer.insert_endpoint_results(vec![(
        machine.ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            vendor: Some(bmc_vendor::BMCVendor::Lenovo),
            systems: vec![ComputerSystem {
                serial_number: Some("0123456789".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )]);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(machine.ip.parse().unwrap(), &mut txn)
        .await?;
    txn.commit().await?;
    explorer.run_single_iteration().await.unwrap();

    let explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    assert_eq!(
        explored_managed_hosts.len(),
        1,
        "NicMode declaration should let the host through the strict gate even with zero observed DPUs",
    );
    assert!(
        explored_managed_hosts[0].dpus.is_empty(),
        "NicMode hosts ingest with an empty `dpus` vector",
    );

    Ok(())
}

/// Third member of the zero-DPU triad (alongside the `DpuMode::DpuMode`
/// skip test and the `DpuMode::NicMode` ingest test): a host explicitly
/// declared `dpu_mode = "no_dpu"` ingests as a zero-DPU managed host. The
/// `NoDpu` fast-path in `identify_managed_hosts` short-circuits before any
/// DPU PCIe enumeration, so this holds regardless of what the BMC reports.
#[sqlx_test]
async fn test_site_explorer_ingests_no_dpu_host(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;

    let mut machine = env.new_machine("AA:AB:AC:AD:AA:33", "Vendor1");
    machine.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machine.mac,
            data: ExpectedMachineData {
                serial_number: "host-no-dpu-declared".to_string(),
                dpu_mode: model::expected_machine::DpuMode::NoDpu,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    endpoint_explorer.insert_endpoint_results(vec![(
        machine.ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            vendor: Some(bmc_vendor::BMCVendor::Lenovo),
            systems: vec![ComputerSystem {
                serial_number: Some("0123456789".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )]);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::set_preingestion_complete(machine.ip.parse().unwrap(), &mut txn)
        .await?;
    txn.commit().await?;
    explorer.run_single_iteration().await.unwrap();

    let explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    assert_eq!(
        explored_managed_hosts.len(),
        1,
        "NoDpu declaration should ingest the host as zero-DPU",
    );
    assert!(
        explored_managed_hosts[0].dpus.is_empty(),
        "NoDpu hosts ingest with an empty `dpus` vector",
    );

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_unknown_vendor(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;
    let underlay_segment = env.underlay_segment;

    let mut machine = env.new_machine("B8:3F:D2:90:97:A7", "Vendor1");
    machine.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &underlay_segment.id)
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    endpoint_explorer.insert_endpoint_result(
        machine.ip.parse().unwrap(),
        Err(EndpointExplorationError::UnsupportedVendor {
            vendor: "Unknown".to_string(),
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
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
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);
    let report = &explored[0];
    assert_eq!(report.report_version.version_nr(), 1);
    assert_eq!(
        report.report.last_exploration_error,
        Some(EndpointExplorationError::UnsupportedVendor {
            vendor: "Unknown".to_string(),
        })
    );

    let guard = endpoint_explorer.reports.lock().unwrap();
    let res = guard.get(&report.address).unwrap().as_ref();
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err(),
        report.report.last_exploration_error.as_ref().unwrap()
    );

    Ok(())
}

#[sqlx_test]
async fn test_expected_machine_device_type_metrics(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new(pool).await;

    let test_sku_gpu_id = format!("test-sku-gpu-{}", uuid::Uuid::new_v4());
    let test_sku_no_type_id = format!("test-sku-no-type-{}", uuid::Uuid::new_v4());
    const EXPECTED_MACHINE_1_MAC: &str = "AA:BB:CC:DD:EE:01";
    const EXPECTED_MACHINE_2_MAC: &str = "AA:BB:CC:DD:EE:02";
    const EXPECTED_MACHINE_3_MAC: &str = "AA:BB:CC:DD:EE:03";

    // Create fake machines with network interfaces so they can be discovered
    let mut machines = vec![
        env.new_machine(EXPECTED_MACHINE_1_MAC, "Vendor1"),
        env.new_machine(EXPECTED_MACHINE_2_MAC, "Vendor2"),
        env.new_machine(EXPECTED_MACHINE_3_MAC, "Vendor3"),
    ];
    machines.discover_dhcp(&env).await?;

    // Create test SKUs in database
    let mut txn = env.pool.begin().await?;

    let test_sku_with_device_type = model::sku::Sku {
        schema_version: db::sku::CURRENT_SKU_VERSION,
        id: test_sku_gpu_id.clone(),
        description: "Test GPU SKU".to_string(),
        created: chrono::Utc::now(),
        components: model::sku::SkuComponents {
            chassis: model::sku::SkuComponentChassis {
                vendor: format!("test_vendor_gpu_{}", uuid::Uuid::new_v4()),
                model: format!("test_model_gpu_{}", uuid::Uuid::new_v4()),
                architecture: "x86_64".to_string(),
            },
            cpus: vec![],
            gpus: vec![],
            memory: vec![],
            infiniband_devices: vec![],
            storage: vec![],
            tpm: None,
        },
        device_type: Some("gpu".to_string()),
    };

    let test_sku_without_device_type = model::sku::Sku {
        schema_version: db::sku::CURRENT_SKU_VERSION,
        id: test_sku_no_type_id.clone(),
        description: "Test SKU without device type".to_string(),
        created: chrono::Utc::now(),
        components: model::sku::SkuComponents {
            chassis: model::sku::SkuComponentChassis {
                vendor: format!("test_vendor_no_type_{}", uuid::Uuid::new_v4()),
                model: format!("test_model_no_type_{}", uuid::Uuid::new_v4()),
                architecture: "x86_64".to_string(),
            },
            cpus: vec![],
            gpus: vec![],
            memory: vec![],
            infiniband_devices: vec![],
            storage: vec![],
            tpm: None,
        },
        device_type: None,
    };

    db::sku::create(&mut txn, &test_sku_with_device_type).await?;
    db::sku::create(&mut txn, &test_sku_without_device_type).await?;

    // Create expected machines with different SKU configurations
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: EXPECTED_MACHINE_1_MAC.parse().unwrap(),
            data: ExpectedMachineData {
                bmc_username: "user1".to_string(),
                bmc_password: "pass1".to_string(),
                serial_number: "serial1".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: Some(test_sku_gpu_id.clone()),
                default_pause_ingestion_and_poweron: None,
                host_nics: vec![],
                rack_id: None,
                dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: Default::default(),
                host_lifecycle_profile: Default::default(),
            },
        },
    )
    .await?;

    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: EXPECTED_MACHINE_2_MAC.parse().unwrap(),
            data: ExpectedMachineData {
                bmc_username: "user2".to_string(),
                bmc_password: "pass2".to_string(),
                serial_number: "serial2".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: Some(test_sku_no_type_id.clone()),
                default_pause_ingestion_and_poweron: None,
                host_nics: vec![],
                rack_id: None,
                dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: Default::default(),
                host_lifecycle_profile: Default::default(),
            },
        },
    )
    .await?;

    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: EXPECTED_MACHINE_3_MAC.parse().unwrap(),
            data: ExpectedMachineData {
                bmc_username: "user3".to_string(),
                bmc_password: "pass3".to_string(),
                serial_number: "serial3".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: None, // No SKU
                default_pause_ingestion_and_poweron: None,
                host_nics: vec![],
                rack_id: None,
                dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: Default::default(),
                host_lifecycle_profile: Default::default(),
            },
        },
    )
    .await?;

    txn.commit().await?;

    // Set up endpoint explorer with mock results for our machines
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock exploration results for each machine
    endpoint_explorer.insert_endpoint_results(vec![
        (
            machines[0].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: Some(std::time::Duration::from_millis(100)),
                vendor: Some(bmc_vendor::BMCVendor::Dell),
                managers: vec![],
                systems: vec![],
                chassis: vec![],
                service: vec![],
                machine_id: None,
                versions: std::collections::HashMap::new(),
                model: Some("test-model".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
                remediation_error: None,
            }),
        ),
        (
            machines[1].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: Some(std::time::Duration::from_millis(100)),
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                managers: vec![],
                systems: vec![],
                chassis: vec![],
                service: vec![],
                machine_id: None,
                versions: std::collections::HashMap::new(),
                model: Some("test-model".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
                remediation_error: None,
            }),
        ),
        (
            machines[2].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: Some(std::time::Duration::from_millis(100)),
                vendor: Some(bmc_vendor::BMCVendor::Supermicro),
                managers: vec![],
                systems: vec![],
                chassis: vec![],
                service: vec![],
                machine_id: None,
                versions: std::collections::HashMap::new(),
                model: Some("test-model".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
                remediation_error: None,
            }),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 3, // Explore our 3 machines
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(false.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);
    let test_meter = &env.test_harness.test_meter;

    // Run site explorer to collect metrics
    explorer.run_single_iteration().await.unwrap();

    // Verify expected machines SKU count metrics
    let device_type_metrics: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_site_exploration_expected_machines_sku_count")
        .into_iter()
        .collect();

    assert!(!device_type_metrics.is_empty());

    // Expected machines metrics are now recorded based on both SKU ID and device type
    // Now that we properly set device_type using update_metadata:
    // - 1 machine with GPU SKU -> sku_id=test_sku_gpu_id, device_type="gpu"
    // - 1 machine with no device_type SKU -> sku_id=test_sku_no_type_id, device_type="unknown"
    // - 1 machine with no SKU -> sku_id="unknown", device_type="unknown"

    // Check machine with GPU SKU
    let gpu_sku_key = format!("{{device_type=\"gpu\",sku_id=\"{test_sku_gpu_id}\"}}");
    assert_eq!(device_type_metrics.get(&gpu_sku_key).unwrap(), "1");

    // Check machine with SKU but no device type
    let no_type_sku_key = format!("{{device_type=\"unknown\",sku_id=\"{test_sku_no_type_id}\"}}");
    assert_eq!(device_type_metrics.get(&no_type_sku_key).unwrap(), "1");

    // Check machine with no SKU
    assert_eq!(
        device_type_metrics
            .get("{device_type=\"unknown\",sku_id=\"unknown\"}")
            .unwrap(),
        "1"
    );

    // Verify total count by summing all device types
    let total_count: u32 = device_type_metrics
        .values()
        .map(|v| v.parse::<u32>().unwrap())
        .sum();
    assert_eq!(total_count, 3);

    Ok(())
}
