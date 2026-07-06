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
use std::sync::atomic::AtomicBool;

use ::rpc::measured_boot::FromGrpc;
use base64::prelude::*;
use carbide_machine_controller::context::MachineStateHandlerContextObjects;
use carbide_machine_controller::handler::{MachineStateHandlerBuilder, handler_host_power_control};
use carbide_machine_controller::metrics::MachineMetrics;
use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_site_explorer::MachineCreator;
use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_utils::arch::CpuArchitecture;
use carbide_uuid::machine::MachineId;
use carbide_uuid::machine_validation::MachineValidationId;
use chrono::Duration;
use common::api_fixtures::dpu::{
    create_dpu_machine, create_dpu_machine_in_waiting_for_network_install,
};
use common::api_fixtures::host::{host_discover_dhcp, host_discover_machine, host_uefi_setup};
use common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    create_host_inband_network_segment,
};
use common::api_fixtures::tpm_attestation::{CA_CERT_SERIALIZED, EK_CERT_SERIALIZED};
use common::api_fixtures::{
    TestEnv, TestManagedHost, create_managed_host, create_managed_host_with_config,
    create_test_env, create_test_env_with_overrides, get_config,
};
use health_report::HealthReport;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use measured_boot::bundle::MeasurementBundle;
use measured_boot::pcr::PcrRegisterValue;
use measured_boot::records::MeasurementBundleState;
use measured_boot::report::MeasurementReport;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::hardware_info::TpmEkCertificate;
use model::machine::health_override::HARDWARE_HEALTH_OVERRIDE_PREFIX;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    BiosConfigInfo, BiosConfigState, CleanupContext, CleanupState, DpuDiscoveringState,
    DpuInitState, DpuReprovisionStates, FailureCause, FailureDetails, FailureSource,
    HostPlatformConfigurationState, InstallDpuOsState, InstanceState, LockdownMode, MachineState,
    MachineValidatingState, ManagedHostState, MeasuringState, PowerState, SetBootOrderInfo,
    SetBootOrderState, SetSecureBootState, SpdmMeasuringState, StateMachineArea, ValidationState,
};
use model::network_segment::NetworkSegmentType;
use model::site_explorer::{EndpointExplorationReport, ExploredDpu, ExploredManagedHost};
use model::test_support::{DpuConfig, ManagedHostConfig};
use rpc::forge::forge_server::Forge;
use rpc::forge::{HealthReportEntry, InsertMachineHealthReportRequest, TpmCaCert, TpmCaCertId};
use rpc::forge_agent_control_response::{Action, LegacyAction};
use rpc::machine_discovery::AttestKeyInfo;
use rpc::{DiscoveryData, DiscoveryInfo};
use state_controller::db_write_batch::DbWriteBatch;
use state_controller::state_handler::StateHandlerContext;
use tonic::{Code, Request};

use crate::cfg::file::DpuConfig as InitialDpuConfig;
use crate::handlers::measured_boot::rpc_forge::MachineDiscoveryInfo;
use crate::measured_boot::convert_vec;
use crate::test_support::fixture_config::{
    DpuConfigExt as _, FixtureDefault as _, ManagedHostConfigExt as _,
};
use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::{
    TEST_DOCA_HBN_VERSION, TEST_DOCA_TELEMETRY_VERSION, TEST_DPU_AGENT_VERSION,
};
use crate::tests::common::api_fixtures::instance::{
    default_os_config, default_tenant_config, single_interface_network_config,
};
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host_with_ek, discovery_completed, forge_agent_control,
    on_demand_machine_validation, update_time_params,
};
use crate::tests::common::attestation::spdm_attestation_run_to_failed_then_to_success;
use crate::tests::instance_ipxe_behaviors::create_instance;

async fn discover_dpu_bmc_ip_for_machine_creator_state_test(
    env: &TestEnv,
    bmc_mac_address: MacAddress,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let response = env
        .api
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(bmc_mac_address, "192.0.1.1")
                .vendor_string("NVIDIA/BF/BMC")
                .tonic_request(),
        )
        .await?
        .into_inner();

    Ok(response.address.parse()?)
}

// Verify the group-sync property of `db::machine::try_update_network_config`,
// where any write to a row in the host's group (the host or any of its DPUs)
// updates that row's content + version, AND fans the version bump out to every
// other row in the "group", after which, the host + all of its DPUs network
// config version are the same.
#[crate::sqlx_test]
async fn test_managed_host_network_config_group_sync(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // After ingestion brings the host to Ready, network_configured fixture
    // calls have caught DPU observations up to their (per-DPU) expected
    // versions, so sync is true at this point.
    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        snapshot.managed_host_network_config_version_synced(),
        "sync should be true after ingestion brings DPU observations up to expected version"
    );

    // Bump the HOST's network_config (write the same content back). The
    // group-sync helper should also bump each DPU's version to the same
    // new value.
    let host_before = mh.host().db_machine(&mut txn).await;
    db::machine::try_update_network_config(
        txn.as_mut(),
        &mh.id,
        host_before.network_config.version,
        &host_before.network_config.value,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let host_after_host_write = mh.host().db_machine(&mut txn).await;
    let dpu_after_host_write = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        host_after_host_write.network_config.version, dpu_after_host_write.network_config.version,
        "group-sync: DPU's version should match host's after a host write"
    );
    assert_ne!(
        host_after_host_write.network_config.version, host_before.network_config.version,
        "host's version should have advanced"
    );

    // Sync should now be false; the DPU's expected has bumped (via the
    // machine group bump), but its observation still reports the older
    // version.
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        !snapshot.managed_host_network_config_version_synced(),
        "sync should be false after the group bump until the DPU agent reports the new version"
    );
    txn.commit().await.unwrap();

    // Simulate the DPU agent polling, applying, and reporting back.
    common::api_fixtures::network_configured(&env, &mh.dpu_ids).await;
    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        snapshot.managed_host_network_config_version_synced(),
        "sync should flip back to true after the agent reports the new version"
    );

    // And now the converse direction -- bump a DPU's row (the shape of
    // machine_discovery's loopback_ip allocation). The group-sync helper
    // fans that bump out to the host's row too, keeping versions equal.
    let dpu_before_dpu_write = mh.dpu().db_machine(&mut txn).await;
    db::machine::try_update_network_config(
        txn.as_mut(),
        &dpu_before_dpu_write.id,
        dpu_before_dpu_write.network_config.version,
        &dpu_before_dpu_write.network_config.value,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let host_after_dpu_write = mh.host().db_machine(&mut txn).await;
    let dpu_after_dpu_write = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        host_after_dpu_write.network_config.version, dpu_after_dpu_write.network_config.version,
        "group-sync: host's version should match DPU's after a DPU write"
    );

    // Sync flips to false again, since the DPU's expected just advanced
    // beyond what it most recently observed.
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        !snapshot.managed_host_network_config_version_synced(),
        "sync should be false after a DPU-row write bumps the group"
    );
}

// Per-DPU network-config sync is rooted in the host-level
// `network_config.version`, not the DPU's own row version.
// carbide-api serves `host.version` to carbide-dpu-agent as
// `managed_host_config_version`, and the agent echoes it back
// as its observation; this just makes sure the host-level
// verison is looked at, and the DPU-level version is ignored.
#[crate::sqlx_test]
async fn test_managed_host_network_config_sync_host_version(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // Do a baseline check that the initial ingestion
    // `network_configured` brought DPU observations up
    // to host.version, meaning things shold be in sync.
    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        snapshot.managed_host_network_config_version_synced(),
        "sync should be true after ingestion"
    );

    // Now, bump just the DPU row's `network_config_version` via
    // a direct raw UPDATE (and bypassing `try_update_network_config`).
    // The idea is this shouldn't matter, since we're looking at the
    // host-level version.
    let dpu_before = mh.dpu().db_machine(&mut txn).await;
    let host_before = mh.host().db_machine(&mut txn).await;
    let drifted_dpu_version = dpu_before.network_config.version.increment();
    sqlx::query("UPDATE machines SET network_config_version = $1 WHERE id = $2")
        .bind(drifted_dpu_version)
        .bind(dpu_before.id)
        .execute(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let host_after = mh.host().db_machine(&mut txn).await;
    let dpu_after = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        host_after.network_config.version, host_before.network_config.version,
        "raw DPU update should leave host.version untouched"
    );
    assert_ne!(
        dpu_after.network_config.version, host_after.network_config.version,
        "dpu.row.version is now ahead of host.version"
    );

    // The observation version should still equal the host.version,
    // so things should still be in sync!
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        snapshot.managed_host_network_config_version_synced(),
        "sync should be true because observation == host.version, even though dpu.row.version is ahead"
    );
}

// A freshly-created host defaults to admin (`use_admin_network` = true);
// flipping the host-level `network_config.use_admin_network` to false
// must be reflected by `ManagedHostStateSnapshot::use_admin_network()`.
#[crate::sqlx_test]
async fn test_use_admin_network_reads_host_network_config(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        snapshot.use_admin_network(),
        "fresh host should default to admin network"
    );

    let host = mh.host().db_machine(&mut txn).await;
    let mut netconf = host.network_config.value.clone();
    netconf.use_admin_network = Some(false);
    db::machine::try_update_network_config(
        txn.as_mut(),
        &mh.id,
        host.network_config.version,
        &netconf,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(
        !snapshot.use_admin_network(),
        "host with network_config.use_admin_network=false should report tenant"
    );
}

#[crate::sqlx_test]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(!mh.host().db_machine(&mut txn).await.dpf.used_for_ingestion);
    for i in 0..mh.dpu_ids.len() {
        let dpu = mh.dpu_n(i).db_machine(&mut txn).await;
        assert!(!dpu.dpf.used_for_ingestion);
    }

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));

    let carbide_machines_per_state = env.test_meter.parsed_metrics("carbide_machines_per_state");

    assert!(carbide_machines_per_state.contains(&(
        "{fresh=\"true\",state=\"ready\",substate=\"\"}".to_string(),
        "3".to_string()
    )));

    let expected_states_entered = &[
        (
            r#"{state="dpunotready",substate="waitingfornetworkconfig"}"#,
            1,
        ),
        (
            r#"{state="dpunotready",substate="waitingforplatformconfiguration"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="discovered"}"#, 1),
        (
            r#"{state="hostnotready",substate="waitingfordiscovery"}"#,
            2,
        ),
        (r#"{state="hostnotready",substate="pollingbiossetup"}"#, 1),
        (
            r#"{state="hostnotready",substate="waitingforplatformconfiguration"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="waitingforlockdown"}"#, 4),
        (r#"{state="ready",substate=""}"#, 3),
    ];

    let states_entered = env
        .test_meter
        .parsed_metrics("carbide_machines_state_entered_total");

    for expected in expected_states_entered.iter() {
        let actual = states_entered
            .iter()
            .find(|s| s.0 == expected.0)
            .unwrap_or_else(|| panic!("Did not enter state {}", expected.0));
        assert_eq!(
            actual.1.parse::<i64>().unwrap(),
            expected.1,
            "Did not enter state {} {} times",
            expected.0,
            expected.1
        );
    }

    let expected_states_exited = &[
        ("{state=\"dpunotready\",substate=\"init\"}", 1),
        (
            "{state=\"dpunotready\",substate=\"waitingfornetworkconfig\"}",
            1,
        ),
        (
            "{state=\"dpunotready\",substate=\"waitingforplatformconfiguration\"}",
            1,
        ),
        ("{state=\"hostnotready\",substate=\"discovered\"}", 1),
        (
            "{state=\"hostnotready\",substate=\"waitingfordiscovery\"}",
            2,
        ),
        ("{state=\"hostnotready\",substate=\"pollingbiossetup\"}", 1),
        (
            "{state=\"hostnotready\",substate=\"waitingforplatformconfiguration\"}",
            1,
        ),
        (
            "{state=\"hostnotready\",substate=\"waitingforlockdown\"}",
            4,
        ),
    ];

    let states_exited = env
        .test_meter
        .parsed_metrics("carbide_machines_state_exited_total");

    for expected in expected_states_exited.iter() {
        let actual = states_exited
            .iter()
            .find(|s| s.0 == expected.0)
            .unwrap_or_else(|| panic!("Did not exit state {}", expected.0));
        assert_eq!(
            actual.1.parse::<i64>().unwrap(),
            expected.1,
            "Did not exit state {} {} times",
            expected.0,
            expected.1
        );
    }
}

#[crate::sqlx_test]
async fn test_machine_creator_created_host_advances_through_dpu_discovery(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prevent Firmware update here, since we test it in other method.
    let mut config = get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
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

    let machine_creator = MachineCreator::new(
        env.pool.clone(),
        explorer_config,
        env.common_pools.clone(),
        Arc::new(env.config.rack_profiles.clone()),
        None,
        env.test_credential_manager.clone(),
    );

    // Use a known DPU serial so we can assert on the generated MachineId.
    let dpu_serial = "MT2328XZ185R".to_string();
    let expected_machine_id =
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string();

    let mock_dpu = DpuConfig::with_serial(dpu_serial.clone());
    let oob_mac = mock_dpu.oob_mac_address;
    let response = env
        .api
        .discover_dhcp(
            rpc::forge::DhcpDiscovery::builder(oob_mac, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert!(!response.address.is_empty());

    let mock_host = ManagedHostConfig::default().with_dpus(vec![mock_dpu.clone()]);
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
            rpc::forge::DhcpDiscovery::builder(mock_host.bmc_mac_address, "192.0.1.1")
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
    let dpu_bmc_ip =
        discover_dpu_bmc_ip_for_machine_creator_state_test(&env, mock_dpu.bmc_mac_address).await?;
    let exploration_report = ExploredManagedHost {
        host_bmc_ip: host_bmc_ip.parse::<IpAddr>()?,
        dpus: vec![ExploredDpu {
            bmc_ip: dpu_bmc_ip,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        }],
    };

    let expected_machine = ExpectedMachine {
        id: Some(uuid::Uuid::new_v4()),
        bmc_mac_address: mock_host.bmc_mac_address,
        data: ExpectedMachineData::default(),
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

    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        dpu_report.machine_id.as_ref().unwrap(),
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    let dpu_machine_id = dpu_machine.id;
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
    assert_eq!(dpu_machine.bmc_info.ip, Some(dpu_bmc_ip));

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
    let host_machine_id = host_machine.id;
    assert!(
        matches!(
            host_machine.current_state(),
            ManagedHostState::DpuDiscoveringState { .. }
        ),
        "expected DpuDiscoveringState, got {:?}",
        host_machine.current_state(),
    );
    assert!(host_machine.bmc_info.ip.is_some());
    txn.commit().await.unwrap();

    // 2nd creation does nothing.
    assert!(
        !machine_creator
            .create_managed_host(
                &exploration_report,
                &mut EndpointExplorationReport::default(),
                Some(&expected_machine),
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

    // DpuDiscovering/Initializing -> DpuDiscovering/Configuring
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
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
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
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
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
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
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
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
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;
    // EnableSecureBoot: RebootDPU
    env.run_machine_state_controller_iteration().await;
    // CheckSecureBootStatus:
    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
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
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;
    // Wait for installComplete
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
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

    let machine_interfaces =
        db::machine_interface::find_by_mac_address(txn.as_mut(), oob_mac).await?;
    assert!(!machine_interfaces.is_empty());
    let machine_interface_id = machine_interfaces[0].id;
    let topologies = db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machine.id]).await?;
    assert!(topologies.contains_key(&dpu_machine.id));

    let pairs =
        db::machine_topology::find_machine_bmc_pairs_by_machine_id(&mut txn, vec![dpu_machine.id])
            .await?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].1, Some(dpu_bmc_ip.to_string()));

    let topology = &topologies[&dpu_machine.id][0];
    assert!(topology.topology_update_needed());

    let hardware_info = &topology.topology().discovery_data.info;
    assert!(hardware_info.block_devices.is_empty());

    let mut discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
    discovery_info.block_devices = vec![rpc::BlockDevice {
        model: "Fake block device".to_string(),
        ..Default::default()
    }];
    txn.commit().await.unwrap();

    let response = env
        .api
        .discover_machine(Request::new(rpc::MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(discovery_info.clone())),
            create_machine: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.machine_id.is_some());

    // Now let's check that DPU and host updated states and updated hardware information.
    let mut txn = env.db_txn().await;
    let dpu_machine = db::machine::find_one(
        txn.as_mut(),
        &dpu_machine_id,
        MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(dpu_machine.network_config.loopback_ip.is_some());

    let machine_interfaces =
        db::machine_interface::find_by_mac_address(txn.as_mut(), oob_mac).await?;
    assert!(
        machine_interfaces[0]
            .machine_id
            .as_ref()
            .is_some_and(|id| id == &dpu_machine.id)
    );

    let host_machine = db::machine::find_one(
        txn.as_mut(),
        &host_machine_id,
        MachineSearchConfig::default(),
    )
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
async fn test_waiting_for_rack_firmware_upgrade_waits_for_terminal_status(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host = create_managed_host(&env).await;

    let mut txn = env.db_txn().await;
    db::host_machine_update::trigger_host_reprovisioning_request(
        txn.as_mut(),
        "rack-test",
        &host.id,
    )
    .await?;
    db::machine::update_state(
        txn.as_mut(),
        &host.id,
        &ManagedHostState::HostReprovision {
            reprovision_state: model::machine::HostReprovisionState::WaitingForRackFirmwareUpgrade,
            retry_count: 0,
        },
    )
    .await?;
    let requested_at = db::machine::find_one(
        txn.as_mut(),
        &host.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist")
    .host_reprovision_requested
    .expect("rack reprovision request should exist")
    .requested_at;
    db::machine::update_rack_fw_details(
        txn.as_mut(),
        &host.id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::InProgress,
            started_at: Some(requested_at),
            ended_at: None,
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_machine_state_controller_iteration().await;

    let machine = db::machine::find_one(
        &pool,
        &host.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(matches!(
        machine.current_state(),
        ManagedHostState::HostReprovision {
            reprovision_state: model::machine::HostReprovisionState::WaitingForRackFirmwareUpgrade,
            ..
        }
    ));
    assert!(machine.host_reprovision_requested.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_waiting_for_rack_firmware_upgrade_advances_on_completion(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host = create_managed_host(&env).await;

    let mut txn = env.db_txn().await;
    db::host_machine_update::trigger_host_reprovisioning_request(
        txn.as_mut(),
        "rack-test",
        &host.id,
    )
    .await?;
    db::machine::update_state(
        txn.as_mut(),
        &host.id,
        &ManagedHostState::HostReprovision {
            reprovision_state: model::machine::HostReprovisionState::WaitingForRackFirmwareUpgrade,
            retry_count: 0,
        },
    )
    .await?;
    let requested_at = db::machine::find_one(
        txn.as_mut(),
        &host.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist")
    .host_reprovision_requested
    .expect("rack reprovision request should exist")
    .requested_at;
    db::machine::update_rack_fw_details(
        txn.as_mut(),
        &host.id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::Completed,
            started_at: Some(requested_at),
            ended_at: Some(chrono::Utc::now()),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_machine_state_controller_iteration().await;

    let machine = db::machine::find_one(
        &pool,
        &host.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(matches!(
        machine.current_state(),
        ManagedHostState::HostReprovision {
            reprovision_state: model::machine::HostReprovisionState::CheckingFirmwareRepeatV2 { .. },
            ..
        }
    ));
    assert!(machine.host_reprovision_requested.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_waiting_for_rack_firmware_upgrade_accepts_completion_when_only_ended_at_is_current(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host = create_managed_host(&env).await;

    let mut txn = env.db_txn().await;
    db::host_machine_update::trigger_host_reprovisioning_request(
        txn.as_mut(),
        "rack-test",
        &host.id,
    )
    .await?;
    db::machine::update_state(
        txn.as_mut(),
        &host.id,
        &ManagedHostState::HostReprovision {
            reprovision_state: model::machine::HostReprovisionState::WaitingForRackFirmwareUpgrade,
            retry_count: 0,
        },
    )
    .await?;
    let requested_at = db::machine::find_one(
        txn.as_mut(),
        &host.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist")
    .host_reprovision_requested
    .expect("rack reprovision request should exist")
    .requested_at;
    db::machine::update_rack_fw_details(
        txn.as_mut(),
        &host.id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::Completed,
            started_at: Some(requested_at - chrono::Duration::seconds(1)),
            ended_at: Some(requested_at + chrono::Duration::seconds(1)),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_machine_state_controller_iteration().await;

    let machine = db::machine::find_one(
        &pool,
        &host.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(matches!(
        machine.current_state(),
        ManagedHostState::HostReprovision {
            reprovision_state: model::machine::HostReprovisionState::CheckingFirmwareRepeatV2 { .. },
            ..
        }
    ));
    assert!(machine.host_reprovision_requested.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    db::machine::update_failure_details(
        &host,
        &mut txn,
        FailureDetails {
            cause: model::machine::FailureCause::NVMECleanFailed {
                err: "failed in module xyz.".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: model::machine::FailureSource::Scout,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // let state machine check the failure condition.
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { .. }
    ));
}

#[crate::sqlx_test]
async fn test_nvme_clean_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;

    let clean_failed_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
        nvme: Some(
            rpc::protos::forge::machine_cleanup_info::CleanupStepResult {
                result: rpc::protos::forge::machine_cleanup_info::CleanupResult::Error as i32,
                message: "test nvme failure".to_string(),
            },
        ),
        ..Default::default()
    });

    env.api
        .cleanup_machine_completed(clean_failed_req)
        .await
        .unwrap();

    update_time_params(
        &env.pool,
        &host,
        1,
        Some(host.last_reboot_requested.as_ref().unwrap().time - Duration::seconds(59)),
    )
    .await;
    // let state machine check the failure condition.
    env.run_machine_state_controller_iteration().await;

    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::NVMECleanFailed { .. },
                ..
            },
            retry_count: 0,
            ..
        }
    ));

    // Fail again
    let clean_failed_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
        nvme: Some(
            rpc::protos::forge::machine_cleanup_info::CleanupStepResult {
                result: rpc::protos::forge::machine_cleanup_info::CleanupResult::Error as i32,
                message: "test nvme failure".to_string(),
            },
        ),
        ..Default::default()
    });
    env.api
        .cleanup_machine_completed(clean_failed_req)
        .await
        .unwrap();

    // let state machine check the failure condition.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::NVMECleanFailed { .. },
                ..
            },
            retry_count: 1,
            ..
        }
    ));
    // Now the host cleans up successfully.
    let clean_succeeded_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
        ..Default::default()
    });
    env.api
        .cleanup_machine_completed(clean_succeeded_req)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // Run the state machine.
    env.run_machine_state_controller_iteration().await;

    // Check that we've moved the machine to the WaitingForCleanup state.
    let mut txn = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::WaitingForCleanup { .. }
    ));
}

#[crate::sqlx_test]
async fn test_repeated_initial_discovery_cleanup_failure_preserves_host_init_source(
    pool: sqlx::PgPool,
) {
    fn cleanup_failed_request(machine_id: MachineId) -> Request<rpc::MachineCleanupInfo> {
        Request::new(rpc::MachineCleanupInfo {
            machine_id: machine_id.into(),
            nvme: Some(
                rpc::protos::forge::machine_cleanup_info::CleanupStepResult {
                    result: rpc::protos::forge::machine_cleanup_info::CleanupResult::Error as i32,
                    message: "test nvme failure".to_string(),
                },
            ),
            ..Default::default()
        })
    }

    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let waiting_for_initial_discovery_cleanup = ManagedHostState::WaitingForCleanup {
        cleanup_state: CleanupState::HostCleanup {
            boss_controller_id: None,
        },
        cleanup_context: CleanupContext::InitialDiscovery,
    };

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    db::machine::advance(
        &host,
        &mut txn,
        &waiting_for_initial_discovery_cleanup,
        None,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    env.api
        .cleanup_machine_completed(cleanup_failed_request(mh.id))
        .await
        .unwrap();
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: FailureCause::NVMECleanFailed { .. },
                source: FailureSource::StateMachineArea(StateMachineArea::HostInit),
                ..
            },
            ..
        }
    ));
    assert!(matches!(
        host.failure_details.source,
        FailureSource::StateMachineArea(StateMachineArea::HostInit)
    ));
    let first_failed_at = host.failure_details.failed_at;
    txn.commit().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(1)).await;

    env.api
        .cleanup_machine_completed(cleanup_failed_request(mh.id))
        .await
        .unwrap();

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.failure_details.source,
        FailureSource::StateMachineArea(StateMachineArea::HostInit)
    ));
    assert!(
        host.failure_details.failed_at > first_failed_at,
        "repeated cleanup failure should refresh failure details"
    );
    txn.commit().await.unwrap();

    env.api
        .cleanup_machine_completed(Request::new(rpc::MachineCleanupInfo {
            machine_id: mh.id.into(),
            ..Default::default()
        }))
        .await
        .unwrap();

    // Make the recovery timestamp unambiguously newer than the failed state version and failed_at.
    let mut txn = env.db_txn().await;
    db::machine::set_cleanup_time(&mh.id, chrono::Utc::now() + Duration::seconds(1), &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery
        }
    ));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_hdd_clean_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;

    let clean_failed_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
        hdd: Some(
            rpc::protos::forge::machine_cleanup_info::CleanupStepResult {
                result: rpc::protos::forge::machine_cleanup_info::CleanupResult::Error as i32,
                message: "test hdd failure".to_string(),
            },
        ),
        ..Default::default()
    });

    env.api
        .cleanup_machine_completed(clean_failed_req)
        .await
        .unwrap();

    update_time_params(
        &env.pool,
        &host,
        1,
        Some(host.last_reboot_requested.as_ref().unwrap().time - Duration::seconds(59)),
    )
    .await;
    // let state machine check the failure condition.
    env.run_machine_state_controller_iteration().await;

    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::NVMECleanFailed { .. },
                ..
            },
            retry_count: 0,
            ..
        }
    ));
}

/// If the DPU stops sending us health updates we eventually mark it unhealthy
#[crate::sqlx_test]
async fn test_dpu_heartbeat(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // Ensure DPU network status is recorded
    mh.network_configured(&env).await;

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;

    // create_dpu_machine runs record_dpu_network_status, so machine should be healthy
    let dpu_machine = mh.dpu().db_machine(&mut txn).await;
    assert!(
        dpu_machine
            .dpu_agent_health_report()
            .unwrap()
            .alerts
            .is_empty()
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_up_count{fresh=\"true\"}")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_healthy_count{fresh=\"true\"}")
            .unwrap(),
        r#"1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_health_check_failed_count"),
        None
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}"),
        None,
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"hardware-health\"}"),
        None,
    );

    // Tell state handler to mark DPU as unhealthy after 1 second
    let handler = MachineStateHandlerBuilder::builder()
        .dpu_up_threshold(chrono::Duration::seconds(1))
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .hardware_models(env.config.get_firmware_config())
        .power_options_config(env.config.power_manager_options.clone().into())
        .build();
    env.override_machine_state_controller_handler(handler).await;
    env.run_machine_state_controller_iteration().await;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler *twice* because metrics are reported before
    // state transitions occur in `handle_object_state`. Thus, we can only see
    // the updated metrics set in the first iteration by running another round.
    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    // Now the network should be marked unhealthy
    let dpu_machine = mh.dpu().db_machine(&mut txn).await;
    assert!(
        !dpu_machine
            .dpu_agent_health_report()
            .unwrap()
            .alerts
            .is_empty(),
        "DPU is not healthy: {:?}",
        dpu_machine.dpu_agent_health_report().unwrap()
    );

    // The up count reflects the heartbeat timeout.
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_up_count{fresh=\"true\"}")
            .unwrap(),
        "0"
    );
    // The report now says heartbeat timeout, which is unhealthy.
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_healthy_count{fresh=\"true\"}")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_health_check_failed_count{failure=\"HeartbeatTimeout [Target: forge-dpu-agent]\",fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",in_use=\"false\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}")
            .unwrap(),
        "1",
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",in_use=\"false\",probe_id=\"HeartbeatTimeout\",probe_target=\"hardware-health\"}"),
        None,
    );
    assert_eq!(
        env.test_meter
            .formatted_metric(
                "carbide_hosts_health_status_count{fresh=\"true\",healthy=\"false\",in_use=\"false\"}"
            )
            .unwrap(),
        "1"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_failed_state_host_discovery_recovery(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    db::machine::update_failure_details(
        &host,
        &mut txn,
        FailureDetails {
            cause: model::machine::FailureCause::Discovery {
                err: "host discovery failed".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: model::machine::FailureSource::Scout,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // let state machine check the failure condition.

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { retry_count: 0, .. }
    ));
    txn.commit().await.unwrap();

    update_time_params(&env.pool, &host, 1, None).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { retry_count: 1, .. }
    ));

    txn.commit().await.unwrap();
    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: rpc::forge::MachineArchitecture::X86 as i32,
            product: None,
            client_ip: Some(host.interfaces[0].addresses[0].to_string()),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(pxe.pxe_script.contains("scout.efi"));

    let response = forge_agent_control(&env, mh.id).await;
    assert!(matches!(response.action, Some(Action::Discovery(_))));
    assert_eq!(response.legacy_action, LegacyAction::Discovery as i32);

    discovery_completed(&env, mh.id).await;

    env.run_machine_state_controller_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_reboot_attempts_in_failed_during_discovery_sum")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_reboot_attempts_in_failed_during_discovery_count")
            .unwrap(),
        "1"
    );

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(host.last_reboot_requested.is_some());
    let last_reboot_requested_time = host.last_reboot_requested.as_ref().unwrap().time;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown { .. },
        }
    ));
    txn.commit().await.unwrap();

    // First wait for the lockdown state machine to reach WaitForDPUUp
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        5,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: model::machine::LockdownInfo {
                    state: model::machine::LockdownState::WaitForDPUUp,
                    mode: model::machine::LockdownMode::Enable,
                },
            },
        },
    )
    .await;

    // We use dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    mh.network_configured(&env).await;

    // Now wait for validation state after DPU is up
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        10,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Discovery".to_string(),
                    id: MachineValidationId::new(),
                    completed: 1,
                    total: 1,
                    is_enabled: true,
                },
            },
        },
    )
    .await;

    mh.machine_validation_completed().await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        4,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert_ne!(
        last_reboot_requested_time,
        host.last_reboot_requested.as_ref().unwrap().time
    );
    txn.commit().await.unwrap();

    let response = forge_agent_control(&env, mh.id).await;
    assert!(matches!(response.action, Some(Action::Noop(_))));
    assert_eq!(response.legacy_action, LegacyAction::Noop as i32);
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        1,
        ManagedHostState::Ready,
    )
    .await;
}

/// Check whether metrics that describe hardware/software versions of discovered machines
/// are emitted correctly
#[crate::sqlx_test]
async fn test_managed_host_version_metrics(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    common::api_fixtures::create_managed_host(&env).await;
    common::api_fixtures::create_managed_host(&env).await;

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_gpus_in_use_count")
            .unwrap(),
        r#"{fresh="true"} 0"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_in_use_count")
            .unwrap(),
        r#"{fresh="true"} 0"#
    );
    // TODO: For some reason the 2nd created Host stays in state `Discovered`
    // and never becomes ready. Once it does, the test should be updated.
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_usable_count")
            .unwrap(),
        r#"{fresh="true"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_gpus_usable_count")
            .unwrap(),
        r#"{fresh="true"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_gpus_total_count")
            .unwrap(),
        r#"{fresh="true"} 2"#
    );

    let mut health_status_metrics = env
        .test_meter
        .formatted_metrics("carbide_hosts_health_status_count");
    health_status_metrics.sort();
    assert_eq!(health_status_metrics.len(), 4);

    for expected in [
        r#"{fresh="true",healthy="false",in_use="false"} 0"#,
        r#"{fresh="true",healthy="true",in_use="false"} 2"#,
        r#"{fresh="true",healthy="false",in_use="true"} 0"#,
        r#"{fresh="true",healthy="true",in_use="true"} 0"#,
    ] {
        assert!(
            health_status_metrics.iter().any(|m| m.as_str() == expected),
            "Expected to find {expected}. Got {health_status_metrics:?}"
        );
    }

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_firmware_version_count")
            .unwrap(),
        r#"{firmware_version="24.42.1000",fresh="true"} 2"#,
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_agent_version_count")
            .unwrap(),
        format!(r#"{{fresh="true",version="{TEST_DPU_AGENT_VERSION}"}} 2"#)
    );

    let mut inventory_metrics = env
        .test_meter
        .formatted_metrics("carbide_machine_inventory_component_version_count");
    inventory_metrics.sort();

    for expected in &[
        format!(r#"{{fresh="true",name="doca-hbn",version="{TEST_DOCA_HBN_VERSION}"}} 2"#),
        format!(
            r#"{{fresh="true",name="doca-telemetry",version="{TEST_DOCA_TELEMETRY_VERSION}"}} 2"#
        ),
    ] {
        assert!(
            inventory_metrics
                .iter()
                .any(|m| m.as_str() == expected.as_str()),
            "Expected to find {expected}. Got {inventory_metrics:?}"
        );
    }

    // Now that we track all hosts (including those without SKU as "unknown"),
    // we should have SKU metrics for the created hosts
    let sku_metrics = env
        .test_meter
        .formatted_metric("carbide_hosts_by_sku_count");
    assert_eq!(
        sku_metrics.unwrap(),
        r#"{device_type="unknown",fresh="true",sku="unknown"} 2"#
    );
}

/// Check that controller state reason is correct as we work through the states
#[crate::sqlx_test]
async fn test_state_outcome(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let mh = create_dpu_machine_in_waiting_for_network_install(&env, &host_config).await;

    let mut txn = env.db_txn().await;
    let host_machine = mh.host().db_machine(&mut txn).await;
    txn.rollback().await.unwrap();
    let expected_state = ManagedHostState::DPUInit {
        dpu_states: model::machine::DpuInitStates {
            states: HashMap::from([(mh.dpu().id, DpuInitState::WaitingForNetworkConfig)]),
        },
    };
    assert_eq!(
        host_machine.current_state(),
        &expected_state,
        "machine should be in DPUInit, waiting for network config"
    );
    assert!(
        matches!(
            host_machine.controller_state_outcome,
            Some(PersistentStateHandlerOutcome::Transition { .. })
        ),
        "Machine should have just transitioned into WaitingForNetworkConfig"
    );

    // Scout does its thing

    let _ = mh.dpu().forge_agent_control().await;

    // Now we're stuck waiting for DPU agent to run
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let host_machine = mh.host().db_machine(&mut txn).await;
    txn.rollback().await.unwrap();
    let outcome = host_machine.controller_state_outcome.unwrap();
    assert!(
        matches!(outcome, PersistentStateHandlerOutcome::Wait{ reason, source_ref: Some(source_ref) } if !reason.is_empty() && source_ref.file.ends_with("/handler.rs")),
        "Third iteration should be waiting for DPU agent, and include a wait reason and source reference",
    );
}

#[crate::sqlx_test]
async fn test_state_sla(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // When the Machine is in Ready state, there is no SLA
    let machine = mh.host().rpc_machine().await;
    let sla = machine.state_sla.as_ref().unwrap();
    assert!(!sla.time_in_state_above_sla);
    assert!(sla.sla.is_none());

    // Now do a Hack and move the Machine into a failed state - which has a SLA
    let mut txn = env.db_txn().await;
    db::machine::update_state(
        &mut txn,
        &mh.id,
        &ManagedHostState::Failed {
            details: FailureDetails {
                cause: FailureCause::NoError,
                failed_at: chrono::Utc::now(),
                source: FailureSource::NoError,
            },
            machine_id: mh.id,
            retry_count: 1,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let machine = mh.host().rpc_machine().await;
    let sla = machine.state_sla.as_ref().unwrap();
    assert!(sla.time_in_state_above_sla);
    assert_eq!(sla.sla.unwrap(), std::time::Duration::from_secs(0).into());
}

/// test_measurement_failed_state_transition is used to test the state
/// machine changes surrounding measured boot, more specifically, making
/// sure the handle_measuring_state function works as expected, in terms
/// of being able to fluidly switch back and forth between Ready/Failed
/// states in reaction to measurement bundle management changes behind the
/// scenes via the API and/or CLI.
///
/// This includes the initial movement of a machine to Ready state after
/// initial attestation, "failure" of a machine (out of Ready state) into
/// a FailureCause::MeasurementsRetired state by retiring the bundle that
/// put it into Ready state, and then re-activating the bundle to move
/// the machine from ::Failed -> back to ::Ready.
#[crate::sqlx_test]
async fn test_measurement_failed_state_transition(pool: sqlx::PgPool) {
    // For this test case, we'll flip on attestation, which will
    // introduce the measurement states into the state machine (which
    // also includes additional steps that happen during `create_managed_host`.
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let mh = create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    env.run_machine_state_controller_iteration().await;

    // This is kind of redundant since `create_managed_host` returns a machine
    // in Ready state, but, just to be super explicit...
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();

    // At this point there is an attested/measured machine in Ready state,
    // so get its bundle, retire it, run another iteration, and make sure
    // it's retired.
    let bundles_response = env
        .api
        .show_measurement_bundles(Request::new(
            rpc::protos::measured_boot::ShowMeasurementBundlesRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(1, bundles_response.bundles.len());
    let bundle = MeasurementBundle::from_grpc(bundles_response.bundles[0].clone()).unwrap();
    assert_eq!(bundle.state, MeasurementBundleState::Active);
    let mut txn = env.db_txn().await;
    let retired_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        bundle.bundle_id,
        MeasurementBundleState::Retired,
    )
    .await
    .unwrap();
    assert_eq!(bundle.bundle_id, retired_bundle.bundle_id);
    assert_eq!(retired_bundle.state, MeasurementBundleState::Retired);
    txn.commit().await.unwrap();

    // .. and now flip it to retired.
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsRetired { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // ..and now reactivate the bundle.
    let mut txn = env.db_txn().await;
    let reactivated_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    assert_eq!(retired_bundle.bundle_id, reactivated_bundle.bundle_id);
    txn.commit().await.unwrap();

    // ..and now flip it back.
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

// this is mostly copied from the one above
#[crate::sqlx_test]
async fn test_measurement_ready_to_retired_to_ca_fail_to_revoked_to_ready(pool: sqlx::PgPool) {
    // For this test case, we'll flip on attestation, which will
    // introduce the measurement states into the state machine (which
    // also includes additional steps that happen during `create_managed_host`.
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    let inserted_cert = env
        .api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert")
        .into_inner();

    let mh = create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    env.run_machine_state_controller_iteration().await;

    // This is kind of redundant since `create_managed_host` returns a machine
    // in Ready state, but, just to be super explicit...
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();

    // At this point there is an attested/measured machine in Ready state,
    // so get its bundle, retire it, run another iteration, and make sure
    // it's retired.

    let bundles_response = env
        .api
        .show_measurement_bundles(Request::new(
            rpc::protos::measured_boot::ShowMeasurementBundlesRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(1, bundles_response.bundles.len());
    let bundle = MeasurementBundle::from_grpc(bundles_response.bundles[0].clone()).unwrap();
    assert_eq!(bundle.state, MeasurementBundleState::Active);
    let mut txn = env.db_txn().await;
    let retired_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        bundle.bundle_id,
        MeasurementBundleState::Retired,
    )
    .await
    .unwrap();
    assert_eq!(bundle.bundle_id, retired_bundle.bundle_id);
    assert_eq!(retired_bundle.state, MeasurementBundleState::Retired);
    txn.commit().await.unwrap();

    // now trigger the state transition
    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    // make sure the machine is in retired state
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    // and confirm that it is actually in the retired state
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsRetired { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // now remove the ca cert and resurrect the bundle
    // and try to move forward - this will now fail due to the lack
    // of ca cert
    let delete_ca_certs_request = tonic::Request::new(TpmCaCertId {
        ca_cert_id: inserted_cert.id.unwrap().ca_cert_id,
    });
    env.api
        .tpm_delete_ca_cert(delete_ca_certs_request)
        .await
        .unwrap();
    // "resurrect" the bundle
    let mut txn = env.db_txn().await;
    let reactivated_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    assert_eq!(retired_bundle.bundle_id, reactivated_bundle.bundle_id);
    txn.commit().await.unwrap();

    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    // check that it has failed as intended due to the lack of ca cert
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsCAValidationFailed { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // ... and now re-insert the ca cert
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    // before advancing the state, change the bundle state to revoked
    let mut txn = env.db_txn().await;
    let _revoked_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        bundle.bundle_id,
        MeasurementBundleState::Revoked,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // ... and trigger the state transition
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    // check we are in revoked state
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsRevoked { .. },
                ..
            },
            ..
        }
    ));

    // and now reactivate the state so that it would get to ready
    let _reactivated_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // ... and trigger the state transition
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_measurement_host_init_failed_to_waiting_for_measurements_to_pending_bundle_to_ready(
    pool: sqlx::PgPool,
) {
    let mut config = get_config();
    config.attestation_enabled = true;
    config.spdm.enabled = true;

    let mut overrides = TestEnvOverrides::with_config(config);

    // set NRAS verifier to fail
    let nras_should_fail_parsing_flag = Arc::new(AtomicBool::new(true));

    overrides.nras_should_fail_parsing = Some(nras_should_fail_parsing_flag.clone());

    let env = create_test_env_with_overrides(pool, overrides).await;

    // 1. create_dpu as usual
    // 2. start creating host until ca validation failure is encountered
    // 3. add ca certificate - we should recover from failure and go into Ready state

    let host_config = ManagedHostConfig {
        tpm_ek_cert: TpmEkCertificate::from(EK_CERT_SERIALIZED.to_vec()),
        ..ManagedHostConfig::default()
    };

    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    //--------
    let env = &env;

    let machine_interface_id = host_discover_dhcp(env, &host_config, &dpu_machine_id).await;

    let host_machine_id = host_discover_machine(env, &host_config, machine_interface_id).await;
    let mh = TestManagedHost {
        id: host_machine_id,
        dpu_ids: vec![dpu_machine_id],
        api: env.api.clone(),
    };

    // ---------------
    // now, since the CA has not been added, we should be stuck in the failed state
    for _ in 0..11 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.db_txn().await;

    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsCAValidationFailed { .. },
                ..
            },
            ..
        }
    ));
    // ----------
    // now add the CA cert, we should transition to waiting for measurements
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    let _inserted_cert = env
        .api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert")
        .into_inner();

    env.run_machine_state_controller_iteration().await;

    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::Measuring {
                measuring_state: MeasuringState::WaitingForMeasurements
            }
        }
    ));
    //----------
    // now inject some measurement values

    let pcr_values: Vec<PcrRegisterValue> = vec![
        PcrRegisterValue {
            pcr_register: 0,
            sha_any: "aa".to_string(),
        },
        PcrRegisterValue {
            pcr_register: 1,
            sha_any: "bb".to_string(),
        },
    ];

    let _response = env
        .api
        .attest_candidate_machine(Request::new(
            rpc::protos::measured_boot::AttestCandidateMachineRequest {
                machine_id: host_machine_id.to_string(),
                pcr_values: convert_vec(pcr_values),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    // now we should be in pending bundle state
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::Measuring {
                measuring_state: MeasuringState::PendingBundle
            }
        }
    ));

    // now promote report to bundle
    let reports_response = env
        .api
        .show_measurement_reports(Request::new(
            rpc::protos::measured_boot::ShowMeasurementReportsRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(1, reports_response.reports.len());
    let report = MeasurementReport::from_grpc(reports_response.reports[0].clone()).unwrap();

    let _promotion_response = env
        .api
        .promote_measurement_report(Request::new(
            rpc::protos::measured_boot::PromoteMeasurementReportRequest {
                report_id: Some(report.report_id),
                pcr_registers: "0,1".to_string(),
            },
        ))
        .await
        .unwrap();

    // ---------
    // now do the spdm attestation

    spdm_attestation_run_to_failed_then_to_success(
        env,
        nras_should_fail_parsing_flag,
        &mh,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::SpdmMeasuring {
                spdm_measuring_state: SpdmMeasuringState::PollResult,
            },
        },
    )
    .await;

    // ---------
    // after the measurements are in, we should proceed to ready state
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        5,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery,
        },
    )
    .await;

    env.api
        .insert_machine_health_report(Request::new(InsertMachineHealthReportRequest {
            health_report_entry: Some(HealthReportEntry {
                report: Some(
                    HealthReport::empty(format!("{HARDWARE_HEALTH_OVERRIDE_PREFIX}health")).into(),
                ),
                ..Default::default()
            }),
            machine_id: Some(host_machine_id),
        }))
        .await
        .expect("Failed to add hardware health report to newly created machine");

    let response = mh.host().forge_agent_control().await;
    assert!(matches!(response.action, Some(Action::Retry(_))));
    assert_eq!(response.legacy_action, LegacyAction::Retry as i32);

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        ManagedHostState::WaitingForCleanup {
            cleanup_state: CleanupState::HostCleanup {
                boss_controller_id: None,
            },
            cleanup_context: CleanupContext::InitialDiscovery,
        },
    )
    .await;

    let response = mh.host().forge_agent_control().await;
    assert!(matches!(response.action, Some(Action::Reset(_))));
    assert_eq!(response.legacy_action, LegacyAction::Reset as i32);

    env.api
        .cleanup_machine_completed(Request::new(rpc::MachineCleanupInfo {
            machine_id: mh.id.into(),
            ..Default::default()
        }))
        .await
        .unwrap();

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery,
        },
    )
    .await;

    let response = mh.host().forge_agent_control().await;
    assert!(matches!(response.action, Some(Action::Discovery(_))));
    assert_eq!(response.legacy_action, LegacyAction::Discovery as i32);

    mh.host().discovery_completed().await;

    host_uefi_setup(env, &host_machine_id).await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        10,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: model::machine::LockdownInfo {
                    state: model::machine::LockdownState::WaitForDPUUp,
                    mode: LockdownMode::Enable,
                },
            },
        },
    )
    .await;

    // We use forge_dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    mh.network_configured(env).await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        10,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Discovery".to_string(),
                    id: MachineValidationId::new(),
                    completed: 1,
                    total: 1,
                    is_enabled: env.config.machine_validation_config.enabled,
                },
            },
        },
    )
    .await;

    mh.machine_validation_completed().await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;

    // This is what simulates a reboot being completed.
    let response = mh.host().forge_agent_control().await;
    assert!(matches!(response.action, Some(Action::Noop(_))));
    assert_eq!(response.legacy_action, LegacyAction::Noop as i32);

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        1,
        ManagedHostState::Ready,
    )
    .await;
}

#[crate::sqlx_test]
async fn test_update_reboot_requested_time_off(pool: sqlx::PgPool) {
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let mh = create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    let mut write_batch = DbWriteBatch::new();
    let mut services = env.machine_state_handler_services();
    let mut metrics = MachineMetrics::default();
    let mut ctx = StateHandlerContext::<MachineStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut write_batch,
    };
    handler_host_power_control(
        &snapshot,
        &mut ctx,
        libredfish::SystemPowerControl::ForceOff,
    )
    .await
    .unwrap();
    write_batch.apply_all(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;

    let snapshot1 = mh.snapshot(&mut txn).await;
    for i in 0..snapshot.dpu_snapshots.len() {
        assert_ne!(
            snapshot.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .map(|x| x.time)
                .unwrap_or_default(),
            snapshot1.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .unwrap()
                .time
        );
    }

    let mut txn = env.db_txn().await;
    let mut write_batch = DbWriteBatch::new();
    let mut services = env.machine_state_handler_services();
    let mut metrics = MachineMetrics::default();
    let mut ctx = StateHandlerContext::<MachineStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut write_batch,
    };
    handler_host_power_control(&snapshot, &mut ctx, libredfish::SystemPowerControl::On)
        .await
        .unwrap();
    write_batch.apply_all(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let snapshot2 = mh.snapshot(&mut txn).await;
    for i in 0..snapshot.dpu_snapshots.len() {
        assert_ne!(
            snapshot1.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .map(|x| x.time)
                .unwrap_or_default(),
            snapshot2.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .unwrap()
                .time
        );
    }

    let mut txn = env.db_txn().await;
    let mut write_batch = DbWriteBatch::new();
    let mut services = env.machine_state_handler_services();
    let mut metrics = MachineMetrics::default();
    let mut ctx = StateHandlerContext::<MachineStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut write_batch,
    };
    handler_host_power_control(
        &snapshot,
        &mut ctx,
        libredfish::SystemPowerControl::ForceRestart,
    )
    .await
    .unwrap();
    write_batch.apply_all(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let snapshot3 = mh.snapshot(&mut txn).await;

    for i in 0..snapshot.dpu_snapshots.len() {
        assert_eq!(
            snapshot2.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .map(|x| x.time)
                .unwrap_or_default(),
            snapshot3.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .unwrap()
                .time
        );
    }
}

/// Exercises WaitingForBiosJob state by configuring mock BMC to return a job ID from machine_setup.
/// Verifies that host reaches "Ready" and that state machine transitioned through WaitingForBiosJob.
#[crate::sqlx_test]
async fn test_bios_config_job_happy_path(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    env.redfish_sim
        .set_machine_setup_bios_job_id(Some("JID_BIOS_TEST_123".to_string()));
    env.redfish_sim.set_job_state_sequence(vec![
        libredfish::JobState::Scheduled,
        libredfish::JobState::Completed,
    ]);

    let mh = common::api_fixtures::create_managed_host(&env).await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(
        matches!(host.current_state(), ManagedHostState::Ready),
        "Expected host to reach Ready, but got: {:?}",
        host.current_state()
    );

    let history = mh.host().parsed_history(None).await;
    let went_through_bios_job = history.iter().any(|state| {
        matches!(
            state,
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForBiosJob { .. },
            }
        )
    });
    assert!(
        went_through_bios_job,
        "Expected state history to include WaitingForBiosJob, but it did not. History: {:#?}",
        history
    );
}

/// When HostInit/PollingBiosSetup is stuck, enter HandleBiosJobFailure recovery.
#[crate::sqlx_test]
async fn test_polling_bios_setup_stuck_enters_handle_bios_job_failure(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mh = common::api_fixtures::create_managed_host(&env).await;
    let host_id = mh.host().id;

    env.redfish_sim.set_is_bios_setup(false);

    set_host_controller_state_stuck_in(
        &env,
        host_id,
        &ManagedHostState::HostInit {
            machine_state: MachineState::PollingBiosSetup { retry_count: 0 },
        },
        16,
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(
        matches!(
            host.current_state(),
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForBiosJob {
                    bios_config_info: BiosConfigInfo {
                        bios_job_id: None,
                        retry_count: 1,
                        bios_config_state: BiosConfigState::HandleBiosJobFailure {
                            power_state: PowerState::Off,
                            ..
                        },
                    },
                },
            }
        ),
        "expected stuck HostInit/PollingBiosSetup to enter HandleBiosJobFailure recovery, got: {:?}",
        host.current_state()
    );
}

/// Assigned/HostPlatformConfiguration/PollingBiosSetup stuck recovery enters HandleBiosJobFailure.
#[crate::sqlx_test]
async fn test_hpc_polling_bios_setup_stuck_enters_handle_bios_job_failure(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mh = common::api_fixtures::create_managed_host(&env).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    create_instance(&env, &mh, false, segment_id).await;
    let host_id = mh.host().id;

    env.redfish_sim.set_is_bios_setup(false);

    set_host_controller_state_stuck_in(
        &env,
        host_id,
        &ManagedHostState::Assigned {
            instance_state: InstanceState::HostPlatformConfiguration {
                platform_config_state: HostPlatformConfigurationState::PollingBiosSetup {
                    retry_count: 0,
                },
            },
        },
        16,
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(
        matches!(
            host.current_state(),
            ManagedHostState::Assigned {
                instance_state: InstanceState::HostPlatformConfiguration {
                    platform_config_state: HostPlatformConfigurationState::WaitingForBiosJob {
                        bios_config_info: BiosConfigInfo {
                            bios_job_id: None,
                            retry_count: 1,
                            bios_config_state: BiosConfigState::HandleBiosJobFailure {
                                power_state: PowerState::Off,
                                ..
                            },
                        },
                    },
                },
            }
        ),
        "expected stuck Assigned/HostPlatformConfiguration/PollingBiosSetup to enter HandleBiosJobFailure recovery, got: {:?}",
        host.current_state()
    );
}

/// Stuck HostInit/PollingBiosSetup recovery re-runs machine_setup and reaches HostInit/SetBootOrder.
#[crate::sqlx_test]
async fn test_polling_bios_setup_full_recovery_reruns_machine_setup_and_succeeds(
    pool: sqlx::PgPool,
) {
    let env = create_test_env(pool).await;

    let mh = common::api_fixtures::create_managed_host(&env).await;
    let host_id = mh.host().id;

    env.redfish_sim.set_is_bios_setup(false);

    set_host_controller_state_stuck_in(
        &env,
        host_id,
        &ManagedHostState::HostInit {
            machine_state: MachineState::PollingBiosSetup { retry_count: 0 },
        },
        16,
    )
    .await;

    let redfish_timepoint = env.redfish_sim.timepoint();

    // Escalate into HandleBiosJobFailure while BIOS still reports not ready.
    env.run_machine_state_controller_iteration().await;
    env.redfish_sim.set_is_bios_setup(true);

    // ForceOff records last_reboot_requested; backdate it so power_down_wait elapses in-process.
    env.run_machine_state_controller_iteration().await;
    {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        update_time_params(&env.pool, &host, 1, None).await;
    }

    let mut reached_set_boot_order = false;
    for _ in 0..30 {
        env.run_machine_state_controller_iteration().await;

        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        if matches!(
            host.current_state(),
            ManagedHostState::HostInit {
                machine_state: MachineState::SetBootOrder { .. },
            }
        ) {
            reached_set_boot_order = true;
            break;
        }

        if matches!(
            host.current_state(),
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForLockdown {
                    lockdown_info: model::machine::LockdownInfo {
                        state: model::machine::LockdownState::WaitForDPUUp
                            | model::machine::LockdownState::TimeWaitForDPUDown,
                        ..
                    },
                },
            }
        ) {
            if host.last_reboot_requested.is_some() {
                update_time_params(&env.pool, &host, 1, None).await;
            }
            mh.network_configured(&env).await;
        }
    }
    if !reached_set_boot_order {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        panic!(
            "expected recovery to reach HostInit/SetBootOrder, got: {:?}",
            host.current_state()
        );
    }

    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, RedfishSimAction::BmcReset)),
        "expected BMC reset during stuck HostInit/PollingBiosSetup recovery, got: {actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, RedfishSimAction::MachineSetup { .. })),
        "expected machine_setup to be re-run after recovery, got: {actions:?}"
    );
}

/// Builds a test env wired for zero-DPU (NIC-mode) ingestion: the admin and
/// host-inband site prefixes are routable and the host-inband segment exists,
/// so a zero-DPU host's in-band NIC takes a real `machine_interfaces` row that
/// the boot-order phase can resolve. Mirrors `test_dhcp_allows_zero_dpu_host`.
async fn create_zero_dpu_test_env(pool: sqlx::PgPool) -> TestEnv {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
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
            ]),
            ..Default::default()
        },
    )
    .await;
    create_host_inband_network_segment(&env.api, None).await;
    env
}

/// Places a host directly in HostInit/SetBootOrder at the start of the
/// boot-order flow, backdated so it reads as freshly entered.
async fn set_host_stuck_in_set_boot_order(env: &TestEnv, host_id: MachineId) {
    set_host_controller_state_stuck_in(
        env,
        host_id,
        &ManagedHostState::HostInit {
            machine_state: MachineState::SetBootOrder {
                set_boot_order_info: Some(SetBootOrderInfo {
                    set_boot_order_jid: None,
                    set_boot_order_state: SetBootOrderState::SetBootOrder,
                    retry_count: 0,
                }),
            },
        },
        1,
    )
    .await;
}

/// Drives the machine state controller until the host leaves HostInit/SetBootOrder
/// for the next phase (HostInit/Measuring), returning whether it got there. A
/// zero-DPU host whose `HttpDev1` device has de-enumerated never reaches it
/// unless SetBootOrder re-asserts `machine_setup`, so callers assert on the
/// result to distinguish recovery from a host wedged at CheckBootOrder.
async fn drive_until_past_set_boot_order(
    env: &TestEnv,
    mh: &TestManagedHost,
    max_iterations: usize,
) -> bool {
    for _ in 0..max_iterations {
        env.run_machine_state_controller_iteration().await;

        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        if matches!(
            host.current_state(),
            ManagedHostState::HostInit {
                machine_state: MachineState::Measuring { .. },
            }
        ) {
            return true;
        }
    }
    false
}

/// The MAC of the zero-DPU host's in-band NIC -- the boot interface the
/// boot-order phase resolves and targets. Looked up by segment type (the same
/// way the admin boot-interface resolution tests locate it), since a zero-DPU
/// host boots from its HostInband NIC.
async fn host_inband_nic_mac(env: &TestEnv, host_id: MachineId) -> MacAddress {
    let mut txn = env.pool.begin().await.unwrap();
    db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
        .await
        .unwrap()
        .remove(&host_id)
        .expect("zero-DPU host should have interface rows")
        .into_iter()
        .find(|i| i.network_segment_type == Some(NetworkSegmentType::HostInband))
        .expect("zero-DPU host should have a HostInband interface")
        .mac_address
}

/// Asserts that, within the recorded boot-order actions, `machine_setup` ran
/// before the `set_boot_order_dpu_first` reorder, and that BOTH targeted
/// `expected_mac` -- the resolved boot NIC. This is the ordering the recovery
/// depends on: re-enable `HttpDev1`, then reorder, both against the same NIC.
fn assert_machine_setup_precedes_reorder_for(
    actions: &[RedfishSimAction],
    expected_mac: MacAddress,
) {
    // `MachineSetup` records the target as `Option<String>` (setup can run
    // without one), while `SetBootOrderDpuFirst` always has a `String`.
    let expected = expected_mac.to_string();

    let machine_setup_idx = actions
        .iter()
        .position(|action| {
            matches!(
                action,
                RedfishSimAction::MachineSetup { boot_interface_mac, .. }
                    if boot_interface_mac.as_deref() == Some(expected.as_str())
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "expected a machine_setup targeting the boot NIC {expected_mac}, got: {actions:?}"
            )
        });

    let reorder_idx = actions
        .iter()
        .position(|action| {
            matches!(
                action,
                RedfishSimAction::SetBootOrderDpuFirst { boot_interface_mac }
                    if *boot_interface_mac == expected
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "expected a set_boot_order_dpu_first targeting the boot NIC {expected_mac}, got: {actions:?}"
            )
        });

    assert!(
        machine_setup_idx < reorder_idx,
        "machine_setup (idx {machine_setup_idx}) must re-assert HttpDev1 before the reorder \
         (idx {reorder_idx}); actions: {actions:?}"
    );
}

/// Regression test for the NIC-mode `HttpDev1` de-enumeration hang.
///
/// On a zero-DPU host, a reboot during the boot-order phase can de-enumerate the
/// BlueField from Redfish, reverting the `HttpDev1` UEFI HTTP-boot device to the
/// onboard default. `set_boot_order_dpu_first` only reorders the boot options it
/// finds, so it cannot bring `HttpDev1` back -- the boot order never verifies and
/// the host wedges in SetBootOrder/CheckBootOrder. SetBootOrder now re-asserts
/// `machine_setup` on each attempt, re-enabling the device so the reorder sticks.
///
/// The sim models this: `set_http_dev1_reverted` disables the device, so the
/// first `set_boot_order_dpu_first` records the boot order as *not* configured;
/// only the re-assert's `machine_setup` re-enables it. Without the re-assert the
/// host never leaves CheckBootOrder; with it, the host recovers to Measuring.
#[crate::sqlx_test]
async fn test_set_boot_order_reasserts_machine_setup_when_http_dev1_de_enumerates(
    pool: sqlx::PgPool,
) {
    let env = create_zero_dpu_test_env(pool).await;

    let mh = create_managed_host_with_config(&env, ManagedHostConfig::zero_dpu()).await;
    assert!(
        mh.dpu_ids.is_empty(),
        "zero-DPU fixture should produce no DPU machines"
    );
    let host_id = mh.host().id;
    let boot_nic_mac = host_inband_nic_mac(&env, host_id).await;

    // Model the BlueField de-enumerating: HttpDev1 reverts to the onboard
    // default, so the first reorder won't make the boot order verify.
    env.redfish_sim.set_http_dev1_reverted();

    set_host_stuck_in_set_boot_order(&env, host_id).await;

    let redfish_timepoint = env.redfish_sim.timepoint();

    let recovered = drive_until_past_set_boot_order(&env, &mh, 15).await;
    if !recovered {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        panic!(
            "expected SetBootOrder to re-assert machine_setup and recover a de-enumerated \
             HttpDev1 (reaching HostInit/Measuring), but the host wedged at: {:?}",
            host.current_state()
        );
    }

    // The recovery hinges on machine_setup running -- targeting the boot NIC --
    // before the reorder during the boot-order phase.
    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    assert_machine_setup_precedes_reorder_for(&actions, boot_nic_mac);
}

/// Healthy-path counterpart: when `HttpDev1` was never de-enumerated, the
/// SetBootOrder `machine_setup` re-assert is idempotent -- the host still
/// advances out of SetBootOrder exactly as before, and machine_setup is invoked
/// without changing the outcome. Guards against the re-assert regressing the
/// normal zero-DPU boot-order path.
#[crate::sqlx_test]
async fn test_set_boot_order_reassert_is_idempotent_on_healthy_zero_dpu_host(pool: sqlx::PgPool) {
    let env = create_zero_dpu_test_env(pool).await;

    let mh = create_managed_host_with_config(&env, ManagedHostConfig::zero_dpu()).await;
    let host_id = mh.host().id;
    let boot_nic_mac = host_inband_nic_mac(&env, host_id).await;

    // No de-enumeration this time: HttpDev1 stays enabled throughout.
    set_host_stuck_in_set_boot_order(&env, host_id).await;

    let redfish_timepoint = env.redfish_sim.timepoint();

    let recovered = drive_until_past_set_boot_order(&env, &mh, 15).await;
    assert!(
        recovered,
        "a healthy zero-DPU host should still advance past SetBootOrder with the re-assert in place"
    );

    // The re-assert still runs (targeting the boot NIC) before the reorder; on
    // the healthy path it just doesn't change the outcome.
    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    assert_machine_setup_precedes_reorder_for(&actions, boot_nic_mac);
}

/// When HostInit/PollingBiosSetup retry budget is exhausted, enter Failed and recover via is_bios_setup.
#[crate::sqlx_test]
async fn test_polling_bios_setup_exhausted_enters_failed_and_recovers_when_bios_setup_true(
    pool: sqlx::PgPool,
) {
    let env = create_test_env(pool).await;

    let mh = common::api_fixtures::create_managed_host(&env).await;
    let host_id = mh.host().id;

    env.redfish_sim.set_is_bios_setup(false);

    set_host_controller_state_stuck_in(
        &env,
        host_id,
        &ManagedHostState::HostInit {
            machine_state: MachineState::PollingBiosSetup { retry_count: 3 },
        },
        16,
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        assert!(
            matches!(
                host.current_state(),
                ManagedHostState::Failed {
                    details: FailureDetails {
                        cause: FailureCause::BiosSetupFailed { .. },
                        source: FailureSource::StateMachineArea(StateMachineArea::HostInit),
                        ..
                    },
                    ..
                }
            ),
            "expected ManagedHostState::Failed with BiosSetupFailed/HostInit, got: {:?}",
            host.current_state()
        );
    }

    env.redfish_sim.set_is_bios_setup(true);
    env.run_machine_state_controller_iteration().await;

    {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        assert!(
            matches!(
                host.current_state(),
                ManagedHostState::HostInit {
                    machine_state: MachineState::SetBootOrder { .. },
                }
            ),
            "expected recovery to reach HostInit/SetBootOrder, got: {:?}",
            host.current_state()
        );
    }
}

/// Assigned/HostPlatformConfiguration/PollingBiosSetup retry exhaustion enters InstanceState::Failed.
#[crate::sqlx_test]
async fn test_hpc_polling_bios_setup_exhausted_enters_failed_and_recovers_when_bios_setup_true(
    pool: sqlx::PgPool,
) {
    let env = create_test_env(pool).await;

    let mh = common::api_fixtures::create_managed_host(&env).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    create_instance(&env, &mh, false, segment_id).await;
    let host_id = mh.host().id;

    env.redfish_sim.set_is_bios_setup(false);

    set_host_controller_state_stuck_in(
        &env,
        host_id,
        &ManagedHostState::Assigned {
            instance_state: InstanceState::HostPlatformConfiguration {
                platform_config_state: HostPlatformConfigurationState::PollingBiosSetup {
                    retry_count: 3,
                },
            },
        },
        16,
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        assert!(
            matches!(
                host.current_state(),
                ManagedHostState::Assigned {
                    instance_state: InstanceState::Failed {
                        details: FailureDetails {
                            cause: FailureCause::BiosSetupFailed { .. },
                            source: FailureSource::StateMachineArea(
                                StateMachineArea::AssignedInstance
                            ),
                            ..
                        },
                        ..
                    },
                }
            ),
            "expected Assigned/InstanceState::Failed with BiosSetupFailed/AssignedInstance, got: {:?}",
            host.current_state()
        );
    }

    env.redfish_sim.set_is_bios_setup(true);
    env.run_machine_state_controller_iteration().await;

    {
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        assert!(
            matches!(
                host.current_state(),
                ManagedHostState::Assigned {
                    instance_state: InstanceState::HostPlatformConfiguration {
                        platform_config_state: HostPlatformConfigurationState::SetBootOrder { .. },
                    },
                }
            ),
            "expected recovery to reach HostPlatformConfiguration/SetBootOrder, got: {:?}",
            host.current_state()
        );
    }
}

async fn set_host_controller_state_stuck_in(
    env: &TestEnv,
    host_id: MachineId,
    state: &ManagedHostState,
    minutes_in_state: i64,
) {
    let state_json = serde_json::to_value(state).unwrap();
    let ts = chrono::Utc::now() - chrono::Duration::minutes(minutes_in_state);
    let version = format!("V1-T{}", ts.timestamp_micros());

    let mut txn = env.db_txn().await;
    sqlx::query(
        "UPDATE machines SET \
            controller_state = $1, \
            controller_state_version = $2, \
            controller_state_outcome = NULL \
         WHERE id = $3",
    )
    .bind(sqlx::types::Json(&state_json))
    .bind(&version)
    .bind(host_id)
    .execute(&mut *txn)
    .await
    .unwrap();
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_scout_heartbeat_timeout_alert_cleared_on_ready_transition(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.host().id;

    let mut txn = env.db_txn().await;
    sqlx::query(
        "UPDATE machines SET last_scout_contact_time = NOW() - INTERVAL '2 years' WHERE id = $1",
    )
    .bind(host_machine_id)
    .execute(&mut *txn)
    .await
    .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    on_demand_machine_validation(&env, host_machine_id, vec![], vec![], false, vec![]).await;

    let mut reached_validation = false;
    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        if matches!(
            host.current_state(),
            ManagedHostState::Validation {
                validation_state: ValidationState::MachineValidation { .. }
            }
        ) {
            reached_validation = true;
            break;
        }
    }
    assert!(
        reached_validation,
        "host never transitioned from Ready to Validation"
    );

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(
        !host.health_reports.merges.contains_key("scout"),
        "expected scout_heartbeat_timeout alert to be cleared when leaving Ready"
    );
}

#[crate::sqlx_test]
async fn test_scout_heartbeat_timeout_alert_cleared_on_instance_creation_transition(
    pool: sqlx::PgPool,
) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.host().id;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let mut txn = env.db_txn().await;
    sqlx::query(
        "UPDATE machines SET last_scout_contact_time = NOW() - INTERVAL '2 years' WHERE id = $1",
    )
    .bind(host_machine_id)
    .execute(&mut *txn)
    .await
    .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    env.api
        .allocate_instance(Request::new(rpc::forge::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(host_machine_id),
            instance_type_id: None,
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                network_security_group_id: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/machine_states".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: true,
        }))
        .await
        .unwrap();

    let mut reached_assigned = false;
    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
        let mut txn = env.db_txn().await;
        let host = mh.host().db_machine(&mut txn).await;
        if matches!(
            host.current_state(),
            ManagedHostState::Assigned {
                instance_state: InstanceState::DpaProvisioning
            } | ManagedHostState::Assigned {
                instance_state: InstanceState::WaitingForDpaToBeReady
            }
        ) {
            reached_assigned = true;
            break;
        }
    }

    assert!(
        reached_assigned,
        "host never transitioned from Ready to Assigned after instance allocation"
    );

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(
        !host.health_reports.merges.contains_key("scout"),
        "expected scout_heartbeat_timeout alert to be cleared when leaving Ready via instance creation"
    );
}

#[crate::sqlx_test]
async fn test_scout_heartbeat_timeout_alert_not_cleared_when_unhealthy_allocation_blocked(
    pool: sqlx::PgPool,
) {
    let mut config = get_config();
    config
        .host_health
        .prevent_allocations_on_scout_heartbeat_timeout = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;
    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.host().id;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let mut txn = env.db_txn().await;
    sqlx::query(
        "UPDATE machines SET last_scout_contact_time = NOW() - INTERVAL '2 years' WHERE id = $1",
    )
    .bind(host_machine_id)
    .execute(&mut *txn)
    .await
    .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let err = env
        .api
        .allocate_instance(Request::new(rpc::forge::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(host_machine_id),
            instance_type_id: None,
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                network_security_group_id: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/machine_states".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    assert!(
        host.health_reports.merges.contains_key("scout"),
        "expected scout_heartbeat_timeout alert to remain when unhealthy allocation is blocked"
    );
}

#[crate::sqlx_test]
async fn test_tpm_logging(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    let machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    host_discover_machine(&env, &host_config, machine_interface_id).await;

    let mut discovery_info =
        DiscoveryInfo::try_from(model::hardware_info::HardwareInfo::from(&host_config)).unwrap();
    discovery_info.tpm_ek_certificate =
        Some(BASE64_STANDARD.encode(common::api_fixtures::tpm_attestation::EK_CERT_SERIALIZED));
    discovery_info.attest_key_info = Some(AttestKeyInfo {
        ek_pub: common::api_fixtures::tpm_attestation::EK_PUB_SERIALIZED.to_vec(),
        ak_pub: common::api_fixtures::tpm_attestation::AK_PUB_SERIALIZED.to_vec(),
        ak_name: common::api_fixtures::tpm_attestation::AK_NAME_SERIALIZED.to_vec(),
    });
    let result = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            create_machine: false,
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("Expected FK violation from mismatched TPM");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("machine_id foreign key violation"),
        "Expected TPM mismatch error, got: {}",
        err.message()
    );
}

#[crate::sqlx_test]
async fn test_host_discovery_without_tpm_cert_does_not_downgrade_existing_tpm_identity(
    pool: sqlx::PgPool,
) {
    let mut config = get_config();
    config.tpm_required = false;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    let machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    host_discover_machine(&env, &host_config, machine_interface_id).await;

    let mut discovery_info =
        DiscoveryInfo::try_from(model::hardware_info::HardwareInfo::from(&host_config)).unwrap();
    discovery_info.tpm_ek_certificate = None;

    let result = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            create_machine: false,
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("Expected serial fallback to be rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("TPM EK certificate missing"),
        "Expected missing TPM EK certificate error, got: {}",
        err.message()
    );
}

/// Spins up a test env configured for zero-DPU hosts plus a zero-DPU
/// managed host, and inserts a bare `instances` row attached to it,
/// which is the minimal state needed to exercise the state controller
/// for an assigned host (which would otherwise bail early if
/// `mh_snapshot.instance` is `None`).
async fn zero_dpu_host_with_instance(pool: sqlx::PgPool) -> (TestEnv, TestManagedHost) {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
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
            ]),
            ..Default::default()
        },
    )
    .await;
    create_host_inband_network_segment(&env.api, None).await;

    let mh = create_managed_host_with_config(&env, ManagedHostConfig::zero_dpu()).await;
    assert!(
        mh.dpu_ids.is_empty(),
        "zero-DPU fixture should produce no DPU machines"
    );

    // Provide valid empty configs explicitly so the state controller can
    // load the snapshot.
    //
    // TODO(chet): It looks like a handful of `instances` column "defaults"
    // are stale JSON shapes that don't match the current Rust structs (e.g.
    // `network_config` defaults to '{}' but `InstanceNetworkConfig` requires
    // an `interfaces` field; and `nvlink_config` defaults to '{"nvlink_gpus": []}'
    // but the struct expects `gpu_configs`). I want to say lol here, so lol.
    let mut txn = env.pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO instances (machine_id, network_config, nvlink_config) \
         VALUES ($1, '{\"interfaces\": []}'::jsonb, '{\"gpu_configs\": []}'::jsonb)",
    )
    .bind(mh.host().id)
    .execute(txn.as_mut())
    .await
    .unwrap();
    txn.commit().await.unwrap();

    (env, mh)
}

/// Set the host directly into an `Assigned { instance_state }` state
/// and commit so the next state controller iteration picks it up.
async fn set_assigned_state(env: &TestEnv, host_id: &MachineId, instance_state: InstanceState) {
    let mut txn = env.db_txn().await;
    db::machine::update_state(
        txn.as_mut(),
        host_id,
        &ManagedHostState::Assigned { instance_state },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();
}

async fn load_host_state(env: &TestEnv, host_id: &MachineId) -> ManagedHostState {
    db::machine::find_one(
        &env.pool,
        host_id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .expect("host should exist")
    .current_state()
    .clone()
}

#[crate::sqlx_test]
async fn test_waiting_for_extension_services_config_skips_for_zero_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env, mh) = zero_dpu_host_with_instance(pool).await;
    set_assigned_state(
        &env,
        &mh.host().id,
        InstanceState::WaitingForExtensionServicesConfig,
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    assert!(matches!(
        load_host_state(&env, &mh.host().id).await,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForRebootToReady,
        }
    ));
    Ok(())
}

#[crate::sqlx_test]
async fn test_waiting_for_dpus_to_up_skips_wait_for_zero_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env, mh) = zero_dpu_host_with_instance(pool).await;
    set_assigned_state(&env, &mh.host().id, InstanceState::WaitingForDpusToUp).await;

    env.run_machine_state_controller_iteration().await;

    // Without the zero-DPU guard the handler would have returned a
    // "Waiting for DPUs to come up" wait and the state would be
    // unchanged. With the guard, we proceed past the wait into the
    // termination/reboot path.
    let state = load_host_state(&env, &mh.host().id).await;
    assert!(
        !matches!(
            state,
            ManagedHostState::Assigned {
                instance_state: InstanceState::WaitingForDpusToUp,
            }
        ),
        "expected to advance past WaitingForDpusToUp, got: {state:?}"
    );
    Ok(())
}

#[crate::sqlx_test]
async fn test_dpu_reprovision_errors_for_zero_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env, mh) = zero_dpu_host_with_instance(pool).await;
    set_assigned_state(
        &env,
        &mh.host().id,
        InstanceState::DPUReprovision {
            dpu_states: DpuReprovisionStates {
                states: HashMap::new(),
            },
        },
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    // The guard returns an error, which the state controller surfaces
    // as a handler failure rather than silently advancing. The host
    // should not have transitioned out of DPUReprovision.
    assert!(matches!(
        load_host_state(&env, &mh.host().id).await,
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { .. },
        }
    ));
    Ok(())
}

/// Host-level `ManagedHostState::DPUReprovision` (different from the
/// instance-scoped `InstanceState::DPUReprovision` covered above) is only
/// entered from `Ready` when `dpu_reprovisioning_needed()` returns true;
/// this requires non-empty DPUs. Reaching it with a zero-DPU host is a
/// bug: without the explicit guard the empty loop would fall through
/// to `do_nothing()` and the host would sit in the state forever.
/// Verify the guard surfaces a loud error instead.
#[crate::sqlx_test]
async fn test_host_level_dpu_reprovision_errors_for_zero_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env, mh) = zero_dpu_host_with_instance(pool).await;

    let mut txn = env.db_txn().await;
    db::machine::update_state(
        txn.as_mut(),
        &mh.host().id,
        &ManagedHostState::DPUReprovision {
            dpu_states: DpuReprovisionStates {
                states: HashMap::new(),
            },
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    // The guard returns an error, which the state controller surfaces as
    // a handler failure rather than silently advancing. The host stays in
    // DPUReprovision.
    assert!(matches!(
        load_host_state(&env, &mh.host().id).await,
        ManagedHostState::DPUReprovision { .. }
    ));
    Ok(())
}
