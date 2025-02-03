/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::tests::common;
use crate::tests::common::api_fixtures::{create_test_env, TestEnvOverrides};
use crate::{
    cfg::file::FirmwareComponentType,
    db::{
        explored_endpoints::DbExploredEndpoint,
        host_machine_update::HostMachineUpdate,
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
        DatabaseError,
    },
    machine_update_manager::MachineUpdateManager,
    model::{
        machine::{HostReprovisionState, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport,
            EndpointType, Inventory, PowerState, PreingestionState, Service,
        },
    },
    preingestion_manager::PreingestionManager,
    CarbideResult,
};
use common::api_fixtures::{self, create_test_env_with_overrides, get_config, TestEnv};
use forge_uuid::machine::MachineId;
use rpc::forge::forge_server::Forge;
use rpc::forge::DhcpDiscovery;
use sqlx::{Postgres, Transaction};
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    thread::sleep,
    time::Duration,
};
use tempdir::TempDir;

#[crate::sqlx_test]
async fn test_preingestion_bmc_upgrade(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mgr = PreingestionManager::new(
        pool.clone(),
        env.config.clone(),
        env.redfish_sim.clone(),
        env.test_meter.meter(),
        None,
        None,
    );

    let mut txn = pool.begin().await.unwrap();

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: "b8:3f:d2:90:97:a6".to_string(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: Some("iDRac".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await?
        .into_inner();

    // First, a host where it's already up to date; it should immediately go to complete.
    let addr = response.address.as_str();
    insert_endpoint_version(&mut txn, addr, "6.00.30.00", "1.13.2").await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    let mut txn = pool.begin().await.unwrap();
    assert!(
        DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn)
            .await?
            .is_empty()
    );
    assert!(
        DbExploredEndpoint::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );

    // Next, one that isn't up to date but it above preingestion limits.
    DbExploredEndpoint::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    insert_endpoint_version(&mut txn, addr, "5.1", "1.13.2").await?;
    txn.commit().await?;
    let mut txn = pool.begin().await.unwrap();

    mgr.run_single_iteration().await?;

    assert!(
        DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn)
            .await?
            .is_empty()
    );
    assert!(
        DbExploredEndpoint::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );

    // And now, one that's low enough to trigger preingestion upgrades.
    DbExploredEndpoint::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    insert_endpoint_version(&mut txn, addr, "4.9", "1.13.2").await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    // The "upload" is synchronous now and will be complete at this point.

    // At this point, we expect that it shows as having completed upload
    let mut txn = pool.begin().await.unwrap();

    let endpoints = DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn).await?;
    assert!(endpoints.len() == 1);
    let mut endpoint = endpoints.first().unwrap().clone();
    match &endpoint.preingestion_state {
        // We expect it to be waiting for task completion
        PreingestionState::UpgradeFirmwareWait {
            task_id,
            final_version,
            upgrade_type,
            ..
        } => {
            println!("Waiting on {task_id} {upgrade_type:?} {final_version}");
        }
        _ => {
            panic!("Bad preingestion state: {endpoint:?}");
        }
    }

    // Now we simulate site explorer coming through and reading the new updated version
    endpoint.report.service[0].inventories[0].version = Some("6.00.30.00".to_string());
    assert!(
        DbExploredEndpoint::try_update(
            endpoint.address,
            endpoint.report_version,
            &endpoint.report,
            &mut txn
        )
        .await?
    );

    txn.commit().await?;

    // The next run of the state machine should see that the task shows as complete and move us back to checking again
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints = DbExploredEndpoint::find_all(&mut txn).await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
    match &endpoint.preingestion_state {
        PreingestionState::RecheckVersions => {
            println!("Rechecking versions");
        }
        _ => {
            panic!("Bad preingestion state: {endpoint:?}");
        }
    }
    txn.commit().await?;

    // Now it should go to completion
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    assert!(
        DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn)
            .await?
            .is_empty()
    );
    assert!(
        DbExploredEndpoint::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );
    txn.commit().await?;

    // Check DPU update during pre-ingestion
    let mut txn = pool.begin().await.unwrap();
    let dpu_ip = IpAddr::from_str(addr).unwrap();
    let cec_version = "4-12";
    DbExploredEndpoint::delete(&mut txn, dpu_ip).await?;
    insert_dpu_endpoint(
        &mut txn,
        addr,
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
        "23.07",
        cec_version,
    )
    .await?;
    txn.commit().await?;
    let mut txn = pool.begin().await.unwrap();

    let dpu_ep = DbExploredEndpoint::find_all_by_ip(dpu_ip, &mut txn).await?;
    txn.commit().await?;
    assert_eq!(dpu_ep.len(), 1);
    assert_eq!(
        dpu_ep[0]
            .find_version(
                &env.config.dpu_config.dpu_models["bluefield3"],
                FirmwareComponentType::Cec
            )
            .unwrap(),
        cec_version
    );

    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    assert_eq!(
        DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn)
            .await?
            .len(),
        1
    );
    assert_eq!(
        DbExploredEndpoint::find_all_preingestion_complete(&mut txn)
            .await?
            .len(),
        0
    );
    txn.commit().await?;

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_preingestion_waiting_download")
            .unwrap(),
        "0"
    );
    Ok(())
}

async fn insert_endpoint_version(
    txn: &mut Transaction<'_, Postgres>,
    addr: &str,
    bmc_version: &str,
    uefi_version: &str,
) -> Result<(), DatabaseError> {
    insert_endpoint(
        txn,
        addr,
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
        "Dell Inc.",
        "PowerEdge R750",
        bmc_version,
        uefi_version,
    )
    .await
}

async fn insert_endpoint(
    txn: &mut Transaction<'_, Postgres>,
    addr: &str,
    machine_id_str: &str,
    vendor: &str,
    model: &str,
    bmc_version: &str,
    uefi_version: &str,
) -> Result<(), DatabaseError> {
    DbExploredEndpoint::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &build_exploration_report(vendor, model, bmc_version, uefi_version, machine_id_str),
        txn,
    )
    .await
}

fn build_exploration_report(
    vendor: &str,
    model: &str,
    bmc_version: &str,
    uefi_version: &str,
    machine_id_str: &str,
) -> EndpointExplorationReport {
    let machine_id = if machine_id_str.is_empty() {
        None
    } else {
        Some(MachineId::from_str(machine_id_str).unwrap())
    };

    let mut report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        vendor: Some(bmc_vendor::BMCVendor::Dell),
        last_exploration_error: None,
        last_exploration_latency: None,
        managers: vec![],
        systems: vec![ComputerSystem {
            model: Some(model.to_string()),
            ethernet_interfaces: vec![],
            id: "".to_string(),
            manufacturer: Some(vendor.to_string()),
            serial_number: None,
            attributes: ComputerSystemAttributes {
                nic_mode: None,
                http_dev1_interface: None,
                is_infinite_boot_enabled: Some(true),
            },
            pcie_devices: vec![],
            base_mac: None,
            power_state: PowerState::On,
            sku: None,
        }],
        chassis: vec![Chassis {
            model: Some(model.to_string()),
            id: "".to_string(),
            manufacturer: Some(vendor.to_string()),
            part_number: None,
            serial_number: None,
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "".to_string(),
            inventories: vec![
                Inventory {
                    id: "Installed-???__iDRAC.???".to_string(),
                    description: None,
                    version: Some(bmc_version.to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "Current-159-1.13.2__BIOS.Setup.1-1".to_string(),
                    description: None,
                    version: Some(uefi_version.to_string()),
                    release_date: None,
                },
            ],
        }],
        machine_id,
        versions: HashMap::default(),
        model: None,
    };
    report.model = report.model();
    report
}

async fn insert_dpu_endpoint(
    txn: &mut Transaction<'_, Postgres>,
    addr: &str,
    machine_id_str: &str,
    bmc_version: &str,
    cec_version: &str,
) -> Result<(), DatabaseError> {
    DbExploredEndpoint::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &build_dpu_exploration_report(machine_id_str, bmc_version, cec_version),
        txn,
    )
    .await
}

fn build_dpu_exploration_report(
    machine_id_str: &str,
    bmc_version: &str,
    cec_version: &str,
) -> EndpointExplorationReport {
    let machine_id = if machine_id_str.is_empty() {
        None
    } else {
        Some(MachineId::from_str(machine_id_str).unwrap())
    };

    EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        last_exploration_error: None,
        last_exploration_latency: None,
        managers: vec![],
        systems: vec![],
        chassis: vec![Chassis {
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            part_number: None,
            serial_number: None,
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "Nvidia".to_string(),
            inventories: vec![
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: None,
                    version: Some(bmc_version.to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "Bluefield_FW_ERoT".to_string(),
                    description: None,
                    version: Some(cec_version.to_string()),
                    release_date: None,
                },
            ],
        }],
        machine_id,
        versions: HashMap::default(),
        model: None,
    }
}

#[crate::sqlx_test]
async fn test_postingestion_bmc_upgrade(pool: sqlx::PgPool) -> CarbideResult<()> {
    // Create an environment with one managed host in the ready state.
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;

    // Create and start an update manager
    let update_manager =
        MachineUpdateManager::new(env.pool.clone(), env.config.clone(), env.test_meter.meter());
    // Update manager should notice that the host is underversioned, setting the request to update it
    update_manager.run_single_iteration().await?;

    // Check that we're properly marking it as upgrade needed
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(host.host_reprovisioning_requested().is_some());
    txn.commit().await.unwrap();

    // Now we want a tick of the state machine
    env.run_machine_state_controller_iteration().await;

    // It should have "started" a UEFI upgrade
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let _ = host.host_reprovisioning_requested().unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::WaitingForFirmwareUpgrade { firmware_type, .. } = reprovision_state
    else {
        panic!("Not in WaitingForFirmwareUpgrade");
    };
    assert_eq!(firmware_type, FirmwareComponentType::Uefi);
    txn.commit().await.unwrap();

    // The faked Redfish task will immediately show as completed, but we won't proceed further because "site explorer" (ie us) has not re-reported the info.
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::ResetForNewFirmware { .. } = reprovision_state else {
        panic!("Not in reset {reprovision_state:?}");
    };
    txn.commit().await.unwrap();

    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::NewFirmwareReportedWait { .. } = reprovision_state else {
        panic!("Not in waiting {reprovision_state:?}");
    };

    // "Site explorer" pass
    let endpoints =
        DbExploredEndpoint::find_by_ips(&mut txn, vec![host.bmc_info().ip_addr().unwrap()]).await?;
    let mut endpoint = endpoints.first().unwrap().clone();
    endpoint.report.service[0].inventories[1].version = Some("1.13.2".to_string());
    endpoint
        .report
        .versions
        .insert(FirmwareComponentType::Uefi, "1.13.2".to_string());
    DbExploredEndpoint::try_update(
        host.bmc_info().ip_addr().unwrap(),
        endpoint.report_version,
        &endpoint.report,
        &mut txn,
    )
    .await?;
    txn.commit().await.unwrap();

    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::CheckingFirmware { .. } = reprovision_state else {
        panic!("Not in reset {reprovision_state:?}");
    };
    txn.commit().await.unwrap();

    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    // It should have "started" a BMC upgrade now
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let _ = host.host_reprovisioning_requested().unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::WaitingForFirmwareUpgrade { firmware_type, .. } = reprovision_state
    else {
        panic!("Not in WaitingForFirmwareUpgrade");
    };
    assert_eq!(firmware_type, FirmwareComponentType::Bmc);
    txn.commit().await.unwrap();

    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::ResetForNewFirmware { .. } = reprovision_state else {
        panic!("Not in reset {reprovision_state:?}");
    };

    // "Site explorer" pass to indicate that we're at the desired version
    let endpoints =
        DbExploredEndpoint::find_by_ips(&mut txn, vec![host.bmc_info().ip_addr().unwrap()]).await?;
    let mut endpoint = endpoints.first().unwrap().clone();
    endpoint.report.service[0].inventories[0].version = Some("6.00.30.00".to_string());
    endpoint
        .report
        .versions
        .insert(FirmwareComponentType::Bmc, "6.00.30.00".to_string());
    DbExploredEndpoint::try_update(
        host.bmc_info().ip_addr().unwrap(),
        endpoint.report_version,
        &endpoint.report,
        &mut txn,
    )
    .await?;
    MachineTopology::update_firmware_version_by_bmc_address(
        &mut txn,
        &host.bmc_info().ip_addr().unwrap(),
        "6.00.30.00",
        "1.2.3",
    )
    .await?;
    txn.commit().await.unwrap();
    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::NewFirmwareReportedWait { .. } = reprovision_state else {
        panic!("Not in waiting {reprovision_state:?}");
    };

    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    // It should be checking
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostReprovision { reprovision_state } = host.current_state() else {
        panic!("Not in HostReprovision");
    };
    if reprovision_state != HostReprovisionState::CheckingFirmware {
        panic!("Not in checking");
    }
    txn.commit().await.unwrap();

    // Another state machine pass
    env.run_machine_state_controller_iteration().await;

    // Now we should be back waiting for lockdown to resolve
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ManagedHostState::HostInit { .. } = host.current_state() else {
        panic!("Not in HostINit");
    };
    txn.commit().await.unwrap();

    // Step until we reach ready
    env.run_machine_state_controller_iteration().await;

    // Now let update manager run again, it should not put us back to reprovisioning.
    update_manager.run_single_iteration().await?;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(host.host_reprovisioning_requested().is_none()); // Should be cleared or we'd right back in
    let reqs = HostMachineUpdate::find_upgrade_needed(&mut txn, true).await?;
    assert!(reqs.is_empty());
    txn.commit().await.unwrap();

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_pending_host_firmware_update_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_active_host_firmware_update_count")
            .unwrap(),
        "0"
    );

    // Validate update_firmware_version_by_bmc_address behavior
    assert_eq!(
        host.bmc_info().firmware_version,
        Some("6.00.30.00".to_string())
    );
    assert_eq!(
        host.hardware_info()
            .unwrap()
            .dmi_data
            .clone()
            .unwrap()
            .bios_version,
        "1.2.3".to_string()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_host_fw_upgrade_enabledisable_global_enabled(
    pool: sqlx::PgPool,
) -> CarbideResult<()> {
    let (env, host_machine_id) = test_host_fw_upgrade_enabledisable_generic(pool, true).await?;

    // Check that if it's globally enabled but specifically disabled, we don't request updates.
    let mut txn = env.pool.begin().await.unwrap();
    Machine::set_firmware_autoupdate(&mut txn, &host_machine_id, Some(false)).await?;
    txn.commit().await.unwrap();

    // Create and start an update manager
    let update_manager =
        MachineUpdateManager::new(env.pool.clone(), env.config.clone(), env.test_meter.meter());
    update_manager.run_single_iteration().await?;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(host.host_reprovisioning_requested().is_none());

    // Now switch it to unspecified and it should get a request
    Machine::set_firmware_autoupdate(&mut txn, &host_machine_id, None).await?;
    txn.commit().await.unwrap();

    update_manager.run_single_iteration().await?;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(host.host_reprovisioning_requested().is_some());
    txn.commit().await.unwrap();

    Ok(())
}

#[crate::sqlx_test]
async fn test_host_fw_upgrade_enabledisable_global_disabled(
    pool: sqlx::PgPool,
) -> CarbideResult<()> {
    let (env, host_machine_id) = test_host_fw_upgrade_enabledisable_generic(pool, false).await?;
    // Create and start an update manager
    let update_manager =
        MachineUpdateManager::new(env.pool.clone(), env.config.clone(), env.test_meter.meter());
    update_manager.run_single_iteration().await?;

    // Globally disabled, so it should not have requested an update
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(host.host_reprovisioning_requested().is_none());

    // Now specifically enable it, and an update should be requested.
    Machine::set_firmware_autoupdate(&mut txn, &host_machine_id, Some(true)).await?;
    txn.commit().await.unwrap();

    update_manager.run_single_iteration().await?;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(host.host_reprovisioning_requested().is_some());
    txn.commit().await.unwrap();

    Ok(())
}

async fn test_host_fw_upgrade_enabledisable_generic(
    pool: sqlx::PgPool,
    global_enabled: bool,
) -> CarbideResult<(TestEnv, MachineId)> {
    // Create an environment with one managed host in the ready state.  Tweak the default config to enable or disable firmware global autoupdate.
    let mut config = get_config();
    config.firmware_global.autoupdate = global_enabled;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    let (host_machine_id, _dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;

    Ok((env, host_machine_id))
}

#[test]
fn test_merge_firmware_configs() -> Result<(), eyre::Report> {
    let tmpdir = TempDir::new("test_merge_firmware_configs")?;

    // B_1 comes later alphabetically but because it's written first, should be parsed first
    test_merge_firmware_configs_write(
        &tmpdir,
        "dir_B_1",
        r#"
vendor = "Dell"
model = "PowerEdge R750"
[components.uefi]
current_version_reported_as = "^Installed-.*__BIOS.Setup."
preingest_upgrade_when_below = "1.0"
known_firmware = [
    # Set version to match the version that the firmware will give, and for filename change filename.bin to the filename you specified in Dockerfile.  Leave everything else as it is.
    { version = "1.0", filename = "/opt/fw/dell-r750-bmc-1.0/filename.bin", default = true },
]
    "#,
    )?;
    // Even though the file modification time has a precision of nanoseconds, the two files can have matching times, so we have to wait a bit.
    sleep(Duration::from_millis(100));
    test_merge_firmware_configs_write(
        &tmpdir,
        "dir_A_2",
        r#"
vendor = "Dell"
model = "PowerEdge R750"
[components.uefi]
current_version_reported_as = "^Installed-.*__BIOS.Setup."
preingest_upgrade_when_below = "1.1"
known_firmware = [
    # Set version to match the version that the firmware will give, and for filename change filename.bin to the filename you specified in Dockerfile.  Leave everything else as it is.
    { version = "2.0", filename = "/opt/fw/dell-r750-bmc-2.0/filename.bin", default = true },
]
    "#,
    )?;
    // And a directory that has no metadata, just to make sure we don't panic
    let mut dir = tmpdir.path().to_path_buf();
    dir.push("bad");
    fs::create_dir_all(dir.clone())?;

    let mut cfg = api_fixtures::get_config();
    cfg.firmware_global.firmware_directory = tmpdir.path().to_path_buf();
    let cfg = cfg.get_firmware_config();
    // Clean up tmpdir before any possible failures so we don't leave it behind
    drop(tmpdir);

    let model = cfg
        .find(bmc_vendor::BMCVendor::Dell, "PowerEdge R750".to_string())
        .unwrap();

    assert_eq!(
        model
            .components
            .get(&FirmwareComponentType::Bmc)
            .unwrap()
            .known_firmware
            .len(),
        3
    );
    let uefi = model.components.get(&FirmwareComponentType::Uefi).unwrap();
    assert_eq!(uefi.preingest_upgrade_when_below, Some("1.1".to_string()));

    assert_eq!(uefi.known_firmware.len(), 3);
    for x in &uefi.known_firmware {
        match x.version.as_str() {
            "1.0" => {
                assert!(!x.default);
            }
            "2.0" => {
                assert!(x.default);
            }
            "1.13.2" => {
                assert!(!x.default);
            }
            _ => {
                panic!("Wrong version {x:?}");
            }
        }
    }

    Ok(())
}

fn test_merge_firmware_configs_write(
    tmpdir: &TempDir,
    name: &str,
    contents: &str,
) -> Result<(), eyre::Report> {
    let mut dir = tmpdir.path().to_path_buf();
    dir.push(name);
    fs::create_dir_all(dir.clone())?;
    let mut file = dir.clone();
    file.push("metadata.toml");
    fs::write(file, contents)?;

    Ok(())
}
