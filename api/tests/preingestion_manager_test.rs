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

pub mod common;

use carbide::{
    db::{explored_endpoints::DbExploredEndpoint, DatabaseError},
    model::{
        machine::machine_id::MachineId,
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport,
            EndpointType, Inventory, PreingestionState, Service,
        },
    },
    preingestion_manager::PreingestionManager,
};
use common::api_fixtures::network_segment::create_admin_network_segment;
use rpc::forge::forge_server::Forge;
use rpc::forge::DhcpDiscovery;
use sqlx::{Postgres, Transaction};
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_preingestion_bmc_upgrade(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let mgr = PreingestionManager::new(
        pool.clone(),
        env.config.clone(),
        env.redfish_sim.clone(),
        env.test_meter.meter(),
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
    insert_endpoint_version(&mut txn, addr, "1.0").await?;
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
    insert_endpoint_version(&mut txn, addr, "0.5").await?;
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
    // Next, one that isn't up to date but it above preingestion limits.
    DbExploredEndpoint::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    insert_endpoint_version(&mut txn, addr, "0.4").await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    // The "upload" is synchronous now and will be complete at this point.
    // Allow the upgrade task to run, it's set to take a few seconds
    //sleep(Duration::from_secs(6)).await;

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
    endpoint.report.service[0].inventories[0].version = Some("1.0".to_string());
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
    DbExploredEndpoint::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    insert_dpu_endpoint(
        &mut txn,
        addr,
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
        "23.07",
    )
    .await?;
    txn.commit().await?;

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
    version: &str,
) -> Result<(), DatabaseError> {
    insert_endpoint(
        txn,
        addr,
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
        "Dell",
        "R750",
        version,
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
) -> Result<(), DatabaseError> {
    DbExploredEndpoint::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &build_exploration_report(vendor, model, bmc_version, machine_id_str),
        txn,
    )
    .await
}

fn build_exploration_report(
    vendor: &str,
    model: &str,
    bmc_version: &str,
    machine_id_str: &str,
) -> EndpointExplorationReport {
    let machine_id = if machine_id_str.is_empty() {
        None
    } else {
        Some(MachineId::from_str(machine_id_str).unwrap())
    };

    EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        vendor: Some(bmc_vendor::BMCVendor::Dell),
        last_exploration_error: None,
        managers: vec![],
        systems: vec![ComputerSystem {
            model: Some(model.to_string()),
            ethernet_interfaces: vec![],
            id: "".to_string(),
            manufacturer: Some(vendor.to_string()),
            serial_number: None,
            attributes: ComputerSystemAttributes {
                nic_mode: None,
                http_dev1_interface: Some("NIC.Slot.5-1".to_string()),
            },
            pcie_devices: vec![],
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
            inventories: vec![Inventory {
                id: "idrac_blah".to_string(),
                description: None,
                version: Some(bmc_version.to_string()),
                release_date: None,
            }],
        }],
        machine_id,
    }
}

async fn insert_dpu_endpoint(
    txn: &mut Transaction<'_, Postgres>,
    addr: &str,
    machine_id_str: &str,
    bmc_version: &str,
) -> Result<(), DatabaseError> {
    DbExploredEndpoint::insert(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &build_dpu_exploration_report(machine_id_str, bmc_version),
        txn,
    )
    .await
}

fn build_dpu_exploration_report(
    machine_id_str: &str,
    bmc_version: &str,
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
            id: "".to_string(),
            inventories: vec![Inventory {
                id: "Nvidia".to_string(),
                description: None,
                version: Some(bmc_version.to_string()),
                release_date: None,
            }],
        }],
        machine_id,
    }
}
