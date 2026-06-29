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

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use carbide_firmware::test_support::script_setup;
use carbide_preingestion_manager::PreingestionManager;
use carbide_redfish::libredfish::test_support::RedfishSim;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::default_config;
use model::site_explorer::{InitialResetPhase, PowerDrainState, PreingestionState};
use rpc::forge::DhcpDiscovery;

use crate::common;

#[sqlx_test]
async fn test_preingestion_bmc_upgrade(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool.clone()).build().await;
    let domain = env.test_domain().await;
    let nc = env.network_controller();
    let underlay_segment = nc.create_underlay_segment(&domain).await;
    let config = default_config::get();

    let mgr = PreingestionManager::new(
        pool.clone(),
        config.preingestion_manager(),
        Arc::new(RedfishSim::default()),
        env.test_meter.meter(),
        None,
        None,
        None,
        env.api().work_lock_manager_handle(),
        config.ntp_servers.clone(),
    );

    let response = env
        .api()
        .discover_dhcp(
            DhcpDiscovery::builder("b8:3f:d2:90:97:a6", underlay_segment.relay_address)
                .vendor_string("iDRac")
                .tonic_request(),
        )
        .await?
        .into_inner();

    // First, a host where it's already up to date; it should go to complete
    // after passing through the explicit NTP setup state.
    let mut txn = pool.begin().await.unwrap();
    let addr = response.address.as_str();
    common::insert_endpoint_version(&mut txn, addr, "6.00.30.00", "1.13.2", false).await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;

    mgr.run_single_iteration().await?;
    let mut txn = pool.begin().await.unwrap();
    assert!(
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut())
            .await?
            .is_empty()
    );
    assert!(
        db::explored_endpoints::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );

    // Next, one that isn't up to date but it above preingestion limits.
    db::explored_endpoints::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    common::insert_endpoint_version(&mut txn, addr, "5.1", "1.13.2", false).await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    assert!(
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut())
            .await?
            .is_empty()
    );
    assert!(
        db::explored_endpoints::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );

    // And now, one that's low enough to trigger preingestion upgrades.
    db::explored_endpoints::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    common::insert_endpoint_version(&mut txn, addr, "4.9", "1.13.2", false).await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    mgr.run_single_iteration().await?;
    // The "upload" is synchronous now and will be complete at this point.

    // At this point, we expect that it shows as having completed upload
    let mut txn = pool.begin().await.unwrap();

    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
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
    txn.commit().await?;

    // Second firmware upload
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints = db::explored_endpoints::find_all(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
    if let PreingestionState::UpgradeFirmwareWait {
        firmware_number, ..
    } = endpoint.preingestion_state
    {
        assert_eq!(firmware_number, Some(1));
    } else {
        panic!("Bad preingestion state: {endpoint:?}");
    };
    txn.commit().await?;

    // Let it go to NewFirmwareReportedWait
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints = db::explored_endpoints::find_all(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
    let PreingestionState::NewFirmwareReportedWait { .. } = endpoint.preingestion_state else {
        panic!("Bad preingestion state: {endpoint:?}");
    };
    txn.commit().await?;

    // One more, to make sure noething is weird with retrying resets
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints = db::explored_endpoints::find_all(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let mut endpoint = endpoints.into_iter().next().unwrap();

    // Now we simulate site explorer coming through and reading the new updated version
    endpoint.report.service[0].inventories[0].version = Some("6.00.30.00".to_string());
    assert!(
        db::explored_endpoints::try_update(
            endpoint.address,
            endpoint.report_version,
            &endpoint.report,
            false,
            &mut txn
        )
        .await?
    );

    txn.commit().await?;

    // The next run of the state machine should see that the task shows as complete and move us back to checking again
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints = db::explored_endpoints::find_all(txn.as_mut()).await?;
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
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut())
            .await?
            .is_empty()
    );
    assert!(
        db::explored_endpoints::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );
    txn.commit().await?;

    Ok(())
}

#[sqlx_test]
async fn test_preingestion_preupdate_powercycling(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool.clone()).build().await;
    let domain = env.test_domain().await;
    let nc = env.network_controller();
    let underlay_segment = nc.create_underlay_segment(&domain).await;

    let config = default_config::get();
    tracing::debug!("{:?}", config.host_models);

    let mgr = PreingestionManager::new(
        pool.clone(),
        config.preingestion_manager(),
        Arc::new(RedfishSim::default()),
        env.test_meter.meter(),
        None,
        None,
        None,
        env.api().work_lock_manager_handle(),
        config.ntp_servers.clone(),
    );

    let response = env
        .api()
        .discover_dhcp(
            DhcpDiscovery::builder("b8:3f:d2:90:97:a6", underlay_segment.relay_address)
                .vendor_string("iDRac")
                .tonic_request(),
        )
        .await?
        .into_inner();

    let mut txn = pool.begin().await.unwrap();
    let addr = response.address.as_str();
    common::insert_endpoint_version(&mut txn, addr, "4.9", "1.1", true).await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    mgr.run_single_iteration().await?;
    // The "upload" is synchronous now and will be complete at this point.

    // Expect "reset" the BMC
    let mut txn = pool.begin().await.unwrap();
    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    let endpoint = endpoints.first().unwrap();
    match &endpoint.preingestion_state {
        PreingestionState::InitialReset { phase, .. } => {
            assert_eq!(*phase, InitialResetPhase::BMCWasReset);
        }
        _ => {
            panic!("Bad preingestion state: {:?}", endpoint.preingestion_state);
        }
    }
    txn.commit().await?;
    mgr.run_single_iteration().await?;

    // Expect WaitHostBoot
    let mut txn = pool.begin().await.unwrap();
    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    let endpoint = endpoints.first().unwrap();
    match &endpoint.preingestion_state {
        PreingestionState::InitialReset { phase, .. } => {
            assert_eq!(*phase, InitialResetPhase::WaitHostBoot);
        }
        _ => {
            panic!("Bad preingestion state: {:?}", endpoint.preingestion_state);
        }
    }
    // Pretend we waited
    db::explored_endpoints::pregestion_hostboot_time_test(
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()),
        &mut txn,
    )
    .await?;
    txn.commit().await?;
    mgr.run_single_iteration().await?;

    // Recheck versions
    let mut txn = pool.begin().await.unwrap();
    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    let endpoint = endpoints.first().unwrap();
    assert_eq!(
        endpoint.preingestion_state,
        PreingestionState::RecheckVersions
    );
    txn.commit().await?;
    mgr.run_single_iteration().await?;

    // At this point, we expect that it shows as having completed upload
    let mut txn = pool.begin().await.unwrap();

    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let mut endpoint = endpoints.into_iter().next().unwrap();
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
            panic!("Bad preingestion state: {:?}", endpoint.preingestion_state);
        }
    }

    // Now we simulate site explorer coming through and reading the new updated version
    endpoint.report.service[0].inventories[0].version = Some("6.00.30.00".to_string());
    assert!(
        db::explored_endpoints::try_update(
            endpoint.address,
            endpoint.report_version,
            &endpoint.report,
            false,
            &mut txn
        )
        .await?
    );

    txn.commit().await?;

    for state in [
        PowerDrainState::Off,
        PowerDrainState::Powercycle,
        PowerDrainState::On,
        PowerDrainState::Off,
        PowerDrainState::Powercycle,
        PowerDrainState::On,
    ] {
        mgr.run_single_iteration().await?;

        let mut txn = pool.begin().await.unwrap();
        let endpoints = db::explored_endpoints::find_all(txn.as_mut()).await?;
        assert!(endpoints.len() == 1);
        let mut endpoint = endpoints.into_iter().next().unwrap();
        tracing::debug!("State should be {state:?}");
        match &endpoint.preingestion_state {
            PreingestionState::ResetForNewFirmware {
                delay_until,
                last_power_drain_operation,
                ..
            } => {
                assert!(delay_until.is_some());
                assert_eq!(last_power_drain_operation.clone().unwrap(), state);
                println!("Rechecking versions");
            }
            _ => {
                panic!("Bad preingestion state: {:?}", endpoint.preingestion_state);
            }
        }

        // At some point in here we would have picked up the new version
        endpoint.report.service[0].inventories[1].version = Some("1.13.2".to_string());
        assert!(
            db::explored_endpoints::try_update(
                endpoint.address,
                endpoint.report_version,
                &endpoint.report,
                false,
                &mut txn
            )
            .await?
        );

        txn.commit().await?;
    }

    mgr.run_single_iteration().await?;
    let mut txn = pool.begin().await.unwrap();
    let endpoints = db::explored_endpoints::find_all(txn.as_mut()).await?;
    txn.commit().await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
    let PreingestionState::RecheckVersions = endpoint.preingestion_state else {
        panic!("Not in recheck versions: {:?}", endpoint.preingestion_state);
    };

    // Now it should go to completion
    mgr.run_single_iteration().await?;
    let mut txn = pool.begin().await.unwrap();
    assert!(
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut())
            .await?
            .is_empty()
    );
    assert!(
        db::explored_endpoints::find_all_preingestion_complete(&mut txn)
            .await?
            .len()
            == 1
    );
    txn.commit().await?;

    Ok(())
}

#[sqlx_test]
async fn test_preingestion_upgrade_script(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool.clone()).build().await;
    let domain = env.test_domain().await;
    let nc = env.network_controller();
    let underlay_segment = nc.create_underlay_segment(&domain).await;
    let mut config = default_config::get();

    let (_tmpdir, host_models) = script_setup();
    config.host_models = host_models;

    let mgr = PreingestionManager::new(
        pool.clone(),
        config.preingestion_manager(),
        Arc::new(RedfishSim::default()),
        env.test_meter.meter(),
        None,
        None,
        None,
        env.api().work_lock_manager_handle(),
        config.ntp_servers.clone(),
    );

    let response = env
        .api()
        .discover_dhcp(
            DhcpDiscovery::builder("b8:3f:d2:90:97:a6", underlay_segment.relay_address)
                .vendor_string("iDRac")
                .tonic_request(),
        )
        .await?
        .into_inner();

    let addr = response.address.as_str();
    let mut txn = pool.begin().await.unwrap();
    db::explored_endpoints::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    common::insert_endpoint_version(&mut txn, addr, "0", "0", false).await?;
    txn.commit().await?;

    mgr.run_single_iteration().await?;
    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
    match &endpoint.preingestion_state {
        // We expect it to be waiting for task completion
        PreingestionState::ScriptRunning => {}
        _ => {
            panic!("Bad preingestion state: {endpoint:?}");
        }
    }
    txn.commit().await?;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    mgr.run_single_iteration().await?;

    let mut txn = pool.begin().await.unwrap();
    let endpoints =
        db::explored_endpoints::find_preingest_not_waiting_not_error(txn.as_mut()).await?;
    assert!(endpoints.len() == 1);
    let endpoint = endpoints.first().unwrap();
    match &endpoint.preingestion_state {
        // We expect it to be have gone back to rechecking versions, we won't bother testing that here
        PreingestionState::RecheckVersions => {}
        _ => {
            panic!("Bad preingestion state: {endpoint:?}");
        }
    }
    txn.commit().await?;

    Ok(())
}
