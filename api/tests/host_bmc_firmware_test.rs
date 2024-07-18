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

use std::{net::IpAddr, str::FromStr};

use carbide::{
    db::explored_endpoints::DbExploredEndpoint, model::site_explorer::PreingestionState,
    preingestion_manager::PreingestionManager,
};

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test]
async fn test_preingestion_bmc_upgrade(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mgr = PreingestionManager::new(
        pool.clone(),
        env.config.clone(),
        env.redfish_sim.clone(),
        env.test_meter.meter(),
    );

    let mut txn = pool.begin().await.unwrap();

    // First, a host where it's already up to date; it should immediately go to complete.
    let addr = "141.219.24.7";
    common::endpoint::insert_endpoint_version(&mut txn, addr, "1.0").await?;
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
    common::endpoint::insert_endpoint_version(&mut txn, addr, "0.5").await?;
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
    common::endpoint::insert_endpoint_version(&mut txn, addr, "0.4").await?;
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

    // Now, let's make sure that a DPU would immediately pass through
    let mut txn = pool.begin().await.unwrap();
    DbExploredEndpoint::delete(&mut txn, IpAddr::from_str(addr).unwrap()).await?;
    common::endpoint::insert_dpu_endpoint(
        &mut txn,
        addr,
        "fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg",
    )
    .await?;
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
    txn.commit().await?;

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_preingestion_waiting_download")
            .unwrap(),
        "0"
    );
    Ok(())
}
