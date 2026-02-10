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
use std::collections::HashSet;
use std::string::ToString;

use common::api_fixtures::{create_managed_host, create_managed_host_multi_dpu, create_test_env};
use model::machine::LoadSnapshotOptions;
use model::machine_update_module::{
    AutomaticFirmwareUpdateReference, HOST_UPDATE_HEALTH_REPORT_SOURCE,
};

use crate::CarbideResult;
use crate::machine_update_manager::dpu_nic_firmware::DpuNicFirmwareUpdate;
use crate::machine_update_manager::machine_update_module::MachineUpdateModule;
use crate::tests::common;
use crate::tests::common::api_fixtures::TestManagedHost;
use crate::tests::common::api_fixtures::test_managed_host::TestManagedHostSnapshots;
use crate::tests::dpu_machine_update::{get_all_snapshots, update_nic_firmware_version};

#[crate::sqlx_test]
async fn test_start_updates(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let managed_host = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;
    managed_host.update_nic_firmware_version(&mut txn).await?;
    txn.commit().await?;
    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        metrics: None,
        config: env.config.clone(),
    };

    let snapshots = get_all_snapshots(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let started_count = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default(), &snapshots)
        .await?;

    assert_eq!(started_count.len(), 1);
    assert!(!started_count.contains(&managed_host.dpu().id));
    assert!(started_count.contains(&managed_host.id));

    // Check if health override is placed
    let managed_host = managed_host.snapshot(&mut txn).await;

    for dpu in managed_host.dpu_snapshots.iter() {
        let initiator = &dpu.reprovision_requested.as_ref().unwrap().initiator;
        assert!(initiator.starts_with(AutomaticFirmwareUpdateReference::REF_NAME));
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_start_updates_with_multidpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let host = mh.host().rpc_machine().await;
    let dpu_ids = host.associated_dpu_machine_ids;
    let dpu_machine_id = dpu_ids[0];
    let dpu_machine_id2 = dpu_ids[1];
    let mut txn = env.pool.begin().await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id2, "11.10.1000").await?;
    txn.commit().await?;

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        metrics: None,
        config: env.config.clone(),
    };

    let snapshots = get_all_snapshots(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let dpus_started = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default(), &snapshots)
        .await?;

    assert_eq!(dpus_started.len(), 1);
    assert!(!dpus_started.contains(&dpu_machine_id));
    assert!(!dpus_started.contains(&dpu_machine_id2));
    assert!(dpus_started.contains(&mh.host().id));

    // Check if health override is placed
    let managed_host = mh.snapshot(&mut txn).await;

    for dpu in managed_host.dpu_snapshots.iter() {
        let initiator = &dpu.reprovision_requested.as_ref().unwrap().initiator;
        assert!(initiator.starts_with(AutomaticFirmwareUpdateReference::REF_NAME));
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_get_updates_in_progress(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let managed_host = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;
    managed_host.update_nic_firmware_version(&mut txn).await?;
    txn.commit().await?;
    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        metrics: None,
        config: env.config.clone(),
    };

    let snapshots = get_all_snapshots(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let updating_count = dpu_nic_firmware_update
        .get_updates_in_progress(&mut txn)
        .await?;

    assert!(updating_count.is_empty());

    let started_count = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default(), &snapshots)
        .await?;

    let updating_count = dpu_nic_firmware_update
        .get_updates_in_progress(&mut txn)
        .await?;

    assert!(started_count.contains(&managed_host.id));
    assert_eq!(updating_count.len(), 1);
    assert!(updating_count.contains(&managed_host.id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_check_for_updates(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let machines = vec![
        create_managed_host(&env).await,
        create_managed_host(&env).await,
    ];
    let mut txn = env.pool.begin().await?;
    for m in &machines {
        m.update_nic_firmware_version(&mut txn).await?;
    }
    txn.commit().await?;

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        metrics: None,
        config: env.config.clone(),
    };

    let snapshots = machines
        .snapshots(
            &mut env.db_reader(),
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                host_health_config: env.config.host_health,
            },
        )
        .await;

    let machine_updates = dpu_nic_firmware_update.check_for_updates(&snapshots, 10);
    assert_eq!(machine_updates.len(), 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_clear_completed_updates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;
    mh.update_nic_firmware_version(&mut txn).await?;
    txn.commit().await?;

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        metrics: None,
        config: env.config.clone(),
    };

    let snapshots = get_all_snapshots(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let started_count = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default(), &snapshots)
        .await?;

    assert!(!started_count.contains(&mh.dpu().id));
    assert!(started_count.contains(&mh.id));

    // Check if health override is placed
    let managed_host = mh.snapshot(&mut txn).await;

    for dpu in managed_host.dpu_snapshots.iter() {
        let initiator = &dpu.reprovision_requested.as_ref().unwrap().initiator;
        assert!(initiator.starts_with(AutomaticFirmwareUpdateReference::REF_NAME));
    }

    txn.commit().await.expect("commit failed");

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    dpu_nic_firmware_update
        .clear_completed_updates(&mut txn)
        .await
        .unwrap();

    // Health override is still in place since update did not complete
    let managed_host = mh.snapshot(&mut txn).await;

    for dpu in managed_host.dpu_snapshots.iter() {
        let initiator = &dpu.reprovision_requested.as_ref().unwrap().initiator;
        assert!(initiator.starts_with(AutomaticFirmwareUpdateReference::REF_NAME));
    }

    txn.rollback().await.unwrap();

    // pretend like the update happened
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    let query = r#"UPDATE machine_topologies SET topology=jsonb_set(topology, '{discovery_data,Info,dpu_info,firmware_version}', $1, false)
     WHERE machine_id=$2"#;
    sqlx::query::<_>(query)
        .bind(sqlx::types::Json("24.42.1000"))
        .bind(mh.dpu().id.to_string())
        .execute(&mut *txn)
        .await
        .unwrap();
    let query = r#"UPDATE machines set reprovisioning_requested = NULL where id = $1"#;
    sqlx::query(query)
        .bind(mh.dpu().id.to_string())
        .execute(&mut *txn)
        .await
        .unwrap();

    let health_override = crate::machine_update_manager::machine_update_module::create_host_update_health_report_dpufw();
    // Mark the Host as in update.
    db::machine::insert_health_report_override(
        &mut txn,
        &mh.id,
        health_report::OverrideMode::Merge,
        &health_override,
        false,
    )
    .await?;

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    dpu_nic_firmware_update
        .clear_completed_updates(&mut txn)
        .await
        .unwrap();

    // Health override is removed
    let managed_host = mh.snapshot(&mut txn).await;
    assert!(
        !managed_host
            .host_snapshot
            .health_report_overrides
            .merges
            .contains_key(HOST_UPDATE_HEALTH_REPORT_SOURCE)
    );
    assert!(managed_host.aggregate_health.alerts.is_empty());

    Ok(())
}

impl TestManagedHost {
    pub async fn update_nic_firmware_version(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> CarbideResult<()> {
        update_nic_firmware_version(txn, &self.dpu().id, "11.10.1000").await
    }
}
