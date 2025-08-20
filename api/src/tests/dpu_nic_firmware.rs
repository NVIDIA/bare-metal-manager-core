use crate::db::managed_host::LoadSnapshotOptions;
use crate::machine_update_manager::machine_update_module::HOST_UPDATE_HEALTH_REPORT_SOURCE;
use crate::tests::common;
use crate::tests::dpu_machine_update::{get_all_snapshots, update_nic_firmware_version};

use std::collections::HashSet;
use std::str::FromStr;
use std::string::ToString;

use crate::{
    db,
    machine_update_manager::{
        dpu_nic_firmware::DpuNicFirmwareUpdate,
        machine_update_module::{AutomaticFirmwareUpdateReference, MachineUpdateModule},
    },
};
use common::api_fixtures::{create_managed_host, create_managed_host_multi_dpu, create_test_env};
use forge_uuid::machine::MachineId;
use rpc::forge::forge_server::Forge;

#[crate::sqlx_test]
async fn test_start_updates(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
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
    assert!(!started_count.contains(&dpu_machine_id));
    assert!(started_count.contains(&host_machine_id));

    // Check if health override is placed
    let managed_host =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await
            .unwrap()
            .unwrap();

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

    let (host_machine_id, _) = create_managed_host_multi_dpu(&env, 2).await;

    let rpc_host_id: rpc::MachineId = host_machine_id.into();
    let host = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![rpc_host_id],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    let rpc_dpu_ids = host.associated_dpu_machine_ids;
    let dpu_machine_id = MachineId::from_str(&rpc_dpu_ids[0].id).unwrap();
    let dpu_machine_id2 = MachineId::from_str(&rpc_dpu_ids[1].id).unwrap();
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
    assert!(dpus_started.contains(&host_machine_id));

    // Check if health override is placed
    let managed_host =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await
            .unwrap()
            .unwrap();

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
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
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

    assert!(started_count.contains(&host_machine_id));
    assert_eq!(updating_count.len(), 1);
    assert!(updating_count.contains(&host_machine_id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_check_for_updates(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut machine_ids = Vec::default();
    let (host_machine_id, dpu_machine_id1) = create_managed_host(&env).await;
    machine_ids.push(host_machine_id);
    let (host_machine_id, dpu_machine_id2) = create_managed_host(&env).await;
    machine_ids.push(host_machine_id);
    let mut txn = env.pool.begin().await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id1, "11.10.1000").await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id2, "11.10.1000").await?;
    txn.commit().await?;

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        metrics: None,
        config: env.config.clone(),
    };

    let mut txn = env.pool.begin().await?;
    let snapshots = crate::db::managed_host::load_by_machine_ids(
        &mut txn,
        &machine_ids,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: env.config.host_health,
        },
    )
    .await
    .unwrap();

    let machine_updates = dpu_nic_firmware_update
        .check_for_updates(&snapshots, 10)
        .await;
    assert_eq!(machine_updates.len(), 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_clear_completed_updates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
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

    assert!(!started_count.contains(&dpu_machine_id));
    assert!(started_count.contains(&host_machine_id));

    // Check if health override is placed
    let managed_host =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await
            .unwrap()
            .unwrap();

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
    let managed_host =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await
            .unwrap()
            .unwrap();

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
        .bind(dpu_machine_id.to_string())
        .execute(&mut *txn)
        .await
        .unwrap();
    let query = r#"UPDATE machines set reprovisioning_requested = NULL where id = $1"#;
    sqlx::query(query)
        .bind(dpu_machine_id.to_string())
        .execute(&mut *txn)
        .await
        .unwrap();

    let health_override = crate::machine_update_manager::machine_update_module::create_host_update_health_report_dpufw();
    // Mark the Host as in update.
    crate::db::machine::insert_health_report_override(
        &mut txn,
        &host_machine_id,
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
    let managed_host =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await
            .unwrap()
            .unwrap();
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
