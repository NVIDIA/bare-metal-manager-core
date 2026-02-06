/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;

use carbide_uuid::machine::MachineId;
use common::api_fixtures::{create_managed_host, create_managed_host_multi_dpu, create_test_env};
use db::DatabaseError;
use model::dpu_machine_update::DpuMachineUpdate;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::network::MachineNetworkStatusObservation;
use model::machine::{LoadSnapshotOptions, Machine, ManagedHostStateSnapshot};
use sqlx::PgConnection;

use super::common::api_fixtures::TestEnv;
use crate::CarbideResult;
use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;

pub async fn update_nic_firmware_version(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    version: &str,
) -> CarbideResult<()> {
    let query = r#"UPDATE machine_topologies SET topology =
                jsonb_set(topology, '{discovery_data, Info, dpu_info, firmware_version}', $1) 
                WHERE machine_id=$2"#;

    sqlx::query(query)
        .bind(sqlx::types::Json(version))
        .bind(machine_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

async fn create_machines(
    test_env: &TestEnv,
    machine_count: usize,
) -> HashMap<MachineId, ManagedHostStateSnapshot> {
    let mut machines = Vec::default();
    for _ in 0..machine_count {
        let machine = create_managed_host(test_env).await;
        machines.push(machine);
    }
    let mut txn = test_env.pool.begin().await.unwrap();

    for m in &machines {
        update_nic_firmware_version(&mut txn, &m.dpu().id, "11.10.1000")
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();

    let mut txn = test_env.pool.begin().await.unwrap();

    db::managed_host::load_by_machine_ids(
        &mut txn,
        &machines.iter().map(|m| m.id).collect::<Vec<_>>(),
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: test_env.config.host_health,
        },
    )
    .await
    .expect("Failed to load snapshots")
}

pub async fn get_all_snapshots(test_env: &TestEnv) -> HashMap<MachineId, ManagedHostStateSnapshot> {
    let mut txn = test_env.pool.begin().await.unwrap();
    let machine_ids = db::machine::find_machine_ids(
        txn.as_mut(),
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    db::managed_host::load_by_machine_ids(
        &mut txn,
        &machine_ids,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: test_env.config.host_health,
        },
    )
    .await
    .unwrap()
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let dpu_count: usize = 10;
    let snapshots = create_machines(&env, dpu_count).await;
    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        None,
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    )?;

    assert_eq!(dpus.len(), dpu_count);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_with_unhealthy(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let snapshots = create_machines(&env, 10).await;
    let dpu_machine_id = snapshots.iter().next().unwrap().1.dpu_snapshots[0].id;

    let machine_obs = MachineNetworkStatusObservation {
        machine_id: dpu_machine_id,
        agent_version: None,
        observed_at: chrono::Utc::now(),
        network_config_version: None,
        client_certificate_expiry: None,
        agent_version_superseded_at: None,
        instance_network_observation: None,
        extension_service_observation: None,
    };

    let health_report = health_report::HealthReport {
        source: "forge-dpu-agent".to_string(),
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![health_report::HealthProbeAlert {
            id: "TestFailed".parse().unwrap(),
            target: Some("t1".to_string()),
            in_alert_since: Some(chrono::Utc::now()),
            message: "Test Failed".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes(),
            ],
        }],
    };
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    db::machine::update_network_status_observation(&mut txn, &dpu_machine_id, &machine_obs).await?;
    db::machine::update_dpu_agent_health_report(&mut txn, &dpu_machine_id, &health_report).await?;

    txn.commit().await.unwrap();

    let snapshots = get_all_snapshots(&env).await;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        None,
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    )?;

    assert_eq!(dpus.len(), 9);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let snapshots = create_machines(&env, 10).await;
    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        Some(1),
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    )?;

    assert_eq!(dpus.len(), 1);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_unavailable_outdated_dpus_when_none(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let snapshots = create_machines(&env, 10).await;

    let dpus = DpuMachineUpdate::find_unavailable_outdated_dpus(
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    );

    assert_eq!(dpus.len(), 0);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_unavailable_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut txn = env.pool.begin().await?;

    let host_config = env.managed_host_config();
    let mh = create_dpu_machine_in_waiting_for_network_install(&env, &host_config).await;
    update_nic_firmware_version(&mut txn, &mh.dpu().id, "11.10.1000").await?;
    txn.commit().await.unwrap();

    create_machines(&env, 2).await;
    let snapshots = get_all_snapshots(&env).await;

    let dpus = DpuMachineUpdate::find_unavailable_outdated_dpus(
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    );

    assert_eq!(dpus.len(), 1);
    assert_eq!(dpus.first().unwrap().dpu_machine_id, mh.dpu().id);
    assert_eq!(dpus.first().unwrap().host_machine_id, mh.host().id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_multidpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = env.pool.begin().await?;
    let all_dpus = mh.dpu_db_machines(&mut txn).await;

    for dpu in &all_dpus {
        update_nic_firmware_version(&mut txn, &dpu.id, "1.11.1000").await?;
    }

    let snapshots = db::managed_host::load_by_machine_ids(
        &mut txn,
        &[mh.host().id],
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: env.config.host_health,
        },
    )
    .await
    .expect("Failed to load snapshots");

    txn.commit().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        None,
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    )?;

    assert_eq!(dpus.len(), all_dpus.len());
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_multidpu_one_under_reprov(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mh = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await?;
    db::dpu_machine_update::trigger_reprovisioning_for_managed_host(
        &mut txn,
        &[DpuMachineUpdate {
            host_machine_id: mh.host().id,
            dpu_machine_id: mh.dpu_n(0).id,
            firmware_version: "test_version".to_string(),
        }],
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let snapshots = db::managed_host::load_by_machine_ids(
        &mut txn,
        &[mh.host().id],
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: env.config.host_health,
        },
    )
    .await
    .unwrap();

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        None,
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    )?;

    assert!(dpus.is_empty());

    let mut txn = env.pool.begin().await?;
    let all_dpus = mh.dpu_db_machines(&mut txn).await;

    let (dpu_under_reprov, dpu_not_under_reprov): (Vec<Machine>, Vec<Machine>) = all_dpus
        .into_iter()
        .partition(|x| x.reprovision_requested.is_some());
    assert_eq!(dpu_under_reprov.len(), 1);
    assert_eq!(dpu_not_under_reprov.len(), 1);
    assert_eq!(dpu_under_reprov[0].id, mh.dpu_n(0).id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_multidpu_both_under_reprov(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mh = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await?;
    let all_dpus = mh.dpu_db_machines(&mut txn).await;
    db::dpu_machine_update::trigger_reprovisioning_for_managed_host(
        &mut txn,
        &[
            DpuMachineUpdate {
                host_machine_id: mh.host().id,
                dpu_machine_id: all_dpus[1].id,
                firmware_version: "test_version".to_string(),
            },
            DpuMachineUpdate {
                host_machine_id: mh.host().id,
                dpu_machine_id: all_dpus[0].id,
                firmware_version: "test_version".to_string(),
            },
        ],
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let snapshots = db::managed_host::load_by_machine_ids(
        &mut txn,
        &[mh.host().id],
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: env.config.host_health,
        },
    )
    .await
    .unwrap();

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        None,
        &env.config.dpu_config.dpu_nic_firmware_update_versions,
        &snapshots,
    )?;

    assert!(dpus.is_empty());

    let mut txn = env.pool.begin().await?;
    let all_dpus = mh.dpu_db_machines(&mut txn).await;

    let (dpu_under_reprov, dpu_not_under_reprov): (Vec<Machine>, Vec<Machine>) = all_dpus
        .into_iter()
        .partition(|x| x.reprovision_requested.is_some());
    assert_eq!(dpu_under_reprov.len(), 2);
    assert_eq!(dpu_not_under_reprov.len(), 0);
    Ok(())
}
