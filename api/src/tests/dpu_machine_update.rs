use std::ops::DerefMut;

use crate::db::DatabaseError;
use crate::tests::common;

use crate::model::machine::Machine;
use crate::tests::common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;
use crate::{CarbideError, CarbideResult};
use crate::{
    db, db::dpu_machine_update::DpuMachineUpdate,
    model::machine::network::MachineNetworkStatusObservation,
};
use common::api_fixtures::{create_managed_host, create_managed_host_multi_dpu, create_test_env};
use forge_uuid::machine::MachineId;
use health_report::HealthReport;
use sqlx::{Postgres, Transaction};

pub async fn update_nic_firmware_version(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    version: &str,
) -> CarbideResult<()> {
    let query = r#"UPDATE machine_topologies SET topology =
                jsonb_set(topology, '{discovery_data, Info, dpu_info, firmware_version}', $1) 
                WHERE machine_id=$2"#;

    sqlx::query(query)
        .bind(sqlx::types::Json(version))
        .bind(machine_id)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
        let mut txn = env.pool.begin().await?;
        update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
        txn.commit().await?;
        dpu_machine_ids.push(dpu_machine_id);
        host_machine_ids.push(host_machine_id);
    }

    let mut txn = env.pool.begin().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(&mut txn, None, &env.config).await?;

    assert_eq!(dpus.len(), dpu_machine_ids.len());
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_with_unhealthy(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
        let mut txn = env.pool.begin().await?;
        update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
        txn.commit().await?;
        dpu_machine_ids.push(dpu_machine_id);
        host_machine_ids.push(host_machine_id);
    }

    let machine_obs = MachineNetworkStatusObservation {
        machine_id: dpu_machine_ids.first().unwrap().to_string(),
        agent_version: None,
        observed_at: chrono::Utc::now(),
        network_config_version: None,
        client_certificate_expiry: None,
        agent_version_superseded_at: None,
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
    let dpu_machine_id = dpu_machine_ids.first().unwrap();
    db::machine::update_network_status_observation(&mut txn, dpu_machine_id, &machine_obs).await?;
    db::machine::update_dpu_agent_health_report(&mut txn, dpu_machine_id, &health_report).await?;

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(&mut txn, None, &env.config).await?;

    assert_eq!(dpus.len(), dpu_machine_ids.len() - 1);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
        let mut txn = env.pool.begin().await?;
        update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
        txn.commit().await?;
        dpu_machine_ids.push(dpu_machine_id);
        host_machine_ids.push(host_machine_id);
    }

    let mut txn = env.pool.begin().await?;

    let dpus =
        DpuMachineUpdate::find_available_outdated_dpus(&mut txn, Some(1), &env.config).await?;

    assert_eq!(dpus.len(), 1);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_unavailable_outdated_dpus_when_none(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
        let mut txn = env.pool.begin().await?;
        crate::db::machine::update_hardware_health_report(
            &mut txn,
            &host_machine_id,
            &HealthReport::heartbeat_timeout(
                "test".to_owned(),
                "test".to_owned(),
                "test".to_owned(),
            ),
        )
        .await?;
        update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
        txn.commit().await?;
        dpu_machine_ids.push(dpu_machine_id);
        host_machine_ids.push(host_machine_id);
    }

    let mut txn = env.pool.begin().await?;
    let dpus = DpuMachineUpdate::find_unavailable_outdated_dpus(&mut txn, &env.config).await?;

    assert_eq!(dpus.len(), 0);
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_unavailable_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..2 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
        dpu_machine_ids.push(dpu_machine_id);
        host_machine_ids.push(host_machine_id);
    }

    let host_sim = env.start_managed_host_sim();
    let (dpu_machine_id, host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(&env, &host_sim.config).await;
    let mut txn = env.pool.begin().await?;
    update_nic_firmware_version(&mut txn, &dpu_machine_id, "11.10.1000").await?;
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let dpus = DpuMachineUpdate::find_unavailable_outdated_dpus(&mut txn, &env.config).await?;

    assert_eq!(dpus.len(), 1);
    assert_eq!(dpus.first().unwrap().dpu_machine_id, dpu_machine_id);
    assert_eq!(dpus.first().unwrap().host_machine_id, host_machine_id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_multidpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = env.pool.begin().await?;
    let all_dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    for dpu in &all_dpus {
        update_nic_firmware_version(&mut txn, &dpu.id, "1.11.1000").await?;
    }
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let dpus = DpuMachineUpdate::find_available_outdated_dpus(&mut txn, None, &env.config).await?;

    assert_eq!(dpus.len(), all_dpus.len());
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_multidpu_one_under_reprov(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await?;
    let all_dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    let dpu_machine_id = all_dpus[0].id;
    DpuMachineUpdate::trigger_reprovisioning_for_managed_host(
        &mut txn,
        &host_machine_id,
        &[DpuMachineUpdate {
            host_machine_id,
            dpu_machine_id: all_dpus[0].id,
            firmware_version: "test_version".to_string(),
        }],
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(&mut txn, None, &env.config).await?;

    assert!(dpus.is_empty());

    let mut txn = env.pool.begin().await?;
    let all_dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    let (dpu_under_reprov, dpu_not_under_reprov): (Vec<Machine>, Vec<Machine>) = all_dpus
        .into_iter()
        .partition(|x| x.reprovision_requested.is_some());
    assert_eq!(dpu_under_reprov.len(), 1);
    assert_eq!(dpu_not_under_reprov.len(), 1);
    assert_eq!(dpu_under_reprov[0].id, dpu_machine_id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_available_outdated_dpus_multidpu_both_under_reprov(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await?;
    let all_dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    DpuMachineUpdate::trigger_reprovisioning_for_managed_host(
        &mut txn,
        &host_machine_id,
        &[
            DpuMachineUpdate {
                host_machine_id,
                dpu_machine_id: all_dpus[1].id,
                firmware_version: "test_version".to_string(),
            },
            DpuMachineUpdate {
                host_machine_id,
                dpu_machine_id: all_dpus[0].id,
                firmware_version: "test_version".to_string(),
            },
        ],
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(&mut txn, None, &env.config).await?;

    assert!(dpus.is_empty());

    let mut txn = env.pool.begin().await?;
    let all_dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    let (dpu_under_reprov, dpu_not_under_reprov): (Vec<Machine>, Vec<Machine>) = all_dpus
        .into_iter()
        .partition(|x| x.reprovision_requested.is_some());
    assert_eq!(dpu_under_reprov.len(), 2);
    assert_eq!(dpu_not_under_reprov.len(), 0);
    Ok(())
}
