pub mod common;

use std::collections::HashMap;

use carbide::{
    db::{dpu_machine_update::DpuMachineUpdate, machine::Machine},
    model::machine::{
        machine_id::try_parse_machine_id,
        network::{HealthStatus, MachineNetworkStatusObservation},
    },
};
use common::api_fixtures::{
    create_test_env, dpu::create_dpu_machine, host::create_host_machine,
    managed_host::create_managed_host_multi_dpu,
};

use crate::common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let mut txn = env.pool.begin().await?;

    let mut expected_dpu_firmware_versions = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());
    expected_dpu_firmware_versions.insert(
        "BlueField-3 SmartNIC Main Card".to_owned(),
        "v49".to_owned(),
    );

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        &mut txn,
        &expected_dpu_firmware_versions,
        None,
    )
    .await?;

    assert_eq!(dpus.len(), dpu_machine_ids.len());
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus_with_unhealthy(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let machine_obs = MachineNetworkStatusObservation {
        machine_id: dpu_machine_ids.first().unwrap().to_string(),
        agent_version: None,
        observed_at: chrono::Utc::now(),
        health_status: HealthStatus {
            is_healthy: false,
            failed: vec!["test fail status".to_owned()],
            passed: vec![],
            message: Some("hello world".to_owned()),
        },
        network_config_version: None,
        client_certificate_expiry: None,
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
    Machine::update_network_status_observation(&mut txn, dpu_machine_id, &machine_obs).await?;
    Machine::update_dpu_agent_health_report(&mut txn, dpu_machine_id, &health_report).await?;

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await?;

    let mut expected_dpu_firmware_versions = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());
    expected_dpu_firmware_versions.insert(
        "BlueField-3 SmartNIC Main Card".to_owned(),
        "v49".to_owned(),
    );

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        &mut txn,
        &expected_dpu_firmware_versions,
        None,
    )
    .await?;

    assert_eq!(dpus.len(), dpu_machine_ids.len() - 1);
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let mut txn = env.pool.begin().await?;
    let mut expected_dpu_firmware_versions: HashMap<String, String> = HashMap::new();
    expected_dpu_firmware_versions.insert(
        "BlueField-3 SmartNIC Main Card".to_owned(),
        "v49".to_owned(),
    );
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        &mut txn,
        &expected_dpu_firmware_versions,
        Some(1),
    )
    .await?;

    assert_eq!(dpus.len(), 1);
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_unavailable_outdated_dpus_when_none(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..10 {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let mut txn = env.pool.begin().await?;
    let mut expected_dpu_firmware_versions: HashMap<String, String> = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "24.35.2000".to_owned());

    let dpus =
        DpuMachineUpdate::find_unavailable_outdated_dpus(&mut txn, &expected_dpu_firmware_versions)
            .await?;

    assert_eq!(dpus.len(), 0);
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_unavailable_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in 0..2 {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let host_sim = env.start_managed_host_sim();
    let (dpu_machine_id, host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(&env, &host_sim.config).await;

    let mut txn = env.pool.begin().await?;
    let mut expected_dpu_firmware_versions: HashMap<String, String> = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());

    let dpus =
        DpuMachineUpdate::find_unavailable_outdated_dpus(&mut txn, &expected_dpu_firmware_versions)
            .await?;

    assert_eq!(dpus.len(), 1);
    assert_eq!(dpus.first().unwrap().dpu_machine_id, dpu_machine_id);
    assert_eq!(dpus.first().unwrap().host_machine_id, host_machine_id);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus_multidpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await?;

    let mut expected_dpu_firmware_versions = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());
    expected_dpu_firmware_versions.insert(
        "BlueField-3 SmartNIC Main Card".to_owned(),
        "v49".to_owned(),
    );

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        &mut txn,
        &expected_dpu_firmware_versions,
        None,
    )
    .await?;

    let all_dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    assert_eq!(dpus.len(), all_dpus.len());
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus_multidpu_one_under_reprov(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut expected_dpu_firmware_versions = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());
    expected_dpu_firmware_versions.insert(
        "BlueField-3 SmartNIC Main Card".to_owned(),
        "v49".to_owned(),
    );

    let mut txn = env.pool.begin().await?;
    let all_dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    let dpu_machine_id = all_dpus[0].id().clone();
    DpuMachineUpdate::trigger_reprovisioning_for_managed_host(
        &mut txn,
        &host_machine_id,
        &[DpuMachineUpdate {
            host_machine_id: host_machine_id.clone(),
            dpu_machine_id: all_dpus[0].id().clone(),
            firmware_version: "test_version".to_string(),
            product_name: "BlueField SoC".to_string(),
        }],
        expected_dpu_firmware_versions.clone(),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        &mut txn,
        &expected_dpu_firmware_versions,
        None,
    )
    .await?;

    assert!(dpus.is_empty());

    let mut txn = env.pool.begin().await?;
    let all_dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    let (dpu_under_reprov, dpu_not_under_reprov): (Vec<Machine>, Vec<Machine>) = all_dpus
        .into_iter()
        .partition(|x| x.reprovisioning_requested().is_some());
    assert_eq!(dpu_under_reprov.len(), 1);
    assert_eq!(dpu_not_under_reprov.len(), 1);
    assert_eq!(dpu_under_reprov[0].id().clone(), dpu_machine_id);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus_multidpu_both_under_reprov(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut expected_dpu_firmware_versions = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());
    expected_dpu_firmware_versions.insert(
        "BlueField-3 SmartNIC Main Card".to_owned(),
        "v49".to_owned(),
    );

    let mut txn = env.pool.begin().await?;
    let all_dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    DpuMachineUpdate::trigger_reprovisioning_for_managed_host(
        &mut txn,
        &host_machine_id,
        &[
            DpuMachineUpdate {
                host_machine_id: host_machine_id.clone(),
                dpu_machine_id: all_dpus[1].id().clone(),
                firmware_version: "test_version".to_string(),
                product_name: "BlueField SoC".to_string(),
            },
            DpuMachineUpdate {
                host_machine_id: host_machine_id.clone(),
                dpu_machine_id: all_dpus[0].id().clone(),
                firmware_version: "test_version".to_string(),
                product_name: "BlueField SoC".to_string(),
            },
        ],
        expected_dpu_firmware_versions.clone(),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;

    let dpus = DpuMachineUpdate::find_available_outdated_dpus(
        &mut txn,
        &expected_dpu_firmware_versions,
        None,
    )
    .await?;

    assert!(dpus.is_empty());

    let mut txn = env.pool.begin().await?;
    let all_dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    let (dpu_under_reprov, dpu_not_under_reprov): (Vec<Machine>, Vec<Machine>) = all_dpus
        .into_iter()
        .partition(|x| x.reprovisioning_requested().is_some());
    assert_eq!(dpu_under_reprov.len(), 2);
    assert_eq!(dpu_not_under_reprov.len(), 0);
    Ok(())
}
