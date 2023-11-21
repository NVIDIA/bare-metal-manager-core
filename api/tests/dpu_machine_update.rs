pub mod common;

use std::collections::HashMap;

use carbide::{
    db::dpu_machine_update::DpuMachineUpdate, model::machine::machine_id::try_parse_machine_id,
};
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine, host::create_host_machine};

use crate::common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_available_outdated_dpus(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

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

    let mut txn = pool.begin().await?;

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
async fn test_find_available_outdated_dpus_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

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

    let mut txn = pool.begin().await?;
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
    let env = create_test_env(pool.clone()).await;

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

    let mut txn = pool.begin().await?;
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
    let env = create_test_env(pool.clone()).await;

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

    let mut txn = pool.begin().await?;
    let mut expected_dpu_firmware_versions: HashMap<String, String> = HashMap::new();
    expected_dpu_firmware_versions.insert("BlueField SoC".to_owned(), "v9".to_owned());

    let dpus =
        DpuMachineUpdate::find_unavailable_outdated_dpus(&mut txn, &expected_dpu_firmware_versions)
            .await?;

    assert_eq!(dpus.len(), 1);
    assert_eq!(dpus.get(0).unwrap().dpu_machine_id, dpu_machine_id);
    assert_eq!(dpus.get(0).unwrap().host_machine_id, host_machine_id);

    Ok(())
}
