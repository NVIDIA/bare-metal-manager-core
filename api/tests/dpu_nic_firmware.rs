pub mod common;

use std::collections::HashSet;

use carbide::{
    db::{
        machine::{Machine, MachineSearchConfig},
        ObjectFilter,
    },
    machine_update_manager::{
        dpu_nic_firmware::DpuNicFirmwareUpdate, machine_update_module::MachineUpdateModule,
    },
    model::machine::machine_id::try_parse_machine_id,
};
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine, host::create_host_machine};
use sqlx::Row;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_start_updates(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim.config, &dpu_machine_id).await)
            .unwrap();

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        expected_dpu_firmware_version: "2.0.1".to_string(),
        metrics: None,
    };

    let mut txn = pool.begin().await.expect("Failed to create transaction");

    let started_count = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default())
        .await?;

    assert_eq!(started_count.len(), 1);
    assert!(started_count.get(&dpu_machine_id).is_none());
    assert!(started_count.get(&host_machine_id).is_some());

    let query = "SELECT count(maintenance_reference)::int FROM machines WHERE maintenance_reference like 'Automatic dpu firmware update from%'";
    let count: i32 = sqlx::query::<_>(query)
        .fetch_one(&mut *txn)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    assert_eq!(count, 2);

    let machines = Machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();

    assert_eq!(machines.len(), 2);
    let dpu_machine = machines.iter().find(|m| m.is_dpu()).unwrap();
    let initiator = dpu_machine.reprovisioning_requested().unwrap().initiator;
    assert!(initiator.starts_with("Automatic dpu firmware update from"));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_get_updates_in_progress(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim.config, &dpu_machine_id).await)
            .unwrap();

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        expected_dpu_firmware_version: "2.0.1".to_string(),
        metrics: None,
    };

    let mut txn = pool.begin().await.expect("Failed to create transaction");

    let updating_count = dpu_nic_firmware_update
        .get_updates_in_progress(&mut txn)
        .await?;

    assert!(updating_count.is_empty());

    let started_count = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default())
        .await?;

    let updating_count = dpu_nic_firmware_update
        .get_updates_in_progress(&mut txn)
        .await?;

    assert!(started_count.get(&host_machine_id).is_some());
    assert_eq!(updating_count.len(), 1);
    assert!(updating_count.get(&host_machine_id).is_some());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_check_for_updates(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim1 = env.start_managed_host_sim();
    let host_sim2 = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim1.config).await).unwrap();
    let _host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim1.config, &dpu_machine_id).await)
            .unwrap();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim2.config).await).unwrap();
    let _host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim2.config, &dpu_machine_id).await)
            .unwrap();

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        expected_dpu_firmware_version: "2.0.1".to_string(),
        metrics: None,
    };

    let mut txn = pool.begin().await.expect("Failed to create transaction");

    let machine_updates = dpu_nic_firmware_update
        .check_for_updates(&mut txn, 10)
        .await;
    assert_eq!(machine_updates.len(), 2);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_clear_complated_updates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim.config, &dpu_machine_id).await)
            .unwrap();

    let dpu_nic_firmware_update = DpuNicFirmwareUpdate {
        expected_dpu_firmware_version: "2.0.1".to_string(),
        metrics: None,
    };

    let mut txn = pool.begin().await.expect("Failed to create transaction");

    let started_count = dpu_nic_firmware_update
        .start_updates(&mut txn, 10, &HashSet::default())
        .await?;

    assert!(started_count.get(&dpu_machine_id).is_none());
    assert!(started_count.get(&host_machine_id).is_some());

    let machines = Machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();

    assert_eq!(machines.len(), 2);
    let dpu_machine = machines.iter().find(|m| m.is_dpu()).unwrap();
    let initiator = dpu_machine.reprovisioning_requested().unwrap().initiator;
    let reference = dpu_machine.maintenance_reference().unwrap();
    assert!(initiator.starts_with("Automatic dpu firmware update from"));
    assert!(reference.starts_with("Automatic dpu firmware update from"));

    txn.commit().await.expect("commit failed");
    let mut txn = pool.begin().await.expect("Failed to create transaction");

    dpu_nic_firmware_update
        .clear_completed_updates(&mut txn)
        .await
        .unwrap();

    let machines: Vec<Machine> =
        Machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
            .await
            .unwrap();

    assert_eq!(machines.len(), 2);
    let dpu_machine = machines.iter().find(|m| m.is_dpu()).unwrap();
    let initiator = dpu_machine.reprovisioning_requested().unwrap().initiator;
    let reference = dpu_machine.maintenance_reference().unwrap();
    assert!(initiator.starts_with("Automatic dpu firmware update from"));
    assert!(reference.starts_with("Automatic dpu firmware update from"));

    txn.rollback().await.unwrap();

    // pretend like the update happened
    let mut txn = pool.begin().await.expect("Failed to create transaction");
    let query = r#"UPDATE machine_topologies SET topology=jsonb_set(topology, '{discovery_data,Info,dpu_info,firmware_version}', '"2.0.1"', false)
     WHERE machine_id=$1"#;
    sqlx::query::<_>(query)
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

    txn.commit().await.unwrap();

    let mut txn = pool.begin().await.expect("Failed to create transaction");

    dpu_nic_firmware_update
        .clear_completed_updates(&mut txn)
        .await
        .unwrap();

    let dpu_machine = Machine::find(
        &mut txn,
        ObjectFilter::One(dpu_machine_id),
        MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .first()
    .unwrap()
    .clone();

    assert_eq!(dpu_machine.maintenance_reference(), None);

    Ok(())
}
