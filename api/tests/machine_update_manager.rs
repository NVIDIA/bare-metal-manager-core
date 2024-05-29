pub mod common;

use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use carbide::{
    cfg::CarbideConfig,
    db::{
        dpu_machine_update::DpuMachineUpdate,
        machine::{Machine, MaintenanceMode},
    },
    machine_update_manager::{
        machine_update_module::{
            AutomaticFirmwareUpdateReference, DpuReprovisionInitiator, MachineUpdateModule,
        },
        MachineUpdateManager,
    },
    model::machine::machine_id::{try_parse_machine_id, MachineId},
    CarbideResult,
};
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};
use figment::{
    providers::{Format, Toml},
    Figment,
};
use sqlx::{Postgres, Row, Transaction};

use crate::common::api_fixtures::host::create_host_machine;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cfg/test_data");

#[derive(Clone)]
struct TestUpdateModule {
    pub updates_in_progress: Vec<MachineId>,
    pub updates_started: HashSet<MachineId>,
    start_updates_called: Arc<Mutex<i32>>,
    clear_completed_updates_called: Arc<Mutex<i32>>,
}

#[async_trait]
impl MachineUpdateModule for TestUpdateModule {
    fn new(_config: Arc<CarbideConfig>, _meter: opentelemetry::metrics::Meter) -> Option<Self> {
        None
    }

    async fn get_updates_in_progress(
        &self,
        _txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<HashSet<MachineId>> {
        Ok(self.updates_in_progress.clone().into_iter().collect())
    }

    async fn start_updates(
        &self,
        _txn: &mut Transaction<'_, Postgres>,
        _available_updates: i32,
        _updating_machines: &HashSet<MachineId>,
    ) -> CarbideResult<HashSet<MachineId>> {
        if let Ok(mut guard) = self.start_updates_called.lock() {
            (*guard) += 1;
        }
        Ok(self.updates_started.clone())
    }

    async fn clear_completed_updates(
        &self,
        _txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        if let Ok(mut guard) = self.clear_completed_updates_called.lock() {
            (*guard) += 1;
        }

        Ok(())
    }

    async fn update_metrics(&self, _txn: &mut Transaction<'_, Postgres>) {}
}

impl TestUpdateModule {
    pub fn new(updates_in_progress: Vec<MachineId>, updates_started: HashSet<MachineId>) -> Self {
        TestUpdateModule {
            updates_in_progress,
            updates_started,
            start_updates_called: Arc::new(Mutex::new(0)),
            clear_completed_updates_called: Arc::new(Mutex::new(0)),
        }
    }
    pub fn get_start_updates_called(&self) -> i32 {
        *self.start_updates_called.lock().unwrap()
    }

    pub fn get_clear_completed_updates_called(&self) -> i32 {
        *self.clear_completed_updates_called.lock().unwrap()
    }
}

impl fmt::Display for TestUpdateModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestUpdateModule")
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_max_outstanding_updates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
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

    let config: Arc<CarbideConfig> = Arc::new(
        Figment::new()
            .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap(),
    );

    let mut machines_started = HashSet::default();
    machines_started.insert(dpu_machine_id);

    let module1 = Box::new(TestUpdateModule::new(vec![], machines_started));
    let module2 = Box::new(TestUpdateModule::new(vec![], HashSet::default()));

    let machine_update_manager = MachineUpdateManager::new_with_modules(
        env.pool.clone(),
        config,
        vec![module1.clone(), module2.clone()],
    );

    machine_update_manager.run_single_iteration().await?;

    assert_eq!(module1.get_start_updates_called(), 1);
    assert_eq!(module2.get_start_updates_called(), 0);

    assert_eq!(module1.get_clear_completed_updates_called(), 1);
    assert_eq!(module2.get_clear_completed_updates_called(), 1);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_put_machine_in_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim1 = env.start_managed_host_sim();
    let host_sim2 = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim1.config).await).unwrap();
    try_parse_machine_id(&create_host_machine(&env, &host_sim1.config, &dpu_machine_id).await)
        .unwrap();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim2.config).await).unwrap();
    let host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim2.config, &dpu_machine_id).await)
            .unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let machine_update = DpuMachineUpdate {
        host_machine_id,
        dpu_machine_id,
        firmware_version: "1".to_owned(),
        product_name: "product_x".to_owned(),
    };

    let reference = &DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
        from: "x".to_owned(),
        to: "y".to_owned(),
    });

    MachineUpdateManager::put_machine_in_maintenance(&mut txn, &machine_update, reference)
        .await
        .unwrap();

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    let query = format!(
        "SELECT count(maintenance_reference)::int FROM machines WHERE maintenance_reference = '{}'",
        reference
    );
    let count: i32 = sqlx::query::<_>(&query)
        .fetch_one(&mut *txn)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();

    // the dpu and host are put in maintenance
    assert_eq!(count, 2);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_remove_machine_from_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim1 = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim1.config).await).unwrap();
    try_parse_machine_id(&create_host_machine(&env, &host_sim1.config, &dpu_machine_id).await)
        .unwrap();
    let host_sim2 = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim2.config).await).unwrap();
    let host_machine_id =
        try_parse_machine_id(&create_host_machine(&env, &host_sim2.config, &dpu_machine_id).await)
            .unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let machine_update = DpuMachineUpdate {
        host_machine_id,
        dpu_machine_id: dpu_machine_id.clone(),
        firmware_version: "1".to_owned(),
        product_name: "product_x".to_owned(),
    };

    let reference = &DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
        from: "x".to_owned(),
        to: "y".to_owned(),
    });

    MachineUpdateManager::put_machine_in_maintenance(&mut txn, &machine_update, reference)
        .await
        .unwrap();

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    let query = format!(
        "SELECT count(maintenance_reference)::int FROM machines WHERE maintenance_reference = '{}'",
        reference
    );
    let count: i32 = sqlx::query::<_>(&query)
        .fetch_one(&mut *txn)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();

    // the dpu and host are put in maintenance
    assert_eq!(count, 2);

    MachineUpdateManager::remove_machine_from_maintenance(&mut txn, &machine_update)
        .await
        .unwrap();

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    let query = "SELECT count(maintenance_reference)::int FROM machines WHERE maintenance_reference like '$1%'";
    let count: i32 = sqlx::query::<_>(query)
        .bind(AutomaticFirmwareUpdateReference::REF_NAME)
        .fetch_one(&mut *txn)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();

    assert_eq!(count, 0);

    Ok(())
}

#[sqlx::test()]
fn test_start(pool: sqlx::PgPool) {
    let test_module = Box::new(TestUpdateModule::new(vec![], HashSet::default()));

    let mut config: Arc<CarbideConfig> = Arc::new(
        Figment::new()
            .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap(),
    );

    Arc::get_mut(&mut config)
        .unwrap()
        .machine_update_run_interval = Some(1);
    let update_manager =
        MachineUpdateManager::new_with_modules(pool, config, vec![test_module.clone()]);

    let stop = update_manager.start();

    tokio::time::sleep(Duration::from_secs(4)).await;

    let start_count = test_module.get_start_updates_called();

    tokio::time::sleep(Duration::from_secs(4)).await;

    let end_count = test_module.get_start_updates_called();

    assert_ne!(start_count, end_count);

    drop(stop);

    tokio::time::sleep(Duration::from_secs(2)).await;

    let start_count = test_module.get_start_updates_called();

    tokio::time::sleep(Duration::from_secs(4)).await;

    let end_count = test_module.get_start_updates_called();

    assert_eq!(start_count, end_count);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_get_machines_in_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim1 = env.start_managed_host_sim();
    let host_sim2 = env.start_managed_host_sim();
    let dpu_machine_id1 =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim1.config).await).unwrap();
    let host_machine_id1 =
        try_parse_machine_id(&create_host_machine(&env, &host_sim1.config, &dpu_machine_id1).await)
            .unwrap();
    let dpu_machine_id2 =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim2.config).await).unwrap();
    let host_machine_id2 =
        try_parse_machine_id(&create_host_machine(&env, &host_sim2.config, &dpu_machine_id2).await)
            .unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let machine_update = DpuMachineUpdate {
        host_machine_id: host_machine_id1.clone(),
        dpu_machine_id: dpu_machine_id1,
        firmware_version: "1".to_owned(),
        product_name: "product_x".to_owned(),
    };

    let reference = &DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
        from: "x".to_owned(),
        to: "y".to_owned(),
    });

    MachineUpdateManager::put_machine_in_maintenance(&mut txn, &machine_update, reference)
        .await
        .unwrap();

    Machine::set_maintenance_mode(
        &mut txn,
        &host_machine_id2,
        &MaintenanceMode::On {
            reference: "testing".to_owned(),
        },
    )
    .await
    .unwrap();

    Machine::set_maintenance_mode(
        &mut txn,
        &dpu_machine_id2,
        &MaintenanceMode::On {
            reference: "testing".to_owned(),
        },
    )
    .await
    .unwrap();

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    let machines = MachineUpdateManager::get_machines_in_maintenance(&mut txn)
        .await
        .unwrap();

    assert_eq!(machines.len(), 1);
    assert_eq!(machines.iter().next().unwrap(), &host_machine_id1);

    Ok(())
}
