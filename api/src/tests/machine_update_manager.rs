use crate::{
    machine_update_manager::machine_update_module::{
        HOST_UPDATE_HEALTH_REPORT_SOURCE, create_host_update_health_report,
    },
    model::machine::ManagedHostStateSnapshot,
    tests::common,
};

use crate::tests::common::api_fixtures::create_managed_host;
use crate::{
    CarbideResult,
    cfg::file::CarbideConfig,
    db,
    db::{dpu_machine_update::DpuMachineUpdate, machine::MaintenanceMode},
    machine_update_manager::{
        MachineUpdateManager,
        machine_update_module::{
            AutomaticFirmwareUpdateReference, DpuReprovisionInitiator, MachineUpdateModule,
        },
    },
};
use async_trait::async_trait;
use common::api_fixtures::create_test_env;
use figment::{
    Figment,
    providers::{Format, Toml},
};
use forge_uuid::machine::MachineId;
use sqlx::{PgConnection, Row};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

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
    async fn get_updates_in_progress(
        &self,
        _txn: &mut PgConnection,
    ) -> CarbideResult<HashSet<MachineId>> {
        Ok(self.updates_in_progress.clone().into_iter().collect())
    }

    async fn start_updates(
        &self,
        _txn: &mut PgConnection,
        _available_updates: i32,
        _updating_machines: &HashSet<MachineId>,
        _snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> CarbideResult<HashSet<MachineId>> {
        if let Ok(mut guard) = self.start_updates_called.lock() {
            (*guard) += 1;
        }
        Ok(self.updates_started.clone())
    }

    async fn clear_completed_updates(&self, _txn: &mut PgConnection) -> CarbideResult<()> {
        if let Ok(mut guard) = self.clear_completed_updates_called.lock() {
            (*guard) += 1;
        }

        Ok(())
    }

    async fn update_metrics(
        &self,
        _txn: &mut PgConnection,
        _snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) {
    }
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

#[crate::sqlx_test]
async fn test_max_outstanding_updates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    create_managed_host(&env).await;
    let (_, dpu_machine_id) = create_managed_host(&env).await;

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

#[crate::sqlx_test]
async fn test_put_machine_in_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    create_managed_host(&env).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let machine_update = DpuMachineUpdate {
        host_machine_id,
        dpu_machine_id,
        firmware_version: "1".to_owned(),
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

#[crate::sqlx_test]
async fn test_remove_machine_update_markers(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    create_managed_host(&env).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let machine_update = DpuMachineUpdate {
        host_machine_id,
        dpu_machine_id,
        firmware_version: "1".to_owned(),
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
    let (count,) = sqlx::query_as::<_, (i32,)>(&query)
        .fetch_one(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // the dpu and host are put in maintenance
    assert_eq!(count, 2);

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    MachineUpdateManager::remove_machine_update_markers(&mut txn, &machine_update)
        .await
        .unwrap();

    let (count,) = sqlx::query_as::<_, (i32,)>(&query)
        .fetch_one(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(count, 0);

    // Apply health override
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    add_host_update_alert(&mut txn, &machine_update, reference).await?;
    txn.commit().await.unwrap();

    // Check that health override gets removed
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");
    MachineUpdateManager::remove_machine_update_markers(&mut txn, &machine_update)
        .await
        .unwrap();

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
    txn.commit().await.unwrap();

    Ok(())
}

#[crate::sqlx_test()]
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

#[crate::sqlx_test]
async fn test_get_updating_machines(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id1, dpu_machine_id1) = create_managed_host(&env).await;
    let (host_machine_id2, dpu_machine_id2) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Failed to create transaction");

    let machine_update = DpuMachineUpdate {
        host_machine_id: host_machine_id1,
        dpu_machine_id: dpu_machine_id1,
        firmware_version: "1".to_owned(),
    };

    let reference = &DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
        from: "x".to_owned(),
        to: "y".to_owned(),
    });

    add_host_update_alert(&mut txn, &machine_update, reference).await?;
    // Host 2 should be ignored due to the mismatching reference
    db::machine::set_maintenance_mode(
        &mut txn,
        &host_machine_id2,
        &MaintenanceMode::On {
            reference: "testing".to_owned(),
        },
    )
    .await
    .unwrap();

    db::machine::set_maintenance_mode(
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
    let machines = MachineUpdateManager::get_updating_machines(&mut txn)
        .await
        .unwrap();

    assert_eq!(machines.len(), 1);
    assert_eq!(machines.iter().next().unwrap(), &host_machine_id1);

    Ok(())
}

/// Manually adds the HostUpdateInProgress health alert to a Machine
async fn add_host_update_alert(
    txn: &mut PgConnection,
    machine_update: &DpuMachineUpdate,
    reference: &crate::machine_update_manager::machine_update_module::DpuReprovisionInitiator,
) -> CarbideResult<()> {
    let health_override = create_host_update_health_report(
        Some("DpuFirmware".to_string()),
        reference.to_string(),
        false,
    );

    db::machine::insert_health_report_override(
        txn,
        &machine_update.host_machine_id,
        health_report::OverrideMode::Merge,
        &health_override,
        false,
    )
    .await?;

    Ok(())
}
