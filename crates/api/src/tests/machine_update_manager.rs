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
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use common::api_fixtures::create_test_env;
use figment::Figment;
use figment::providers::{Format, Toml};
use model::dpu_machine_update::DpuMachineUpdate;
use model::machine::ManagedHostStateSnapshot;
use model::machine_update_module::{
    AutomaticFirmwareUpdateReference, DpuReprovisionInitiator, HOST_UPDATE_HEALTH_REPORT_SOURCE,
};
use sqlx::PgConnection;

use crate::CarbideResult;
use crate::cfg::file::CarbideConfig;
use crate::machine_update_manager::MachineUpdateManager;
use crate::machine_update_manager::machine_update_module::{
    MachineUpdateModule, create_host_update_health_report,
};
use crate::tests::common;
use crate::tests::common::api_fixtures::create_managed_host;

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
    let (_, dpu_machine_id) = create_managed_host(&env).await.into();

    let config: Arc<CarbideConfig> = Arc::new(
        Figment::new()
            .merge(Toml::file(format!("{TEST_DATA_DIR}/full_config.toml")))
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
        env.api.work_lock_manager_handle.clone(),
    );

    machine_update_manager.run_single_iteration().await?;

    assert_eq!(module1.get_start_updates_called(), 1);
    assert_eq!(module2.get_start_updates_called(), 0);

    assert_eq!(module1.get_clear_completed_updates_called(), 1);
    assert_eq!(module2.get_clear_completed_updates_called(), 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_machine_update_markers(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    create_managed_host(&env).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let machine_update = DpuMachineUpdate {
        host_machine_id,
        dpu_machine_id,
        firmware_version: "1".to_owned(),
    };

    let reference = &DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
        from: "x".to_owned(),
        to: "y".to_owned(),
    });

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
    let work_lock_manager_handle = db::work_lock_manager::start(pool.clone(), Default::default())
        .await
        .unwrap();

    let mut config: Arc<CarbideConfig> = Arc::new(
        Figment::new()
            .merge(Toml::file(format!("{TEST_DATA_DIR}/full_config.toml")))
            .extract()
            .unwrap(),
    );

    Arc::get_mut(&mut config)
        .unwrap()
        .machine_update_run_interval = Some(1);
    let update_manager = MachineUpdateManager::new_with_modules(
        pool,
        config,
        vec![test_module.clone()],
        work_lock_manager_handle,
    );

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
    let (host_machine_id1, dpu_machine_id1) = create_managed_host(&env).await.into();
    let (host_machine_id2, _dpu_machine_id2) = create_managed_host(&env).await.into();

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

    // Second Machine has a health report, but with an irrelevant alert
    let health_override_2 = health_report::HealthReport {
        source: "host-update".to_string(),
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![health_report::HealthProbeAlert {
            id: "should_get_ignored".parse().unwrap(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: "Test".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_allocations(),
                health_report::HealthAlertClassification::suppress_external_alerting(),
            ],
        }],
    };

    db::machine::insert_health_report_override(
        &mut txn,
        &host_machine_id2,
        health_report::OverrideMode::Merge,
        &health_override_2,
        false,
    )
    .await?;

    db::machine::trigger_dpu_reprovisioning_request(&host_machine_id1, &mut txn, "test", true)
        .await?;
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
    reference: &model::machine_update_module::DpuReprovisionInitiator,
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
