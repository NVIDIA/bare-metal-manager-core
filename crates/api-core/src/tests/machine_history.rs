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
use common::api_fixtures::{create_managed_host, create_test_env};
use config_version::ConfigVersion;
use db::{self};
use model::hardware_info::HardwareInfo;
use model::machine::ManagedHostState;
use model::machine::machine_id::from_hardware_info;
use model::state_history::StateHistoryRecord;
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::create_dpu_machine;

#[crate::sqlx_test]
async fn test_machine_state_history(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let dpu_machine_id_string = dpu_machine_id.to_string();

    let expected_initial_states_json = serde_json::json!([
        {"state": "created"},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "initializing"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "configuring"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "enablershim"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"count": 0, "dpudiscoverystate": "enablesecureboot", "enable_secure_boot_state": {"disablesecurebootstate": "checksecurebootstatus"}}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"count": 0, "dpudiscoverystate": "enablesecureboot", "enable_secure_boot_state": {"disablesecurebootstate": "setsecureboot"}}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"count": 0, "dpudiscoverystate": "enablesecureboot", "enable_secure_boot_state": {"disablesecurebootstate": "rebootdpu", "reboot_count": 0}}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"count": 0, "dpudiscoverystate": "enablesecureboot", "enable_secure_boot_state": {"disablesecurebootstate": "rebootdpu", "reboot_count": 1}}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"count": 1, "dpudiscoverystate": "enablesecureboot", "enable_secure_boot_state": {"disablesecurebootstate": "checksecurebootstatus"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "installdpuos", "substate": {"installdpuosstate": "installingbfb"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "installdpuos", "substate": {"installdpuosstate": "waitforinstallcomplete", "progress": "0", "task_id": "0"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "init"}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingforplatformpowercycle", "substate": {"state": "off"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingforplatformpowercycle", "substate": {"state": "on"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingforplatformconfiguration"}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "pollingbiossetup"}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingfornetworkconfig"}}}},
        {"state": "hostinit", "machine_state": {"state": "enableipmioverlan"}},
        {"state": "hostinit", "machine_state": {"state": "waitingforplatformconfiguration", "retry_count": 0}},
        {"state": "hostinit", "machine_state": {"state": "pollingbiossetup", "retry_count": 0}},
        {"state": "hostinit", "machine_state": {"state": "setbootorder", "set_boot_order_info": {"retry_count": 0, "set_boot_order_state": {"state": "setbootorder"}}}},
        {"state": "hostinit", "machine_state": {"state": "setbootorder", "set_boot_order_info": {"retry_count": 0, "set_boot_order_state": {"state": "checkbootorder"}}}},
        {"state": "hostinit", "machine_state": {"state": "measuring", "measuring_state": "waitingformeasurements"}},
        {"state": "hostinit", "machine_state": {"state": "spdmmeasuring", "spdm_measuring_state": "triggermeasurements"}},
        {"state": "hostinit", "machine_state": {"state": "waitingfordiscovery"}},
    ]);
    let expected_initial_states: Vec<serde_json::Value> =
        expected_initial_states_json.as_array().unwrap().clone();

    for machine_id in &[host_machine_id, dpu_machine_id] {
        let mut txn = env.pool.begin().await?;

        let machine = db::machine::find_one(
            txn.as_mut(),
            &dpu_machine_id,
            model::machine::machine_search_config::MachineSearchConfig {
                include_history: true,
                ..Default::default()
            },
        )
        .await?
        .unwrap();

        assert_eq!(
            json_history(&machine.history[..expected_initial_states.len()])?,
            expected_initial_states
        );

        let machine = db::machine::find_one(
            txn.as_mut(),
            &dpu_machine_id,
            model::machine::machine_search_config::MachineSearchConfig::default(),
        )
        .await?
        .unwrap();
        assert!(machine.history.is_empty());
        txn.commit().await?;

        // Check that RPC APIs returns the History if asked for
        // - FindMachinesById should do so if asked for it
        // - FindMachineStateHistories returns the expected history
        let rpc_machine = env
            .api
            .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![*machine_id],
                include_history: true,
            }))
            .await?
            .into_inner()
            .machines
            .remove(0);
        let rpc_history: Vec<serde_json::Value> = rpc_machine
            .events
            .into_iter()
            .map(|ev| serde_json::from_str::<serde_json::Value>(&ev.event))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states
        );

        let mut rpc_histories = env
            .api
            .find_machine_state_histories(tonic::Request::new(
                rpc::forge::MachineStateHistoriesRequest {
                    machine_ids: vec![*machine_id],
                },
            ))
            .await?
            .into_inner();
        assert_eq!(rpc_histories.histories.len(), 1);
        let rpc_history = rpc_histories
            .histories
            .remove(&machine_id.to_string())
            .unwrap();
        let rpc_history: Vec<serde_json::Value> = rpc_history
            .records
            .into_iter()
            .map(|ev| serde_json::from_str::<serde_json::Value>(&ev.event))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states
        );
    }

    // Check if older history entries get deleted

    let mut txn = env.pool.begin().await?;

    let machine = db::machine::find_one(
        txn.as_mut(),
        &host_machine_id,
        model::machine::machine_search_config::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    for _ in 1..300 {
        db::machine::advance(&machine, &mut txn, &ManagedHostState::Ready, None)
            .await
            .unwrap();
    }

    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let result = db::state_history::for_object(
        &mut txn,
        db::state_history::StateHistoryTableId::Machine,
        &host_machine_id,
    )
    .await
    .unwrap();

    // Count should not go beyond 250.
    assert_eq!(result.len(), 250);

    let machine = db::machine::find_one(
        txn.as_mut(),
        &host_machine_id,
        model::machine::machine_search_config::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    assert_eq!(machine.history.len(), 250);
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert!(!power_entry.is_empty());

    // Test whether history is retrievable for a forced deleted Machine
    env.api
        .admin_force_delete_machine(tonic::Request::new(
            ::rpc::forge::AdminForceDeleteMachineRequest {
                host_query: host_machine_id.to_string(),
                delete_interfaces: false,
                delete_bmc_interfaces: false,
                delete_bmc_credentials: false,
                allow_delete_with_orphaned_dpf_crds: false,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert!(env.find_machine(host_machine_id).await.is_empty());

    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert!(power_entry.is_empty());

    let mut rpc_histories = env
        .api
        .find_machine_state_histories(tonic::Request::new(
            rpc::forge::MachineStateHistoriesRequest {
                machine_ids: vec![host_machine_id],
            },
        ))
        .await?
        .into_inner();
    assert_eq!(rpc_histories.histories.len(), 1);
    let rpc_history = rpc_histories
        .histories
        .remove(&host_machine_id.to_string())
        .unwrap();

    assert!(!rpc_history.records.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_state_writers_lock_row_before_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();
    let machine = db::machine::find_one(
        &env.pool,
        &host_machine_id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("managed host should exist");

    // Hold the machine row while a second transaction starts a normal state
    // write. That writer must block before it reaches the history trigger's
    // per-object advisory lock.
    let mut blocker = env.pool.begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(blocker.as_mut())
        .await?;
    sqlx::query("SELECT id FROM machines WHERE id = $1 FOR UPDATE")
        .bind(host_machine_id)
        .fetch_one(blocker.as_mut())
        .await?;
    let independent_history_version =
        ConfigVersion::new(machine.current_version().version_nr() + 100);
    let writer_pool = env.pool.clone();
    let (writer_pid_tx, writer_pid_rx) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(async move {
        let mut txn = writer_pool.begin().await.unwrap();
        let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(txn.as_mut())
            .await
            .unwrap();
        writer_pid_tx.send(writer_pid).unwrap();
        db::machine::advance(&machine, txn.as_mut(), &ManagedHostState::Ready, None)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });
    let writer_pid = writer_pid_rx.await?;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting_on_row: bool = sqlx::query_scalar("SELECT $2 = ANY(pg_blocking_pids($1))")
                .bind(writer_pid)
                .bind(blocker_pid)
                .fetch_one(&env.pool)
                .await
                .unwrap();
            if waiting_on_row {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("machine state writer should block on the held machine row");

    // A history write in the row-owning transaction must remain possible. If
    // the other writer took history first, these two transactions deadlock.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        db::state_history::persist(
            blocker.as_mut(),
            db::state_history::StateHistoryTableId::Machine,
            &host_machine_id,
            &ManagedHostState::Ready,
            independent_history_version,
        ),
    )
    .await
    .expect("machine-row ownership should not be blocked by a later history writer")?;
    blocker.commit().await?;
    writer.await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_stable_id_sync_locks_machine_before_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let stable_machine_id = from_hardware_info(&HardwareInfo::from(&host_config))?;
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let mut txn = env.pool.begin().await?;
    let predicted_host = db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await?
        .expect("DPU should have a predicted host");
    txn.commit().await?;
    assert!(predicted_host.id.machine_type().is_predicted_host());

    // Fill retention so the next history insert must touch rows that a
    // concurrent stable-ID promotion would rename.
    let mut txn = env.pool.begin().await?;
    sqlx::query(
        "INSERT INTO machine_state_history (object_id, state, state_version) \
         SELECT $1, to_jsonb(sequence), $2 \
         FROM generate_series(1, 250) AS sequence",
    )
    .bind(predicted_host.id.to_string())
    .bind(ConfigVersion::initial())
    .execute(txn.as_mut())
    .await?;
    txn.commit().await?;

    // Hold the machine row and let stable-ID promotion reach that lock. A
    // correctly ordered promotion has not touched history yet, so this
    // transaction can complete a normal state write without deadlocking.
    let mut blocker = env.pool.begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(blocker.as_mut())
        .await?;
    sqlx::query("SELECT id FROM machines WHERE id = $1 FOR UPDATE")
        .bind(predicted_host.id)
        .fetch_one(blocker.as_mut())
        .await?;

    let rename_pool = env.pool.clone();
    let current_machine_id = predicted_host.id;
    let (rename_pid_tx, rename_pid_rx) = tokio::sync::oneshot::channel();
    let rename = tokio::spawn(async move {
        let mut txn = rename_pool.begin().await.unwrap();
        let rename_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(txn.as_mut())
            .await
            .unwrap();
        rename_pid_tx.send(rename_pid).unwrap();
        let renamed = db::machine::try_sync_stable_id_with_current_machine_id_for_host(
            txn.as_mut(),
            &Some(current_machine_id),
            &stable_machine_id,
        )
        .await
        .unwrap();
        assert_eq!(renamed, stable_machine_id);
        txn.commit().await.unwrap();
    });
    let rename_pid = rename_pid_rx.await?;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked_by_writer: bool =
                sqlx::query_scalar("SELECT $2 = ANY(pg_blocking_pids($1))")
                    .bind(rename_pid)
                    .bind(blocker_pid)
                    .fetch_one(&env.pool)
                    .await
                    .unwrap();
            if blocked_by_writer {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stable-ID promotion should block on the held machine row");

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        db::machine::advance(
            &predicted_host,
            blocker.as_mut(),
            &ManagedHostState::Ready,
            None,
        ),
    )
    .await
    .expect("machine state writing must not deadlock with stable-ID promotion")?;
    blocker.commit().await?;
    tokio::time::timeout(std::time::Duration::from_secs(10), rename)
        .await
        .expect("stable-ID promotion should finish after the state writer commits")?;

    let mut txn = env.pool.begin().await?;
    assert!(
        db::machine::find_one(
            txn.as_mut(),
            &predicted_host.id,
            model::machine::machine_search_config::MachineSearchConfig::default(),
        )
        .await?
        .is_none()
    );
    assert!(
        db::machine::find_one(
            txn.as_mut(),
            &stable_machine_id,
            model::machine::machine_search_config::MachineSearchConfig::default(),
        )
        .await?
        .is_some()
    );

    Ok(())
}

/// Check that we can handle old / unknown states in the history.
/// This allows us to change MachineState enum.
#[crate::sqlx_test]
async fn test_old_machine_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await?;

    let query = "INSERT INTO machine_state_history (object_id, state, state_version) VALUES ($1, $2::jsonb, $3)";
    sqlx::query(query)
        .bind(host_machine_id.to_string())
        .bind(r#"{"state": "hostinit", "machine_state": {"state": "nolongerarealstate"}}"#)
        .bind(ConfigVersion::initial())
        .execute(&mut *txn)
        .await?;

    let machine = db::machine::find_one(
        txn.as_mut(),
        &host_machine_id,
        model::machine::machine_search_config::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    let states = machine
        .history
        .into_iter()
        .map(|m| serde_json::from_str::<serde_json::Value>(&m.state))
        .rev()
        .take(2)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        serde_json::Value::Array(states).to_string(),
        serde_json::json!([
            {"state": "hostinit", "machine_state": {"state": "nolongerarealstate"}},
            {"state": "ready"},
        ])
        .to_string(),
    );

    Ok(())
}

fn json_history(history: &[StateHistoryRecord]) -> serde_json::Result<Vec<serde_json::Value>> {
    // // Check that version numbers are always incrementing by 1
    if !history.is_empty() {
        let first_version = history[0].state_version.version_nr();
        for (expected_version, entry) in ((first_version + 1)..).zip(&history[1..]) {
            assert_eq!(entry.state_version.version_nr(), expected_version);
        }
    }

    history
        .iter()
        .map(|h| serde_json::from_str::<serde_json::Value>(&h.state))
        .collect::<Result<Vec<_>, _>>()
}
