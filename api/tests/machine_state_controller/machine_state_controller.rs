/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use carbide::{
    db::machine_topology::MachineTopology,
    machine_state_controller::{
        controller::MachineStateController,
        snapshot_loader::DbMachineStateSnapshotLoader,
        state_handler::{
            MachineStateHandler, MachineStateHandlerContext, MachineStateHandlerError,
        },
    },
    model::{hardware_info::HardwareInfo, machine::MachineStateSnapshot},
};

#[derive(Debug, Default, Clone)]
pub struct TestMachineStateHandler {
    pub count: Arc<AtomicUsize>,
    /// We count for every start digit of a machine ID how often
    /// the handler was called
    pub start_digit_count: [Arc<AtomicUsize>; 10],
}

#[async_trait::async_trait]
impl MachineStateHandler for TestMachineStateHandler {
    async fn handle_machine_state(
        &self,
        state: &mut MachineStateSnapshot,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        let id = state.machine_id.to_string();
        let start_digit = id.as_bytes()[0];
        let idx = start_digit - b'0';
        self.start_digit_count[idx as usize].fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }
}

#[sqlx::test]
async fn iterate_over_all_machines(pool: sqlx::PgPool) -> sqlx::Result<()> {
    // Insert some machines
    // TODO: This should use API functions
    let mut txn = pool.begin().await.unwrap();
    let machine_ids = &[
        "52dfecb4-8070-4f4b-ba95-f66d0f51fd98",
        "72dfecb4-8070-4f4b-ba95-f66d0f51fd98",
        "92dfecb4-8070-4f4b-ba95-f66d0f51fd98",
        "93dfecb4-8070-4f4b-ba95-f66d0f51fd98",
    ];
    for id in &machine_ids[..] {
        sqlx::query(&format!(
            "INSERT INTO machines (id) VALUES ('{}') RETURNING *",
            id
        ))
        .execute(&mut txn)
        .await
        .unwrap();

        let hw_info = HardwareInfo {
            network_interfaces: vec![],
            cpus: vec![],
            block_devices: vec![],
            machine_type: "x86_64".to_string(),
        };

        MachineTopology::create(&mut txn, &uuid::Uuid::try_from(*id).unwrap(), &hw_info)
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();

    let machine_handler = Arc::new(TestMachineStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let expected_iterations = (TEST_TIME.as_millis() / ITERATION_TIME.as_millis()) as f64;
    let expected_total_count = expected_iterations * machine_ids.len() as f64;

    // We build multiple state controllers. But since only one should act at a time,
    // the count should still not increase
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(
            MachineStateController::builder()
                .iteration_time(Duration::from_millis(100))
                .database(pool.clone())
                .snapshot_loader(Box::new(DbMachineStateSnapshotLoader::default()))
                .state_handler(machine_handler.clone())
                .build()
                .unwrap(),
        );
    }

    tokio::time::sleep(TEST_TIME).await;
    drop(handles);
    // Wait some extra time until the controller background task shuts down
    tokio::time::sleep(Duration::from_secs(1)).await;

    let count = machine_handler.count.load(Ordering::SeqCst) as f64;
    assert!(
        count > 0.75 * expected_total_count && count < 1.25 * expected_total_count,
        "Expected count of {}, but got {}",
        expected_total_count,
        count
    );

    for i in 0..10 {
        let count = machine_handler.start_digit_count[i].load(Ordering::SeqCst);
        let occurences: usize = machine_ids
            .iter()
            .map(|id| {
                let first_char = id.to_string().as_bytes()[0];
                let idx = (first_char - b'0') as usize;
                if i == idx {
                    1
                } else {
                    0
                }
            })
            .sum();

        if occurences != 0 {
            let expected_count = expected_iterations * occurences as f64;
            assert!(
                (count as f64) > 0.75 * expected_count && (count as f64) < 1.25 * expected_count,
                "Expected count of {} for number {}, but got {}",
                expected_count,
                i,
                count
            );
        } else {
            assert_eq!(count, 0, "Expected count of 0, but got {}", count);
        }
    }

    Ok(())
}
