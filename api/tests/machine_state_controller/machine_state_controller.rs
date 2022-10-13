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

use carbide::machine_state_controller::{IterationHandler, MachineStateController};

#[derive(Debug, Default, Clone)]
pub struct TestIterationHandler {
    pub count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl IterationHandler for TestIterationHandler {
    async fn handle_iteration(&mut self, _txn: &mut sqlx::Transaction<sqlx::Postgres>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[sqlx::test]
async fn test_controller_iteration(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let handler = TestIterationHandler::default();
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let expected_count = (TEST_TIME.as_millis() / ITERATION_TIME.as_millis()) as f64;

    // We build multiple state controllers. But since only one should act at a time,
    // the count should still not increase
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(
            MachineStateController::builder()
                .iteration_time(Duration::from_millis(100))
                .database(pool.clone())
                .iteration_handler(Box::new(handler.clone()))
                .build()
                .unwrap(),
        );
    }

    tokio::time::sleep(TEST_TIME).await;
    drop(handles);
    // Wait some extra time until the controller background task shuts down
    tokio::time::sleep(Duration::from_secs(1)).await;

    let count = handler.count.load(Ordering::SeqCst) as f64;
    assert!(
        count > 0.75 * expected_count && count < 1.25 * expected_count,
        "Expected count of {}, but got {}",
        expected_count,
        count
    );

    Ok(())
}
