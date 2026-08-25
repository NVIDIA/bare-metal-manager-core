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

use std::sync::Arc;
use std::time::Duration;

use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::io::PowerShelfStateControllerIO;
use carbide_test_harness::prelude::*;
use model::power_shelf::PowerShelfConfig;
use model::test_support::power_shelf_config;
use state_controller::config::IterationConfig;
use state_controller::controller::StateController;
use tokio_util::sync::CancellationToken;
use tonic::Request;

use crate::common::{mark_power_shelf_as_deleted, services_without_component_manager};

#[sqlx_test]
async fn test_power_shelf_deletion_with_state_controller(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool.clone()).build().await;

    // Create a power shelf
    let power_shelf_id = env
        .create_power_shelf(PowerShelfConfig {
            capacity: Some(5000),
            ..power_shelf_config("Deletion with State Controller Test Power Shelf")
        })
        .await
        .id;

    // Start the state controller
    let power_shelf_handler = Arc::new(PowerShelfStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api().work_lock_manager_handle())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(services_without_component_manager(&pool, false).into())
        .state_handler(power_shelf_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    // Walk through state machine
    for _ in 0..20 {
        controller.run_single_iteration().await;
    }

    let power_shelf = env
        .api()
        .find_power_shelves_by_ids(Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![power_shelf_id],
        }))
        .await?
        .into_inner()
        .power_shelves
        .remove(0);
    assert_eq!(
        power_shelf.controller_state,
        "{\"state\":\"ready\"}".to_string()
    );

    // Mark the power shelf as deleted
    let mut txn = env.db_txn().await;
    mark_power_shelf_as_deleted(txn.as_mut(), &power_shelf_id).await?;
    txn.commit().await?;

    // Walk through state machine
    for _ in 0..20 {
        controller.run_single_iteration().await;
    }

    // Verify that the DB object is gone
    let power_shelves = env
        .api()
        .find_power_shelves_by_ids(Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![power_shelf_id],
        }))
        .await?
        .into_inner()
        .power_shelves;
    assert!(power_shelves.is_empty());

    Ok(())
}
