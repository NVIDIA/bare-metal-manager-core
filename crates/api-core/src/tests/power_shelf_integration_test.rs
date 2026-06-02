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

use crate::tests::common::api_fixtures::create_test_env;

#[tokio::test]
async fn test_power_shelf_controller_integration() {
    // Create a test environment
    let pool = sqlx_test::new_pool("postgresql://localhost/carbide_test").await;
    let env = create_test_env(pool).await;

    // Verify that the power shelf controller is available
    assert!(env.power_shelf_controller.lock().await.is_some());

    // Run a power shelf controller iteration (should not panic)
    env.run_power_shelf_controller_iteration().await;

    // Test the conditional iteration method
    let mut iteration_count = 0;
    env.run_power_shelf_controller_iteration_until_condition(5, || {
        iteration_count += 1;
        iteration_count >= 3 // Stop after 3 iterations
    })
    .await;

    assert_eq!(iteration_count, 3);
}
