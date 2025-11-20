/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::tests::common::api_fixtures::create_test_env;

#[tokio::test]
async fn test_switch_controller_integration() {
    // Create a test environment
    let pool = sqlx_test::new_pool("postgresql://localhost/carbide_test").await;
    let env = create_test_env(pool).await;

    // Verify that the switch controller is available
    assert!(env.switch_controller.lock().await.is_some());

    // Run a switch controller iteration (should not panic)
    env.run_switch_controller_iteration().await;

    // Test the conditional iteration method
    let mut iteration_count = 0;
    env.run_switch_controller_iteration_until_condition(5, || {
        iteration_count += 1;
        iteration_count >= 3 // Stop after 3 iterations
    })
    .await;

    assert_eq!(iteration_count, 3);
}
