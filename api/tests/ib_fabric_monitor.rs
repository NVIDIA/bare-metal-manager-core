/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide::ib_fabric_monitor::IbFabricMonitor;

mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_ib_fabric_monitor(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let monitor = IbFabricMonitor::new(
        env.config.ib_fabric_monitor.clone(),
        env.test_meter.meter(),
        env.ib_fabric_manager.clone(),
    );

    monitor.run_single_iteration().await.unwrap();
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_fabrics_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_ufm_version_count")
            .unwrap(),
        r#"{fabric="ib_default",version="mock_ufm_1.0"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_fabric_error_count"),
        None
    );

    Ok(())
}
