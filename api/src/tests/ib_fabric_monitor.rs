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
use crate::ib_fabric_monitor::IbFabricMonitor;

use crate::cfg::file::IBFabricConfig;
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;

#[crate::sqlx_test]
async fn test_ib_fabric_monitor(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let monitor = IbFabricMonitor::new(
        env.config.ib_fabric_monitor.clone(),
        env.config.ib_fabrics.clone(),
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
        r#"{fabric="default",version="mock_ufm_1.0"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_fabric_error_count"),
        None
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_ufm_partitions_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );

    Ok(())
}
