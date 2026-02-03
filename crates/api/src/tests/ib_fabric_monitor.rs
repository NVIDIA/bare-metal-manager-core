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
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    env.run_ib_fabric_monitor_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_fabrics_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machine_ib_status_updates_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_ufm_version_count")
            .unwrap(),
        r#"{fabric="default",version="mock_ufm_1.0"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_fabric_error_count"),
        None
    );
    // The default partition is found
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_ufm_partitions_count")
            .unwrap(),
        r#"{fabric="default"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_iteration_latency_milliseconds_count")
            .unwrap(),
        r#"1"#
    );

    // The fabric is configured securely
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_allow_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );

    // Set the default partition to full membership and test again
    // We now except the fabric to be reported as insecure
    env.ib_fabric_manager
        .get_mock_manager()
        .set_default_partition_membership(model::ib::IBPortMembership::Full);
    env.run_ib_fabric_monitor_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_allow_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );

    Ok(())
}
