use rpc::MachineId;
use rpc::forge::forge_server::Forge;
use rpc::forge::{MaintenanceOperation, MaintenanceRequest, PowerOptionUpdateRequest};

/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};

use crate::db::power_manager::{PowerOptions, PowerState};

#[crate::sqlx_test]
async fn test_power_manager_create_entry_on_host_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
    let power_entry = PowerOptions::get_all(&mut txn).await?;
    assert!(power_entry.is_empty());
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await?;
    let power_entry = PowerOptions::get_all(&mut txn).await?;

    assert_eq!(power_entry.len(), 1);
    assert_eq!(power_entry[0].host_id, host_machine_id);
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    txn.rollback().await?;

    env.api
        .set_maintenance(tonic::Request::new(MaintenanceRequest {
            operation: MaintenanceOperation::Enable as i32,
            host_id: Some(MachineId {
                id: host_machine_id.to_string(),
            }),
            reference: Some("testing".to_string()),
        }))
        .await?;

    env.api
        .update_power_option(tonic::Request::new(PowerOptionUpdateRequest {
            machine_id: Some(MachineId {
                id: host_machine_id.to_string(),
            }),
            power_state: rpc::forge::PowerState::Off as i32,
        }))
        .await?;

    let mut txn = env.pool.begin().await?;
    let power_entry = PowerOptions::get_all(&mut txn).await?;

    assert_eq!(power_entry.len(), 1);
    assert_eq!(power_entry[0].desired_power_state, PowerState::Off);
    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_manager_update_fail_since_no_maintenance_set(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
    let power_entry = PowerOptions::get_all(&mut txn).await?;
    assert!(power_entry.is_empty());
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await?;
    let power_entry = PowerOptions::get_all(&mut txn).await?;

    assert_eq!(power_entry.len(), 1);
    assert_eq!(power_entry[0].host_id, host_machine_id);
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    txn.rollback().await?;

    let res = env
        .api
        .update_power_option(tonic::Request::new(PowerOptionUpdateRequest {
            machine_id: Some(MachineId {
                id: host_machine_id.to_string(),
            }),
            power_state: rpc::forge::PowerState::Off as i32,
        }))
        .await;

    assert!(res.is_err());
    assert_eq!(
        res.map_err(|x| x.message().to_string()).err(),
        Some(
            "Machine must have a 'Maintenance' Health Alert with 'SupressExternalAlerting' classification.".to_string()
        )
    );

    Ok(())
}
