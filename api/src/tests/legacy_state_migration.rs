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
use crate::tests::common;

use std::collections::HashMap;
use std::ops::DerefMut;

use crate::{
    db::{
        machine::{Machine, MachineSearchConfig},
        DatabaseError,
    },
    legacy::{
        self,
        states::machine::{migrate_machines, ManagedHostStateV1 as OldStates},
    },
    model::machine::{DpuDiscoveringState, DpuInitState, ManagedHostState, ReprovisionState},
};
use common::api_fixtures::{create_managed_host_multi_dpu, create_test_env};
use forge_uuid::machine::MachineId;
use sqlx::{Postgres, Transaction};

async fn update_host_state(
    txn: &mut Transaction<'_, Postgres>,
    state: legacy::states::machine::ManagedHostStateV1,
    machine_id: MachineId,
) {
    let query = "UPDATE machines SET controller_state=$1, machine_state_model_version=1 WHERE id=$2 RETURNING id";
    let _id: (String,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(state))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .unwrap();
}

async fn get_model_version(txn: &mut Transaction<'_, Postgres>, machine_id: &MachineId) -> i32 {
    let query = "SELECT machine_state_model_version from machines where id=$1";
    let id: (i32,) = sqlx::query_as(query)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .unwrap();

    id.0
}

async fn validate_all_machines(
    txn: &mut Transaction<'_, Postgres>,
    host_machine_id: MachineId,
    expected_state: ManagedHostState,
) {
    let host = Machine::find_one(txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let mut dpus = Machine::find_dpus_by_host_machine_id(txn, &host_machine_id)
        .await
        .unwrap();

    dpus.push(host);

    for machine in dpus {
        assert_eq!(
            machine.current_state(),
            expected_state,
            "Failed machine: {}",
            machine.id()
        );
    }
}

#[crate::sqlx_test]
async fn test_state_migration_1(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::DpuDiscoveringState {
            discovering_state: DpuDiscoveringState::Initializing,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }

    txn.rollback().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    let dpus = Machine::find_dpu_machine_ids_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(host.is_ok());
    validate_all_machines(
        &mut txn,
        host_machine_id,
        ManagedHostState::DpuDiscoveringState {
            dpu_states: crate::model::machine::DpuDiscoveringStates {
                states: dpus
                    .clone()
                    .into_iter()
                    .map(|dpu_id| (dpu_id, DpuDiscoveringState::Initializing))
                    .collect::<HashMap<MachineId, DpuDiscoveringState>>(),
            },
        },
    )
    .await;
    txn.rollback().await.unwrap();
}

#[crate::sqlx_test]
async fn test_state_migration_2(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::DPUNotReady {
            machine_state: legacy::states::machine::MachineState::Init,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }

    txn.rollback().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    let dpus = Machine::find_dpu_machine_ids_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(host.is_ok());
    validate_all_machines(
        &mut txn,
        host_machine_id,
        ManagedHostState::DPUInit {
            dpu_states: crate::model::machine::DpuInitStates {
                states: dpus
                    .clone()
                    .into_iter()
                    .map(|dpu_id| (dpu_id, DpuInitState::Init))
                    .collect::<HashMap<MachineId, DpuInitState>>(),
            },
        },
    )
    .await;
}

#[crate::sqlx_test]
async fn test_state_migration_2_1(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 2).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::DPUNotReady {
            machine_state: legacy::states::machine::MachineState::WaitingForPlatformConfiguration,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }

    assert_eq!(get_model_version(&mut txn, &host_machine_id).await, 1);
    txn.rollback().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    let dpus = Machine::find_dpu_machine_ids_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    assert_eq!(get_model_version(&mut txn, &host_machine_id).await, 2);
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(host.is_ok());
    validate_all_machines(
        &mut txn,
        host_machine_id,
        ManagedHostState::DPUInit {
            dpu_states: crate::model::machine::DpuInitStates {
                states: dpus
                    .clone()
                    .into_iter()
                    .map(|dpu_id| (dpu_id, DpuInitState::WaitingForPlatformConfiguration))
                    .collect::<HashMap<MachineId, DpuInitState>>(),
            },
        },
    )
    .await;
}

#[crate::sqlx_test]
async fn test_state_migration_2_fail(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::DPUNotReady {
            machine_state: legacy::states::machine::MachineState::Discovered,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }

    txn.rollback().await.unwrap();

    // No Update will take place.
    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }
}

#[crate::sqlx_test]
async fn test_state_migration_3(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::HostNotReady {
            machine_state: legacy::states::machine::MachineState::Init,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }

    txn.rollback().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(host.is_ok());
    validate_all_machines(
        &mut txn,
        host_machine_id,
        ManagedHostState::HostInit {
            machine_state: crate::model::machine::MachineState::Init,
        },
    )
    .await;
}

#[crate::sqlx_test]
async fn test_state_migration_4(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(&mut txn, OldStates::Ready, host_machine_id.clone()).await;

    txn.commit().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(host.is_ok());
    validate_all_machines(&mut txn, host_machine_id, ManagedHostState::Ready).await;
}

#[crate::sqlx_test]
async fn test_state_migration_5(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::Assigned {
            instance_state: legacy::states::machine::InstanceState::SwitchToAdminNetwork,
        },
        host_machine_id.clone(),
    )
    .await;

    assert_eq!(get_model_version(&mut txn, &host_machine_id).await, 1);

    txn.commit().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    let dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    assert_eq!(get_model_version(&mut txn, &host_machine_id).await, 2);
    txn.rollback().await.unwrap();

    assert!(host.is_ok());
    assert_eq!(
        host.unwrap().unwrap().current_state(),
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::SwitchToAdminNetwork,
        },
    );

    assert_eq!(
        dpus[0].current_state(),
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::SwitchToAdminNetwork,
        },
    );
}

#[crate::sqlx_test]
async fn test_state_migration_5_1(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::Assigned {
            instance_state: legacy::states::machine::InstanceState::DPUReprovision {
                reprovision_state:
                    crate::model::machine::ReprovisionState::WaitingForNetworkInstall,
            },
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    if let Err(DatabaseError {
        source: sqlx::Error::ColumnDecode { index, .. },
        ..
    }) = host
    {
        assert_eq!(index, "\"controller_state\"");
    } else {
        panic!("Unexpected value: {:?}", host);
    }

    txn.rollback().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpus = Machine::find_dpu_machine_ids_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    assert!(host.is_ok());
    validate_all_machines(
        &mut txn,
        host_machine_id,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: dpus
                        .clone()
                        .into_iter()
                        .map(|dpu_id| (dpu_id, ReprovisionState::WaitingForNetworkInstall))
                        .collect::<HashMap<MachineId, ReprovisionState>>(),
                },
            },
        },
    )
    .await;
}

#[crate::sqlx_test]
async fn test_state_migration_6(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::WaitingForCleanup {
            cleanup_state: crate::model::machine::CleanupState::HostCleanup,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    let dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    txn.rollback().await.unwrap();

    assert!(host.is_ok());
    assert_eq!(
        host.unwrap().unwrap().current_state(),
        ManagedHostState::WaitingForCleanup {
            cleanup_state: crate::model::machine::CleanupState::HostCleanup
        },
    );

    assert_eq!(
        dpus[0].current_state(),
        ManagedHostState::WaitingForCleanup {
            cleanup_state: crate::model::machine::CleanupState::HostCleanup
        },
    );
}

#[crate::sqlx_test]
async fn test_state_migration_7(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;

    let mut txn = env.pool.begin().await.unwrap();
    update_host_state(
        &mut txn,
        OldStates::DPUReprovision {
            reprovision_state: ReprovisionState::PowerDown,
        },
        host_machine_id.clone(),
    )
    .await;

    txn.commit().await.unwrap();

    migrate_machines(env.pool.clone()).await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default()).await;

    let dpus = Machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    txn.rollback().await.unwrap();

    assert!(host.is_ok());
    let mut txn = env.pool.begin().await.unwrap();
    validate_all_machines(
        &mut txn,
        host_machine_id,
        ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: dpus
                    .clone()
                    .into_iter()
                    .map(|dpu| (dpu.id().clone(), ReprovisionState::PowerDown))
                    .collect::<HashMap<MachineId, ReprovisionState>>(),
            },
        },
    )
    .await;
}
