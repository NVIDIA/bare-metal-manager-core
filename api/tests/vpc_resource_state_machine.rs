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
use log::LevelFilter;

use carbide::db::vpc_resource_leaf::NewVpcResourceLeaf;
use carbide::CarbideError;

const FIXTURE_CREATED_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_vpc"))]
async fn vpc_resource_state_machine_advance_from_db_events(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(FIXTURE_CREATED_MACHINE_ID)
        .persist(&mut txn)
        .await?;

    txn.commit().await.unwrap();
    let mut txn = pool.begin().await?;

    leaf.advance(&mut txn, &rpc::VpcResourceStateMachineInput::Submit)
        .await
        .unwrap();
    leaf.advance(&mut txn, &rpc::VpcResourceStateMachineInput::Accept)
        .await
        .unwrap();
    leaf.advance(&mut txn, &rpc::VpcResourceStateMachineInput::Wait)
        .await
        .unwrap();
    leaf.advance(&mut txn, &rpc::VpcResourceStateMachineInput::VpcSuccess)
        .await
        .unwrap();

    let state = leaf.current_state(&mut txn).await.unwrap();

    assert!(matches!(
        state,
        carbide::db::vpc_resource_state::VpcResourceState::Ready
    ));

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn vpc_resource_state_machine_fail_state(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let leaf = NewVpcResourceLeaf::new(FIXTURE_CREATED_MACHINE_ID)
        .persist(&mut txn)
        .await
        .expect("Unable to create VPC Leaf REsource");

    txn.commit().await.unwrap();
    let mut txn = pool.begin().await?;

    leaf.advance(&mut txn, &rpc::VpcResourceStateMachineInput::Fail)
        .await?;

    let state = leaf.current_state(&mut txn).await?;

    assert!(matches!(
        state,
        carbide::db::vpc_resource_state::VpcResourceState::Broken
    ));

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn vpc_resource_test_fsm_invalid_advance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let vpc_leaf = NewVpcResourceLeaf::new(FIXTURE_CREATED_MACHINE_ID)
        .persist(&mut txn)
        .await?;

    let state = vpc_leaf.current_state(&mut txn).await?;

    assert!(matches!(
        state,
        carbide::db::vpc_resource_state::VpcResourceState::New
    ));

    assert!(matches!(
        vpc_leaf
            .advance(&mut txn, &rpc::VpcResourceStateMachineInput::VpcSuccess)
            .await
            .unwrap_err(),
        CarbideError::InvalidState { .. }
    ));

    Ok(())
}
