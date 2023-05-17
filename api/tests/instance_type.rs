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
use carbide::db::instance_type::{
    DeactivateInstanceType, InstanceType, NewInstanceType, UpdateInstanceType,
};

mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test]
async fn test_instance_type_crud(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: Result<InstanceType, _> = NewInstanceType {
        short_name: "integration_test".to_string(),
        description: "integration_test_description".to_string(),
        active: true,
    }
    .persist(&mut txn)
    .await;

    let unwrapped = &segment.unwrap();

    let _updated_type = UpdateInstanceType {
        id: unwrapped.id,
        short_name: format!("{0}_updated", unwrapped.short_name).to_string(),
        description: format!("{0}_updated", unwrapped.description).to_string(),
        active: true,
    }
    .update(&mut txn)
    .await;

    let _deleted_type = DeactivateInstanceType { id: unwrapped.id }
        .deactivate(&mut txn)
        .await;

    txn.commit().await.unwrap();
}
