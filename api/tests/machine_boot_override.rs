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
// use std::str::FromStr;

use carbide::db::machine_boot_override::MachineBootOverride;
use carbide::CarbideError;

pub mod common;
use common::api_fixtures::create_test_env;
use common::api_fixtures::dpu::dpu_discover_dhcp;
use common::api_fixtures::dpu::FIXTURE_DPU_MAC_ADDRESS;
use uuid::Uuid;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn only_one_custom_pxe_per_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let new_interface_id =
        Uuid::try_from(dpu_discover_dhcp(&env, FIXTURE_DPU_MAC_ADDRESS).await).unwrap();

    let mut txn = pool.begin().await?;

    let expected_pxe = Some("custom_pxe_string".to_string());
    let expected_user_data = Some("custom_user_data_string".to_string());

    MachineBootOverride::create(
        &mut txn,
        new_interface_id,
        expected_pxe.clone(),
        expected_user_data.clone(),
    )
    .await?
    .expect("Could not create custom pxe");

    let machine_boot_override = MachineBootOverride::find_optional(&mut txn, new_interface_id)
        .await
        .expect("Could not load custom boot")
        .unwrap();

    txn.commit().await.unwrap();

    assert_eq!(machine_boot_override.custom_pxe, expected_pxe);
    assert_eq!(machine_boot_override.custom_user_data, expected_user_data);

    let mut txn = pool.begin().await?;

    let output = MachineBootOverride::create(
        &mut txn,
        new_interface_id,
        Some("custom_pxe_string".to_string()),
        None,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(output, Err(CarbideError::DBError(_))));
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn confirm_null_fields(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let new_interface_id =
        Uuid::try_from(dpu_discover_dhcp(&env, FIXTURE_DPU_MAC_ADDRESS).await).unwrap();

    let mut txn = pool.begin().await?;

    MachineBootOverride::create(&mut txn, new_interface_id, None, None)
        .await?
        .expect("Could not create custom pxe");

    // ensure these stay Nones as we have code that will react to them not being None
    let machine_boot_override = MachineBootOverride::find_optional(&mut txn, new_interface_id)
        .await
        .expect("Could not load custom boot")
        .unwrap();

    txn.commit().await.unwrap();

    assert!(matches!(machine_boot_override.custom_pxe, None));
    assert!(matches!(machine_boot_override.custom_user_data, None));
    Ok(())
}
