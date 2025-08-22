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

use ::rpc::forge as rpc;
use common::api_fixtures::{
    create_managed_host, create_test_env,
    dpu::{TEST_DOCA_HBN_VERSION, TEST_DOCA_TELEMETRY_VERSION},
};

use crate::tests::common;

#[crate::sqlx_test]
async fn test_create_inventory(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    let dpu_machine_id = create_managed_host(&env).await.into_dpu();

    let machine_result = env.find_machines(dpu_machine_id.into(), None, true).await;

    assert_eq!(machine_result.machines.len(), 1);

    assert_eq!(
        machine_result.machines[0].inventory,
        Some(rpc::MachineInventory {
            components: vec![
                rpc::MachineInventorySoftwareComponent {
                    name: "doca-hbn".to_string(),
                    version: TEST_DOCA_HBN_VERSION.to_string(),
                    url: "nvcr.io/nvidia/doca/".to_string(),
                },
                rpc::MachineInventorySoftwareComponent {
                    name: "doca-telemetry".to_string(),
                    version: TEST_DOCA_TELEMETRY_VERSION.to_string(),
                    url: "nvcr.io/nvidia/doca/".to_string(),
                },
            ]
        })
    );

    Ok(())
}
