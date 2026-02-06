/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ::rpc::forge as rpc;
use common::api_fixtures::dpu::{TEST_DOCA_HBN_VERSION, TEST_DOCA_TELEMETRY_VERSION};
use common::api_fixtures::{create_managed_host, create_test_env};

use crate::tests::common;

#[crate::sqlx_test]
async fn test_create_inventory(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let dpu_machine = create_managed_host(&env).await.dpu().rpc_machine().await;

    assert_eq!(
        dpu_machine.inventory,
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
