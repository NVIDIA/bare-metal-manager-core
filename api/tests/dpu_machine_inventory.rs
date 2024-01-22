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
use carbide::model::machine::machine_id;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_create_inventory(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        machine_id::try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await)
            .unwrap();

    let machine_result = env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await;

    assert_eq!(machine_result.machines.len(), 1);

    assert_eq!(
        machine_result.machines[0].inventory,
        Some(rpc::MachineInventory {
            components: vec![
                rpc::MachineInventorySoftwareComponent {
                    name: "doca-hbn".to_string(),
                    version: "1.5.0-doca2.2.0".to_string(),
                    url: "nvcr.io/nvidia/doca/".to_string(),
                },
                rpc::MachineInventorySoftwareComponent {
                    name: "doca-telemetry".to_string(),
                    version: "1.14.2-doca2.2.0".to_string(),
                    url: "nvcr.io/nvidia/doca/".to_string(),
                },
            ]
        })
    );

    Ok(())
}
