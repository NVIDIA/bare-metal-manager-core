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

pub mod common;
use carbide::{db::bmc_machine::BmcMachine, CarbideError};
use common::api_fixtures::{create_test_env, dpu::dpu_discover_bmc_dhcp};

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn create_bmc_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let machine_interface_id = dpu_discover_bmc_dhcp(&env).await;
    let mut txn = pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin", e))?;

    let mut bmc_machines = BmcMachine::list_bmc_machines(&mut txn).await?;
    assert!(!bmc_machines.is_empty());
    let bmc_machine_id = bmc_machines.remove(0);
    let bmc_machine = BmcMachine::get_by_id(&mut txn, bmc_machine_id).await?;
    assert!(bmc_machine.machine_interface_id.to_string() == machine_interface_id.to_string());

    Ok(())
}
