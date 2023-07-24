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
use ::rpc::forge as forgerpc;
use prettytable::{row, Table};

use super::CarbideCliResult;
use crate::{rpc, Config};

pub async fn list(api_config: Config) -> CarbideCliResult<()> {
    let response =
        rpc::list_resource_pools(forgerpc::ListResourcePoolsRequest {}, api_config.clone()).await?;
    if response.pools.is_empty() {
        println!("No resource pools defined");
        return Err(super::CarbideCliError::Empty);
    }

    let mut table = Table::new();
    table.set_titles(row!["Name", "Min", "Max", "Size", "Used"]);
    for pool in response.pools {
        table.add_row(row![
            pool.name,
            pool.min,
            pool.max,
            pool.total,
            format!(
                "{} ({}%)",
                pool.allocated,
                pool.allocated / pool.total * 100
            ),
        ]);
    }
    table.printstd();
    Ok(())
}
