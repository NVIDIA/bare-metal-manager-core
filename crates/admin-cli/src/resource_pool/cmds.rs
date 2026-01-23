/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::fs;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge as forgerpc;
use prettytable::{Table, row};

use super::args::GrowResourcePool;
use crate::rpc::ApiClient;

pub async fn list(api_client: &ApiClient) -> CarbideCliResult<()> {
    let response = api_client.0.admin_list_resource_pools().await?;
    if response.pools.is_empty() {
        println!("No resource pools defined");
        return Err(CarbideCliError::Empty);
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
                "{} ({:.0}%)",
                pool.allocated,
                pool.allocated as f64 / pool.total as f64 * 100.0
            ),
        ]);
    }
    table.printstd();
    Ok(())
}

pub async fn grow(data: &GrowResourcePool, api_client: &ApiClient) -> CarbideCliResult<()> {
    let defs = fs::read_to_string(&data.filename)?;
    let rpc_req = forgerpc::GrowResourcePoolRequest { text: defs };
    api_client.0.admin_grow_resource_pool(rpc_req).await?;
    Ok(())
}
