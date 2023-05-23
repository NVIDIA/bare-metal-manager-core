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
use std::fs::read_to_string;

use ::rpc::forge as forgerpc;
use prettytable::{row, Table};
use serde::Deserialize;
use tracing::info;

use super::CarbideCliResult;
use crate::{rpc, Config};

/// Create or edit the resource pools, making them match the given toml file
/// Does not currently delete pools that were removed from the file.
pub async fn define_all_from(filename: &str, api_config: Config) -> CarbideCliResult<()> {
    let defs = read_to_string(filename)?;
    let table: toml::Table = defs.parse()?;
    for (name, def) in table {
        let d: ResourcePoolDef = def.try_into()?;

        let rpc_type: forgerpc::ResourcePoolType = d.pool_type.into();
        let rpc_req = forgerpc::DefineResourcePoolRequest {
            name: name.to_string(),
            pool_type: rpc_type.into(),
            ranges: d.ranges.into_iter().map(|r| r.into()).collect(),
        };
        let _ = rpc::define_resource_pool(rpc_req, api_config.clone()).await?;
        info!("Pool {name} populated.");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ResourcePoolDef {
    ranges: Vec<Range>,
    #[serde(rename = "type")]
    pool_type: ResourcePoolType,
}

#[derive(Debug, Deserialize)]
struct Range {
    start: String,
    end: String,
}

impl From<Range> for forgerpc::Range {
    fn from(r: Range) -> Self {
        Self {
            start: r.start,
            end: r.end,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ResourcePoolType {
    Ipv4,
    Integer,
}

impl From<ResourcePoolType> for forgerpc::ResourcePoolType {
    fn from(r: ResourcePoolType) -> Self {
        match r {
            ResourcePoolType::Ipv4 => Self::Ipv4,
            ResourcePoolType::Integer => Self::Integer,
        }
    }
}

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
