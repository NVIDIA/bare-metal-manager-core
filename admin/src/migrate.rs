/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::process::Command;

use ::rpc::forge as forgerpc;
use color_eyre::eyre;
use color_eyre::eyre::WrapErr;
use serde::Deserialize;
use tracing::info;

use crate::Config;

pub async fn vpc(api_config: Config) -> eyre::Result<()> {
    migrate_pools(&api_config).await?;
    migrate_networks(&api_config).await
}

async fn migrate_pools(api_config: &Config) -> eyre::Result<()> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "configurationresourcepools",
            "-n",
            "forge-system",
            "-ojson",
        ])
        .output()
        .wrap_err("Is kubectl on PATH?")?;
    if !output.status.success() {
        return Err(eyre::eyre!(
            "Failed running 'kubectl get configurationresourcepools'. \nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    let pools: Pools = serde_json::from_slice(&output.stdout)?;
    for pool in pools.items {
        let name = pool.metadata.name;
        let rpc_type: forgerpc::ResourcePoolType = match pool.spec.r#type.as_str() {
            "ipv4" => forgerpc::ResourcePoolType::Ipv4,
            "integer" => forgerpc::ResourcePoolType::Integer,
            _ => {
                return Err(eyre::eyre!("Pool {name} invalid type {}", pool.spec.r#type));
            }
        };
        let r = &pool.spec.ranges[0];
        let (mut start, mut end) = (r.start.clone(), r.end.clone());
        if matches!(rpc_type, forgerpc::ResourcePoolType::Integer) {
            let (s_int, e_int): (u32, u32) = (start.parse().unwrap(), end.parse().unwrap());
            if s_int > e_int {
                (start, end) = (end, start);
            }
        }
        let rpc_range = forgerpc::Range { start, end };
        let rpc_req = forgerpc::DefineResourcePoolRequest {
            name: name.clone(),
            pool_type: rpc_type.into(),
            ranges: vec![rpc_range],
        };
        let _ = crate::rpc::define_resource_pool(rpc_req, api_config.clone()).await?;
        info!("Pool {name} populated.");
    }

    Ok(())
}

#[derive(Deserialize, Debug)]
struct Pools {
    items: Vec<Pool>,
}

#[derive(Deserialize, Debug)]
struct Pool {
    metadata: PoolMetadata,
    spec: PoolSpec,
}

#[derive(Deserialize, Debug)]
struct PoolMetadata {
    name: String,
}

#[derive(Deserialize, Debug)]
struct PoolSpec {
    ranges: Vec<PoolRange>,
    r#type: String,
}

#[derive(Deserialize, Debug)]
struct PoolRange {
    start: String,
    end: String,
}

async fn migrate_networks(api_config: &Config) -> eyre::Result<()> {
    let output = Command::new("kubectl")
        .args(["get", "resourcegroups", "-n", "forge-system", "-ojson"])
        .output()
        .wrap_err("Is kubectl on PATH?")?;
    if !output.status.success() {
        return Err(eyre::eyre!(
            "Failed running 'kubectl get resourcegroups'. \nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    let resource_groups: ResourceGroups = serde_json::from_slice(&output.stdout)?;
    let vals: Vec<forgerpc::VpcVname> = resource_groups
        .items
        .into_iter()
        .map(|item| forgerpc::VpcVname {
            dhcp_circuit_id: item.status.dhcpCircID,
            vlan_id: item.status.fabricNetworkConfiguration.vlanID,
            vni: item.status.fabricNetworkConfiguration.vni,
        })
        .collect();
    info!("Sending to API: {vals:?}");
    crate::rpc::migrate_vpc(vals, api_config).await?;
    Ok(())
}

#[derive(Deserialize, Debug)]
struct ResourceGroups {
    items: Vec<ResourceGroup>,
}

#[derive(Deserialize, Debug)]
struct ResourceGroup {
    status: ResourceGroupStatus,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct ResourceGroupStatus {
    dhcpCircID: String,
    fabricNetworkConfiguration: Net,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct Net {
    vlanID: u32,
    vni: u32,
}
