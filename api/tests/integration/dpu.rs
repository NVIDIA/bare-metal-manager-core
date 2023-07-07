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

use std::{collections::HashMap, fs, path, process, thread, time};

use serde::{Deserialize, Serialize};

use crate::grpcurl::{grpcurl, grpcurl_id, Id, IdValue, Value};

pub struct Info {
    pub hbn_root: path::PathBuf,
    pub machine_id: String,
    pub interface_id: String,
    pub interface_addr: ipnetwork::Ipv4Network,
    pub segment_id: String,
}

pub fn bootstrap(
    root_dir: &path::Path,
    bins: &HashMap<String, path::PathBuf>,
) -> eyre::Result<Info> {
    let (_vpc_id, _domain_id, segment_id) = basic(root_dir, bins.get("forge-admin-cli").unwrap())?;
    let (interface_id, dpu_machine_id, ip_address) = discover()?;
    let hbn_root = configure_network(
        root_dir,
        bins.get("forge-dpu-agent").unwrap(),
        &interface_id,
        &dpu_machine_id,
    )?;

    let dpu = Info {
        hbn_root,
        machine_id: dpu_machine_id,
        interface_id,
        interface_addr: ip_address,
        segment_id,
    };
    Ok(dpu)
}

fn basic(
    root_dir: &path::Path,
    forge_admin_cli: &path::Path,
) -> eyre::Result<(String, String, String)> {
    create_resource_pools(root_dir, forge_admin_cli)?;
    let vpc_id = grpcurl_id("CreateVpc", r#"{"name": "test_vpc"}"#)?;
    let domain_id = grpcurl_id("CreateDomain", r#"{"name": "forge.integrationtest"}"#)?;
    let segment_id = create_segment(&vpc_id, &domain_id)?;
    tracing::info!("Created vpc_id={vpc_id}, domain_id={domain_id}, segment_id={segment_id}");
    wait_for_segment(&segment_id)?;

    Ok((vpc_id, domain_id, segment_id))
}

fn discover() -> eyre::Result<(String, String, ipnetwork::Ipv4Network)> {
    let (interface_id, ip_address) = discover_dhcp()?;
    tracing::info!("Created Machine Interface with ID {interface_id}");
    let dpu_machine_id = discover_dpu(&interface_id)?;
    tracing::info!("Created DPU Machine with ID {dpu_machine_id}");
    grpcurl(
        "UpdateMachineCredentials",
        &serde_json::to_string(&CredentialRequest {
            machine_id: Id {
                id: { dpu_machine_id.clone() },
            },
            credentials: vec![Credential {
                user: "forge".to_string(),
                password: "notforprod".to_string(),
                credential_purpose: 1,
            }],
        })?,
    )?;
    tracing::info!("Created 'forge' DPU SSH account");

    Ok((interface_id, dpu_machine_id, ip_address))
}

fn configure_network(
    root_dir: &path::Path,
    forge_dpu_agent: &path::Path,
    interface_id: &str,
    dpu_machine_id: &str,
) -> eyre::Result<path::PathBuf> {
    let hbn_root = make_dpu_filesystem(root_dir, interface_id)?;
    crate::forge_dpu_agent::run(forge_dpu_agent, &hbn_root, dpu_machine_id)?;
    wait_for_dpu_up(dpu_machine_id)?;
    tracing::info!("DPU is up now.");
    Ok(hbn_root)
}

fn wait_for_segment(segment_id: &str) -> eyre::Result<()> {
    tracing::info!("Waiting for network segment to become ready");
    let data = serde_json::to_string(&IdValue {
        id: Value {
            value: segment_id.to_string(),
        },
    })?;
    loop {
        let response = grpcurl("FindNetworkSegments", &data)?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = &resp["networkSegments"][0]["state"];
        if let Some("READY") = state.as_str() {
            break;
        }
        thread::sleep(time::Duration::from_secs(2));
    }
    Ok(())
}

fn wait_for_dpu_up(dpu_machine_id: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "id": {"id": dpu_machine_id},
        "search_config": {"include_dpus": true}
    });
    tracing::info!("Waiting for DPU state Host/WaitingForDiscovery");
    loop {
        let response = grpcurl("FindMachines", &data.to_string())?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = resp["machines"][0]["state"].as_str().unwrap();
        if state == "Host/WaitingForDiscovery" {
            break;
        }
        tracing::debug!("\tCurrent: {state}");
        thread::sleep(time::Duration::from_secs(1));
    }
    Ok(())
}

fn make_dpu_filesystem(
    root_dir: &path::Path,
    machine_interface_id: &str,
) -> eyre::Result<path::PathBuf> {
    let hbn_root = path::PathBuf::from("/tmp/forge-hbn-chroot-integration");
    if hbn_root.exists() {
        tracing::debug!("Deleting old {}", hbn_root.display());
        fs::remove_dir_all(&hbn_root)?;
    }
    fs::create_dir_all(hbn_root.join("etc/frr"))?;
    fs::create_dir_all(hbn_root.join("etc/network"))?;
    fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;

    crate::forge_dpu_agent::write_config(root_dir, machine_interface_id)?;
    Ok(hbn_root)
}

fn discover_dpu(interface_id: &str) -> eyre::Result<String> {
    let data = include_str!("../../../dev/docker-env/dpu_machine_discovery.json")
        .replace("$MACHINE_INTERFACE_ID", interface_id);
    let response = grpcurl("DiscoverMachine", &data)?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    let dpu_machine_id = resp["machineId"]["id"].as_str().unwrap().to_string();
    grpcurl(
        "DiscoveryCompleted",
        &serde_json::json!({"machine_id": {"id": dpu_machine_id}}).to_string(),
    )?;

    Ok(dpu_machine_id)
}

fn discover_dhcp() -> eyre::Result<(String, ipnetwork::Ipv4Network)> {
    let response = grpcurl(
        "DiscoverDhcp",
        include_str!("../../../dev/docker-env/dpu_dhcp_discovery.json"),
    )?;
    let v: serde_json::Value = serde_json::from_str(&response)?;
    let interface_id = v["machineInterfaceId"]["value"].as_str().unwrap();
    let ip_address = v["address"].as_str().unwrap().parse()?;
    Ok((interface_id.to_string(), ip_address))
}

fn create_segment(vpc_id: &str, domain_id: &str) -> eyre::Result<String> {
    let net_prefix = "172.20.0.0/24";
    let net_gateway = "172.20.0.1";
    let segment_data = serde_json::to_string(&SegmentRequest {
        name: "test".to_string(),
        mtu: 1490,
        segment_type: 1,
        prefixes: vec![SegmentPrefix {
            prefix: net_prefix.to_string(),
            gateway: net_gateway.to_string(),
            reserve_first: 100,
        }],
        subdomain_id: Value {
            value: domain_id.to_string(),
        },
        vpc_id: Value {
            value: vpc_id.to_string(),
        },
    })
    .unwrap();
    grpcurl_id("CreateNetworkSegment", &segment_data)
}

fn create_resource_pools(root_dir: &path::Path, forge_admin_cli: &path::Path) -> eyre::Result<()> {
    // the dev/kube-env one is identical, so switching would be fine
    let pool_defs = root_dir.join("dev/docker-env/resource_pools.toml");
    let root_ca = root_dir.join("dev/certs/forge_root.pem");
    let client_cert = root_dir.join("dev/certs/server_identity.pem");
    let client_key = root_dir.join("dev/certs/server_identity.key");
    let out = process::Command::new(forge_admin_cli)
        .arg("-c")
        .arg("https://127.0.0.1:1079")
        .arg("--forge-root-ca-path")
        .arg(root_ca)
        .arg("--client-key-path")
        .arg(client_key)
        .arg("--client-cert-path")
        .arg(client_cert)
        .arg("resource-pool")
        .arg("define")
        .arg("-f")
        .arg(pool_defs)
        .output()?;
    if !out.status.success() {
        tracing::error!(
            "forge-admin-cli STDOUT: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        tracing::error!(
            "forge-admin-cli STDERR: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eyre::bail!("forge-admin-cli exit status code {}", out.status);
    }

    Ok(())
}

// Note that we intentionally don't use the rpc package. This test is intended to be completely
// separate from our code. We want to catch changes that would affect other systems.

#[derive(Serialize, Deserialize)]
struct CredentialRequest {
    machine_id: Id,
    credentials: Vec<Credential>,
}

#[derive(Serialize, Deserialize)]
struct Credential {
    user: String,
    password: String,
    credential_purpose: usize,
}
#[derive(Deserialize, Serialize)]
struct SegmentRequest {
    name: String,
    mtu: usize,
    segment_type: usize,
    prefixes: Vec<SegmentPrefix>,
    subdomain_id: Value,
    vpc_id: Value,
}

#[derive(Deserialize, Serialize)]
struct SegmentPrefix {
    prefix: String,
    gateway: String,
    reserve_first: usize,
}
