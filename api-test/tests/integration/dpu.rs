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

use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path, thread, time,
};

use serde::{Deserialize, Serialize};

use crate::grpcurl::{grpcurl, grpcurl_id, Id, IdValue, Value};

const DPU_CONFIG: &str = r#"
[forge-system]
api-server = "https://$API_SERVER"
pxe-server = "http://127.0.0.1:8080"
root-ca = "$ROOT_DIR/dev/certs/forge_root.pem"

[machine]
interface-id = "$MACHINE_INTERFACE_ID"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.example.com"

[hbn]
root-dir = "$HBN_ROOT"
skip-reload = true
"#;

pub struct Info {
    pub hbn_root: path::PathBuf,
    pub machine_id: String,
    pub interface_id: String,
    pub interface_addr: Ipv4Addr,
    pub segment_id: String,
}

pub async fn bootstrap(
    dpu_config_file: &path::Path,
    carbide_api_addr: SocketAddr,
    root_dir: &path::Path,
) -> eyre::Result<Info> {
    let (_vpc_id, _domain_id, segment_id) = basic(carbide_api_addr)?;
    let (interface_id, dpu_machine_id, ip_address) = discover(carbide_api_addr)?;
    let hbn_root = configure_network(
        dpu_config_file,
        carbide_api_addr,
        root_dir,
        &interface_id,
        &dpu_machine_id,
    )
    .await?;

    let dpu = Info {
        hbn_root,
        machine_id: dpu_machine_id,
        interface_id,
        interface_addr: ip_address,
        segment_id,
    };
    Ok(dpu)
}

// addr is carbide-api's gRPC listener
fn basic(addr: SocketAddr) -> eyre::Result<(String, String, String)> {
    let vpc_id = grpcurl_id(addr, "CreateVpc", r#"{"name": "test_vpc"}"#)?;
    let domain_id = grpcurl_id(addr, "CreateDomain", r#"{"name": "forge.integrationtest"}"#)?;
    let segment_id = create_segment(addr, &vpc_id, &domain_id)?;
    tracing::info!("Created vpc_id={vpc_id}, domain_id={domain_id}, segment_id={segment_id}");
    wait_for_segment(addr, &segment_id)?;

    Ok((vpc_id, domain_id, segment_id))
}

fn discover(addr: SocketAddr) -> eyre::Result<(String, String, Ipv4Addr)> {
    let (interface_id, ip_address) = discover_dhcp(addr)?;
    tracing::info!("Created Machine Interface with ID {interface_id}");
    let dpu_machine_id = discover_dpu(addr, &interface_id)?;
    tracing::info!("Created DPU Machine with ID {dpu_machine_id}");
    grpcurl(
        addr,
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

fn write_config(
    dpu_config_file: &path::Path,
    carbide_api_addr: SocketAddr,
    root_dir: &path::Path,
    machine_interface_id: &str,
    hbn_root: &path::Path,
) -> io::Result<()> {
    let cfg = DPU_CONFIG
        .replace("$MACHINE_INTERFACE_ID", machine_interface_id)
        .replace("$HBN_ROOT", &hbn_root.display().to_string())
        .replace("$ROOT_DIR", &root_dir.display().to_string())
        .replace("$API_SERVER", &carbide_api_addr.to_string());
    fs::write(dpu_config_file, cfg)
}

async fn configure_network(
    dpu_config_file: &path::Path,
    carbide_api_addr: SocketAddr,
    root_dir: &path::Path,
    interface_id: &str,
    dpu_machine_id: &str,
) -> eyre::Result<path::PathBuf> {
    let hbn_root = make_dpu_filesystem(dpu_config_file, carbide_api_addr, root_dir, interface_id)?;

    // Run iteration of forge-dpu-agent: Write the config files
    agent::start(agent::Options {
        version: false,
        config_path: dpu_config_file.to_path_buf(),
        cmd: Some(agent::AgentCommand::Netconf(agent::NetconfParams {
            dpu_machine_id: dpu_machine_id.to_string(),
        })),
    })
    .await?;
    // Run iteration of forge-dpu-agent: Report network as healthy
    agent::start(agent::Options {
        version: false,
        config_path: dpu_config_file.to_path_buf(),
        cmd: Some(agent::AgentCommand::Netconf(agent::NetconfParams {
            dpu_machine_id: dpu_machine_id.to_string(),
        })),
    })
    .await?;

    wait_for_dpu_up(carbide_api_addr, dpu_machine_id)?;
    tracing::info!("DPU is up now.");
    Ok(hbn_root)
}

fn wait_for_segment(addr: SocketAddr, segment_id: &str) -> eyre::Result<()> {
    tracing::info!("Waiting for network segment to become ready");
    let data = serde_json::to_string(&IdValue {
        id: Value {
            value: segment_id.to_string(),
        },
    })?;
    loop {
        let response = grpcurl(addr, "FindNetworkSegments", &data)?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = &resp["networkSegments"][0]["state"];
        if let Some("READY") = state.as_str() {
            break;
        }
        thread::sleep(time::Duration::from_secs(2));
    }
    Ok(())
}

fn wait_for_dpu_up(addr: SocketAddr, dpu_machine_id: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "id": {"id": dpu_machine_id},
        "search_config": {"include_dpus": true}
    });
    tracing::info!("Waiting for DPU state Host/WaitingForDiscovery");
    loop {
        let response = grpcurl(addr, "FindMachines", &data.to_string())?;
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
    dpu_config_file: &path::Path,
    carbide_api_addr: SocketAddr,
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

    write_config(
        dpu_config_file,
        carbide_api_addr,
        root_dir,
        machine_interface_id,
        &hbn_root,
    )?;
    Ok(hbn_root)
}

fn discover_dpu(addr: SocketAddr, interface_id: &str) -> eyre::Result<String> {
    let data = include_str!("../../../dev/docker-env/dpu_machine_discovery.json")
        .replace("$MACHINE_INTERFACE_ID", interface_id);
    let response = grpcurl(addr, "DiscoverMachine", &data)?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    let dpu_machine_id = resp["machineId"]["id"].as_str().unwrap().to_string();
    grpcurl(
        addr,
        "DiscoveryCompleted",
        &serde_json::json!({"machine_id": {"id": dpu_machine_id}}).to_string(),
    )?;

    Ok(dpu_machine_id)
}

fn discover_dhcp(addr: SocketAddr) -> eyre::Result<(String, Ipv4Addr)> {
    let response = grpcurl(
        addr,
        "DiscoverDhcp",
        include_str!("../../../dev/docker-env/dpu_dhcp_discovery.json"),
    )?;
    let v: serde_json::Value = serde_json::from_str(&response)?;
    let interface_id = v["machineInterfaceId"]["value"].as_str().unwrap();
    let ip_address = v["address"].as_str().unwrap().parse()?;
    Ok((interface_id.to_string(), ip_address))
}

fn create_segment(addr: SocketAddr, vpc_id: &str, domain_id: &str) -> eyre::Result<String> {
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
    grpcurl_id(addr, "CreateNetworkSegment", &segment_data)
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
