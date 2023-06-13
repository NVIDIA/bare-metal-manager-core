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

const DPU_CONFIG_FILE: &str = "/tmp/forge-dpu-agent-sim-config.toml";
const DPU_CONFIG: &str = r#"
[forge-system]
api-server = "https://127.0.0.1:1079"
pxe-server = "http://127.0.0.1:8080"
root-ca = "$ROOT_DIR/dev/certs/forge_root.pem"

[machine]
interface-id = "$MACHINE_INTERFACE_ID"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.com"
"#;

pub fn bootstrap(
    root_dir: &path::Path,
    bins: HashMap<String, path::PathBuf>,
) -> eyre::Result<path::PathBuf> {
    let (_vpc_id, _domain_id, _segment_id) = basic(root_dir, bins.get("forge-admin-cli").unwrap())?;
    let (interface_id, dpu_machine_id) = discover()?;
    let hbn_root = configure_network(
        root_dir,
        bins.get("forge-dpu-agent").unwrap(),
        &interface_id,
        &dpu_machine_id,
    )?;

    Ok(hbn_root)
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

fn discover() -> eyre::Result<(String, String)> {
    let interface_id = discover_dhcp()?;
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

    Ok((interface_id, dpu_machine_id))
}

fn configure_network(
    root_dir: &path::Path,
    forge_dpu_agent: &path::Path,
    interface_id: &str,
    dpu_machine_id: &str,
) -> eyre::Result<path::PathBuf> {
    let hbn_root = make_dpu_filesystem(root_dir, interface_id)?;
    super::forge_dpu_agent::run(forge_dpu_agent, DPU_CONFIG_FILE, &hbn_root, dpu_machine_id)?;
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
    loop {
        let response = grpcurl("FindMachines", &data.to_string())?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = resp["machines"][0]["state"].as_str().unwrap();
        if state == "Host/WaitingForDiscovery" {
            break;
        }
        tracing::info!("Waiting for DPU state Host/WaitingForDiscovery. Current: {state}.");
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

    let cfg = DPU_CONFIG
        .replace("$MACHINE_INTERFACE_ID", machine_interface_id)
        .replace("$ROOT_DIR", &root_dir.display().to_string());
    fs::write(DPU_CONFIG_FILE, cfg)?;
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

fn discover_dhcp() -> eyre::Result<String> {
    let response = grpcurl(
        "DiscoverDhcp",
        include_str!("../../../dev/docker-env/dpu_dhcp_discovery.json"),
    )?;
    let v: serde_json::Value = serde_json::from_str(&response)?;
    let interface_id = &v["machineInterfaceId"]["value"];
    Ok(interface_id.as_str().unwrap().to_string())
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

// grpcurl then extra id from response and return that
fn grpcurl_id(endpoint: &str, data: &str) -> eyre::Result<String> {
    let response = grpcurl(endpoint, data)?;
    let resp: IdValue = serde_json::from_str(&response)?;
    Ok(resp.id.value)
}

fn grpcurl(endpoint: &str, data: &str) -> eyre::Result<String> {
    // We don't pass the full path to grpcurl here and rely on the fact
    // that `Command` searches the PATH. This makes function signatures tidier.
    let out = process::Command::new("grpcurl")
        .arg("-d")
        .arg(data)
        .arg("-insecure")
        .arg("127.0.0.1:1079")
        .arg(format!("forge.Forge/{endpoint}"))
        .output()?;
    let response = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        tracing::error!("grpcurl {endpoint} STDOUT: {response}");
        tracing::error!(
            "grpcurl {endpoint} STDERR: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eyre::bail!("grpcurl {endpoint} exit status code {}", out.status);
    }
    Ok(response.to_string())
}

fn create_resource_pools(root_dir: &path::Path, forge_admin_cli: &path::Path) -> eyre::Result<()> {
    // the dev/kube-env one is identical, so switching would be fine
    let pool_defs = root_dir.join("dev/docker-env/resource_pools.toml");
    let out = process::Command::new(forge_admin_cli)
        .arg("-c")
        .arg("https://127.0.0.1:1079")
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

#[derive(Serialize, Deserialize)]
struct IdValue {
    id: Value,
}

#[derive(Serialize, Deserialize)]
struct Value {
    value: String,
}

#[derive(Serialize, Deserialize)]
struct Id {
    id: String,
}
