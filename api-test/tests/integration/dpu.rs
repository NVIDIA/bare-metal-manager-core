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
    path,
};

use serde::{Deserialize, Serialize};

use crate::{
    grpcurl::{grpcurl, Id, Value},
    machine::{get_firmware_version, wait_for_state},
};

const DPU_CONFIG: &str = r#"
[forge-system]
api-server = "https://$API_SERVER"
root-ca = "$ROOT_DIR/dev/certs/forge_root.pem"

[machine]
is-fake-dpu = true

[updates]
override-upgrade-cmd = "echo 'apt-get install --yes --only-upgrade --reinstall forge-dpu' > $UPGRADE_INDICATOR"

[hbn]
root-dir = "$HBN_ROOT"
skip-reload = false

[period]
main-loop-active-secs = 1
main-loop-idle-secs = 2
network-config-fetch-secs = 1
version-check-secs = 1
inventory-update-secs = 30
discovery-retry-secs = 1
discovery-retries-max = 1000
"#;

const BMC_METADATA: &str = r#"{
    "machine_id": {
      "id": "$HOST_MACHINE_ID"
    },
    "bmc_info": {
      "ip": "127.0.0.1",
      "port": 1266
    },
    "data": [
      {
        "user": "forge_admin",
        "password": "notforprod",
        "role": 1
      }
    ],
    "request_type": 1
  }"#;

pub struct Info {
    pub hbn_root: path::PathBuf,
    pub machine_id: String,
    pub interface_id: String,
    pub interface_addr: Ipv4Addr,
}

pub async fn bootstrap(
    dpu_config_path: &path::Path,
    upgrade_indicator_path: &path::Path,
    carbide_api_addr: SocketAddr,
    root_dir: &path::Path,
) -> eyre::Result<Info> {
    let (interface_id, dpu_machine_id, ip_address) =
        discover(carbide_api_addr, Some("1.1.1".to_owned()))?;

    let data = BMC_METADATA.replace("$HOST_MACHINE_ID", &dpu_machine_id);
    grpcurl(carbide_api_addr, "UpdateBMCMetaData", Some(data))?;

    // Complete hack until we affirmatively disable the legacy flow
    // This is the host that gets it's BMC updated
    let (_machine_interface_id, address) = crate::host::discover_dhcp(carbide_api_addr)?;

    let host_machine_id = crate::host::discover_machine(carbide_api_addr, address.as_str())?;

    grpcurl(
        carbide_api_addr,
        "CreateCredential",
        Some(crate::host::BMC_CREDENTIALS55),
    )?;
    let data = crate::host::BMC_METADATA.replace("$HOST_MACHINE_ID", host_machine_id.as_str());
    grpcurl(carbide_api_addr, "UpdateBMCMetaData", Some(data))?;

    //
    /* Disabled until firmware fix is released
    wait_for_state(
        carbide_api_addr,
        &dpu_machine_id,
        "DPU/WaitingForNetworkInstall",
    )?;

    let firmware_version = get_firmware_version(carbide_api_addr, &dpu_machine_id)?;
    assert_eq!(&firmware_version, "1.1.1");

    discover(carbide_api_addr, Some("2.0.1".to_owned()))?;

    forge_agent_control(carbide_api_addr, dpu_machine_id.clone())?;
    */

    wait_for_state(
        carbide_api_addr,
        &dpu_machine_id,
        "DPU/WaitingForNetworkConfig",
    )?;

    let firmware_version = get_firmware_version(carbide_api_addr, &dpu_machine_id)?;
    tracing::info!("firmware_version: {firmware_version}");
    //    assert_eq!(&firmware_version, "2.0.1");

    let hbn_root = make_dpu_filesystem(
        dpu_config_path,
        upgrade_indicator_path,
        carbide_api_addr,
        root_dir,
    )?;

    // Start forge-dpu-agent
    let dmi = dpu_machine_id.clone();
    tokio::spawn(agent::start(agent::Options {
        version: false,
        config_path: Some(dpu_config_path.to_path_buf()),
        cmd: Some(agent::AgentCommand::Run(agent::RunOptions {
            enable_metadata_service: false,
            override_machine_id: Some(dmi.to_string()),
            override_network_virtualization_type: None,
            skip_upgrade_check: false,
        })),
    }));

    // Wait for network configuration to finish
    wait_for_state(
        carbide_api_addr,
        &dpu_machine_id,
        "Host/WaitingForDiscovery",
    )?;
    tracing::info!("DPU is up now.");

    let dpu = Info {
        hbn_root,
        machine_id: dpu_machine_id,
        interface_id,
        interface_addr: ip_address,
    };
    Ok(dpu)
}

fn discover(
    addr: SocketAddr,
    dpu_version: Option<String>,
) -> eyre::Result<(String, String, Ipv4Addr)> {
    let (interface_id, ip_address) = discover_dhcp(addr)?;
    tracing::info!("Created Machine Interface with ID {interface_id}");
    let dpu_machine_id = discover_dpu(addr, dpu_version)?;
    tracing::info!("Created DPU Machine with ID {dpu_machine_id}");
    grpcurl(
        addr,
        "UpdateMachineCredentials",
        Some(&serde_json::to_string(&CredentialRequest {
            machine_id: Id {
                id: { dpu_machine_id.clone() },
            },
            credentials: vec![Credential {
                user: "forge".to_string(),
                password: "notforprod".to_string(),
                credential_purpose: 1,
            }],
        })?),
    )?;
    tracing::info!("Created 'forge' DPU SSH account");

    Ok((interface_id, dpu_machine_id, ip_address))
}

#[allow(dead_code)] // disabled until firmware is fixed
fn forge_agent_control(addr: SocketAddr, dpu_machine_id: String) -> eyre::Result<()> {
    grpcurl(
        addr,
        "ForgeAgentControl",
        Some(serde_json::to_string(&FACRequest {
            machine_id: Id {
                id: { dpu_machine_id },
            },
        })?),
    )?;
    Ok(())
}

fn write_config(
    dpu_config_path: &path::Path,
    upgrade_indicator_path: &path::Path,
    carbide_api_addr: SocketAddr,
    root_dir: &path::Path,
    hbn_root: &path::Path,
) -> io::Result<()> {
    let cfg = DPU_CONFIG
        .replace("$HBN_ROOT", &hbn_root.display().to_string())
        .replace("$ROOT_DIR", &root_dir.display().to_string())
        .replace(
            "$UPGRADE_INDICATOR",
            &upgrade_indicator_path.display().to_string(),
        )
        .replace("$API_SERVER", &carbide_api_addr.to_string());
    fs::write(dpu_config_path, cfg)
}

fn make_dpu_filesystem(
    dpu_config_path: &path::Path,
    upgrade_indicator_path: &path::Path,
    carbide_api_addr: SocketAddr,
    root_dir: &path::Path,
) -> eyre::Result<path::PathBuf> {
    let hbn_root = path::PathBuf::from("/tmp/forge-hbn-chroot-integration");
    if hbn_root.exists() {
        tracing::debug!("Deleting old {}", hbn_root.display());
        fs::remove_dir_all(&hbn_root)?;
    }
    fs::create_dir_all(hbn_root.join("etc/frr"))?;
    fs::create_dir_all(hbn_root.join("etc/network"))?;
    fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;
    fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;
    fs::create_dir_all(hbn_root.join("var/support"))?;
    fs::create_dir_all(hbn_root.join("var/support/forge-dhcp/conf"))?;
    fs::create_dir_all(hbn_root.join("etc/nvue.d/"))?;

    write_config(
        dpu_config_path,
        upgrade_indicator_path,
        carbide_api_addr,
        root_dir,
        &hbn_root,
    )?;
    Ok(hbn_root)
}

fn discover_dpu(addr: SocketAddr, dpu_version: Option<String>) -> eyre::Result<String> {
    let data = include_str!("../../../dev/docker-env/dpu_machine_discovery.json").to_string();

    let data = dpu_version
        .as_ref()
        .map_or(data.clone(), |dv| data.replace("24.35.2000", dv));
    let response = grpcurl(addr, "DiscoverMachine", Some(data))?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;
    let dpu_machine_id = resp["machineId"]["id"].as_str().unwrap().to_string();
    grpcurl(
        addr,
        "DiscoveryCompleted",
        Some(&serde_json::json!({"machine_id": {"id": dpu_machine_id}})),
    )?;

    Ok(dpu_machine_id)
}

fn discover_dhcp(addr: SocketAddr) -> eyre::Result<(String, Ipv4Addr)> {
    let response = grpcurl(
        addr,
        "DiscoverDhcp",
        Some(include_str!(
            "../../../dev/docker-env/dpu_dhcp_discovery.json"
        )),
    )?;
    let v: serde_json::Value = serde_json::from_str(&response)?;
    let interface_id = v["machineInterfaceId"]["value"].as_str().unwrap();
    let ip_address = v["address"].as_str().unwrap().parse()?;
    Ok((interface_id.to_string(), ip_address))
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
}

#[derive(Deserialize, Serialize)]
struct SegmentPrefix {
    prefix: String,
    gateway: String,
    reserve_first: usize,
}

#[derive(Serialize, Deserialize)]
struct FACRequest {
    machine_id: Id,
}
