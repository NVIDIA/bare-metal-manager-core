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

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{env, fs};

use agent::Options;
use axum::http::header;
use axum::response::IntoResponse;
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::Body;
use tempfile::{NamedTempFile, TempDir};

const TLS_CERT: &[u8] = include_bytes!("../../test-certs/tls.crt");
const TLS_KEY: &[u8] = include_bytes!("../../test-certs/tls.key");

#[allow(dead_code)]
const TEST_METADATA_SERVICE: bool = false;

// TODO: Add settings to config file and switch this to true
// Then assert that it works
#[allow(dead_code)]
const AGENT_CONFIG: &str = r#"
[forge-system]
api-server = "https://$API_SERVER"
pxe-server = "http://127.0.0.1:8080"
root-ca = "$ROOT_DIR/dev/certs/forge_root.pem"

[machine]
is-fake-dpu = true
interface-id = "f377ed72-d912-4879-958a-8d1f82a50d62"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.example.com"

[hbn]
root-dir = "$HBN_ROOT"
skip-reload = true

[period]
main-loop-active-secs = 1
network-config-fetch-secs = 1
main-loop-idle-secs = 30
version-check-secs = 600
inventory-update-secs = 3600
discovery-retry-secs = 1
discovery-retries-max = 1000
"#;

#[allow(dead_code)]
pub fn setup_agent_run_env(
    addr: &SocketAddr,
    td: &TempDir,
    acf: &NamedTempFile,
) -> eyre::Result<Option<Options>> {
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
    env::set_var("IGNORE_MGMT_VRF", "true");
    env::set_var("NO_DPU_CONTAINERS", "true");

    let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")) else {
        tracing::warn!(
            "Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping."
        );
        return Ok(None);
    };
    let root_dir = PathBuf::from(repo_root);

    let hbn_root = td.path();
    tracing::info!("Using hbn_root: {:?}", hbn_root);
    fs::create_dir_all(hbn_root.join("etc/frr"))?;
    fs::create_dir_all(hbn_root.join("etc/network"))?;
    fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;
    fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;
    fs::create_dir_all(hbn_root.join("var/support"))?;

    let cfg = AGENT_CONFIG
        .replace("$ROOT_DIR", &root_dir.display().to_string())
        .replace("$HBN_ROOT", &hbn_root.display().to_string())
        .replace("$API_SERVER", &addr.to_string());

    fs::write(acf.path(), cfg)?;
    let opts = agent::Options {
        version: false,
        config_path: Some(acf.path().to_path_buf()),
        cmd: Some(agent::AgentCommand::Run(agent::RunOptions {
            enable_metadata_service: TEST_METADATA_SERVICE,
            override_machine_id: None,
            override_network_virtualization_type: None,
            skip_upgrade_check: false,
        })),
    };

    // Put our fake `crictl` on front of path so that HBN health checks succeed
    let dev_bin = root_dir.join("dev/bin");
    if let Some(path) = env::var_os("PATH") {
        let mut paths = env::split_paths(&path).collect::<Vec<_>>();
        paths.insert(0, dev_bin);
        let new_path = env::join_paths(paths)?;
        env::set_var("PATH", new_path);
    }

    Ok(Some(opts))
}

pub async fn run_grpc_server(
    app: axum::Router<(), Body>,
) -> eyre::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?; // 0 let OS choose available port
    let addr = listener.local_addr()?;
    let join_handle = tokio::spawn(async move {
        let config = RustlsConfig::from_pem(TLS_CERT.to_vec(), TLS_KEY.to_vec())
            .await
            .unwrap();
        axum_server::from_tcp_rustls(listener, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    wait_for_server_to_start(addr).await?;

    Ok((addr, join_handle))
}

async fn wait_for_server_to_start(addr: SocketAddr) -> eyre::Result<()> {
    let url = format!("https://{addr}/up");
    let deadline = Instant::now() + Duration::from_secs(2);
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()?;
    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == reqwest::StatusCode::OK => {
                break;
            }
            Ok(resp) => {
                eyre::bail!(
                    "Invalid status code from /up on mock grpc server: {}",
                    resp.status(),
                );
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    if Instant::now() >= deadline {
        eyre::bail!("Timed out waiting for mock grpc server to start");
    }
    Ok(())
}

/// Takes an rpc object (built from rpc/proto/forge.proto) and turns into into a gRPC axum response
pub fn respond(out: impl prost::Message) -> impl IntoResponse {
    let msg_len = out.encoded_len() as u32;
    let mut body = Vec::with_capacity(1 + 4 + msg_len as usize);
    // first byte is compression: 0 means none
    body.push(0u8);
    // next four bytes are length as bigendian u32
    body.extend_from_slice(&msg_len.to_be_bytes());
    // and finally the message
    out.encode(&mut body).unwrap();

    let headers = [(header::CONTENT_TYPE, "application/grpc+tonic")];
    (headers, body)
}
