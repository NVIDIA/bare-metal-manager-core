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

use std::env;
use std::fs;
use std::path::PathBuf;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::ForgeClientConfig;
use axum::routing::post;

mod common;

const ROOT_CERT_PATH: &str = "dev/certs/forge_developer_local_only_root_cert_pem";

#[tokio::test]
async fn test_upgrade_check() -> eyre::Result<()> {
    forge_host_support::init_logging()?;
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
    env::set_var("IGNORE_MGMT_VRF", "true");

    let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")) else {
        tracing::warn!(
            "Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping."
        );
        return Ok(());
    };
    let root_dir = PathBuf::from(repo_root);

    let marker = tempfile::NamedTempFile::new()?;

    let app = axum::Router::new().route(
        "/forge.Forge/DpuAgentUpgradeCheck",
        post(dpu_agent_upgrade_check),
    );
    let (addr, join_handle) = common::run_grpc_server(app).await?;

    let client_config =
        ForgeClientConfig::new(root_dir.join(ROOT_CERT_PATH).display().to_string(), None)
            .use_mgmt_vrf()?;

    let upgrade_cmd = format!(
        "echo apt-get install --yes --only-upgrade forge-dpu-agent=__PKG_VERSION__ > {}",
        marker.path().display()
    );
    let machine_id = "test_machine_id";
    agent::upgrade_check(
        &format!("https://{addr}"),
        client_config,
        machine_id,
        &upgrade_cmd,
    )
    .await?;

    assert!(
        fs::read_to_string(marker.path())?.contains("apt-get install"),
        "Upgrade command should have run"
    );

    join_handle.abort();

    Ok(())
}

async fn dpu_agent_upgrade_check() -> impl axum::response::IntoResponse {
    common::respond(rpc::DpuAgentUpgradeCheckResponse {
        should_upgrade: true,
        package_version: "2023.06-rc2-1-gc5c05de3".to_string(),
        server_version: "v2023.06-rc2-1-gc5c05de3".to_string(),
    })
}
