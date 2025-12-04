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

use std::path::PathBuf;
use std::{env, fs};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::ForgeClientConfig;
use axum::response::IntoResponse;
use axum::routing::{get, post};

use crate::tests::common;

const ROOT_CERT_PATH: &str = "dev/certs/forge_developer_local_only_root_cert_pem";

#[tokio::test]
async fn test_upgrade_check() -> eyre::Result<()> {
    carbide_host_support::init_logging()?;

    unsafe {
        env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
        env::set_var("IGNORE_MGMT_VRF", "true");
    }

    let root_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));

    let marker = tempfile::NamedTempFile::new()?;

    let app = axum::Router::new()
        .route("/up", get(handle_up))
        .route(
            "/forge.Forge/DpuAgentUpgradeCheck",
            post(dpu_agent_upgrade_check),
        )
        // ForgeApiClient needs a working Version route for connection retrying
        .route("/forge.Forge/Version", post(handle_version));
    let (addr, join_handle) = common::run_grpc_server(app).await?;

    let client_config =
        ForgeClientConfig::new(root_dir.join(ROOT_CERT_PATH).display().to_string(), None)
            .use_mgmt_vrf()?;

    let upgrade_cmd = format!(
        "echo apt-get install --yes --only-upgrade --reinstall forge-dpu-agent > {}",
        marker.path().display()
    );
    let machine_id = "fm100ht6n80e7do39u8gmt7cvhm89pb32st9ngevgdolu542l1nfa4an0rg".parse()?;
    crate::upgrade::upgrade(
        &format!("https://{addr}"),
        &client_config,
        &machine_id,
        Some(upgrade_cmd).as_deref(),
    )
    .await?;

    assert!(
        fs::read_to_string(marker.path())?.contains("apt-get install"),
        "Upgrade command should have run"
    );

    join_handle.abort();

    Ok(())
}

async fn dpu_agent_upgrade_check() -> impl IntoResponse {
    common::respond(rpc::DpuAgentUpgradeCheckResponse {
        should_upgrade: true,
        package_version: "2024.05-rc3-0".to_string(),
        server_version: "v2024.05-rc3-0".to_string(),
    })
}

/// Health check. When this responds we know the mock server is ready.
async fn handle_up() -> &'static str {
    "OK"
}
async fn handle_version() -> impl IntoResponse {
    common::respond(rpc::BuildInfo::default())
}
