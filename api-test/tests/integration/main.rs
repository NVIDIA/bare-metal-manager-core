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
    collections::HashMap,
    env, fs,
    net::{SocketAddr, TcpListener},
    path, time,
};

use sqlx::migrate::MigrateDatabase;
use tokio::time::sleep;

mod api_server;
mod dpu;
pub mod grpcurl;
mod host;
mod instance;
mod vault;
use grpcurl::grpcurl;

/// Integration test that shells out to start the real carbide-api, and then does all the steps
/// that `bootstrap-forge-docker` would do.
/// It requires `grpcurl` and `vault` on the PATH,
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_integration() -> eyre::Result<()> {
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
    // There is unfortunately no support for certificates in the vault dev server, so we have to disable this in code.
    env::set_var("UNSUPPORTED_CERTIFICATE_PROVIDER", "true");

    let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")) else {
        tracing::warn!("Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping.");
        return Ok(());
    };
    let (bins, has_all) = find_prerequisites();
    if !has_all {
        eyre::bail!("Missing pre-requisites");
    }

    // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
    let db_url = env::var("DATABASE_URL")? + "/test_integration";
    if sqlx::Postgres::database_exists(&db_url).await? {
        sqlx::Postgres::drop_database(&db_url).await?;
    }
    sqlx::Postgres::create_database(&db_url).await?;
    let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
    let m = sqlx::migrate!("../api/migrations");

    // Dependencies: Postgres, Vault and a Redfish BMC
    m.run(&db_pool).await?;
    let vault = vault::start(bins.get("vault").unwrap())?;
    tokio::spawn(bmc_mock::run(bmc_mock::BmcState {
        use_qemu: false,
        cert_path: None,
    }));

    // Ask OS for a free port
    let carbide_api_addr = {
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
    };

    let vault_token = vault.token().to_string();
    let root_dir = path::PathBuf::from(repo_root);
    tokio::spawn({
        let root_dir = root_dir.to_str().unwrap().to_string();
        let db_url = db_url.to_string();
        api_server::start(carbide_api_addr, root_dir, db_url, vault_token)
    });

    sleep(time::Duration::from_secs(5)).await;

    let agent_config_file = tempfile::NamedTempFile::new()?;
    let dpu_info = dpu::bootstrap(agent_config_file.path(), carbide_api_addr, &root_dir).await?;
    host_boostrap(carbide_api_addr, agent_config_file.path(), &dpu_info).await?;

    //instance::create(&host_machine_id, &segment_id)?;

    sleep(time::Duration::from_millis(500)).await;
    fs::remove_dir_all(dpu_info.hbn_root)?;
    Ok(())
}

async fn host_boostrap(
    carbide_api_addr: SocketAddr,
    agent_config_file: &path::Path,
    dpu_info: &dpu::Info,
) -> eyre::Result<()> {
    let host_machine_id = host::bootstrap(carbide_api_addr)?;

    // Wait until carbide-api is prepared to admit the DPU might have rebooted.
    // There are hard coded sleeps in carbide-api before this happens.
    host::wait_for_state(carbide_api_addr, &host_machine_id, "WaitForDPUUp")?;

    // After DPU reboot forge_dpu_agent reports health to carbide-api, triggering state transition
    // Run iteration of forge-dpu-agent
    agent::start(agent::Options {
        version: false,
        config_path: agent_config_file.to_path_buf(),
        cmd: Some(agent::AgentCommand::Netconf(agent::NetconfParams {
            dpu_machine_id: dpu_info.machine_id.clone(),
        })),
    })
    .await?;

    host::wait_for_state(carbide_api_addr, &host_machine_id, "Host/Discovered")?;

    grpcurl(
        carbide_api_addr,
        "ForgeAgentControl",
        &serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })
        .to_string(),
    )?;
    host::wait_for_state(carbide_api_addr, &host_machine_id, "Ready")?;
    tracing::info!("ManagedHost is up in Ready state.");
    Ok(())
}

fn find_prerequisites() -> (HashMap<String, path::PathBuf>, bool) {
    let mut bins = HashMap::with_capacity(2);
    let paths: Vec<path::PathBuf> = env::split_paths(&env::var_os("PATH").unwrap()).collect();
    bins.insert("vault", find_first_in("vault", &paths));
    bins.insert("grpcurl", find_first_in("grpcurl", &paths));

    let mut has_all = true;
    let mut full_paths = HashMap::with_capacity(bins.len());
    for (k, v) in bins.drain() {
        match v {
            Some(full_path) => {
                full_paths.insert(k.to_string(), full_path);
            }
            None => {
                tracing::error!("Missing {k}");
                has_all = false;
            }
        }
    }
    if !has_all {
        tracing::error!("\tPATH: {:?}", paths);
    }
    (full_paths, has_all)
}

// Look for a binary in the given paths, return full path or None if not found
fn find_first_in(binary: &str, paths: &[path::PathBuf]) -> Option<path::PathBuf> {
    for path in paths {
        let candidate = path.join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
