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

use std::{collections::HashMap, env, fs, path, thread, time};

use sqlx::migrate::MigrateDatabase;

mod api_server;
#[path = "../common/mod.rs"]
mod common;
mod dpu;
pub mod forge_dpu_agent;
pub mod grpcurl;
mod host;
mod instance;
mod vault;
use grpcurl::grpcurl;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

/// Integration test that shells out to start the real carbide-api, and then does all the steps
/// that `bootstrap-forge-docker` would do.
/// It requires `grpcurl` and `vault` on PATH, and pre-built carbide binaries in target/debug/ or
/// target/release.
///
/// Developer note: This is only marked as 'async' because sqlx is async. Everything else is normal
/// threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_integration() -> eyre::Result<()> {
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");

    let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")) else {
        tracing::warn!("Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping.");
        return Ok(());
    };
    let root_dir = path::PathBuf::from(repo_root);
    let (bins, has_all) = find_prerequisites(&root_dir);
    if !has_all {
        eyre::bail!("Missing pre-requisites in {}", root_dir.display());
    }

    // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
    let db_url = env::var("DATABASE_URL")? + "/test_integration";
    if sqlx::Postgres::database_exists(&db_url).await? {
        sqlx::Postgres::drop_database(&db_url).await?;
    }
    sqlx::Postgres::create_database(&db_url).await?;
    let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
    let m = sqlx::migrate!();

    // Dependencies: Postgres, Vault and a Redfish BMC
    m.run(&db_pool).await?;
    let vault = vault::start(bins.get("vault").unwrap())?;
    tokio::spawn(bmc_mock::run(bmc_mock::BmcState { use_qemu: false }));

    let api = api_server::start(
        &root_dir,
        &db_url,
        vault.token(),
        bins.get("carbide-api").unwrap(),
    )?;
    thread::sleep(time::Duration::from_millis(500));
    assert!(api.has_started(), "carbide-api failed to start");

    let dpu_info = dpu::bootstrap(&root_dir, &bins)?;
    host_boostrap(bins.get("forge-dpu-agent").unwrap(), &dpu_info).await?;

    //instance::create(&host_machine_id, &segment_id)?;

    thread::sleep(time::Duration::from_millis(500));
    fs::remove_dir_all(dpu_info.hbn_root)?;
    Ok(())
}

async fn host_boostrap(forge_dpu_agent: &path::Path, dpu_info: &dpu::Info) -> eyre::Result<()> {
    let host_machine_id = host::bootstrap()?;

    // Wait until carbide-api is prepared to admit the DPU might have rebooted.
    // There are hard coded sleeps in carbide-api before this happens.
    host::wait_for_state(&host_machine_id, "WaitForDPUUp")?;

    // After DPU reboot forge_dpu_agent reports health to carbide-api, triggering state transition
    crate::forge_dpu_agent::run(forge_dpu_agent, &dpu_info.hbn_root, &dpu_info.machine_id)?;

    host::wait_for_state(&host_machine_id, "Host/Discovered")?;

    grpcurl(
        "ForgeAgentControl",
        &serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })
        .to_string(),
    )?;
    host::wait_for_state(&host_machine_id, "Ready")?;
    tracing::info!("ManagedHost is up in Ready state.");
    Ok(())
}

fn find_prerequisites(root_dir: &path::Path) -> (HashMap<String, path::PathBuf>, bool) {
    let mut bins = HashMap::with_capacity(5);
    let cargo_paths = [
        root_dir.join("target/release"),
        root_dir.join("target/debug"),
    ];
    bins.insert("carbide-api", find_in("carbide-api", &cargo_paths));
    bins.insert("forge-admin-cli", find_in("forge-admin-cli", &cargo_paths));
    bins.insert("forge-dpu-agent", find_in("forge-dpu-agent", &cargo_paths));

    let paths: Vec<path::PathBuf> = env::split_paths(&env::var_os("PATH").unwrap()).collect();
    bins.insert("vault", find_in("vault", &paths));
    bins.insert("grpcurl", find_in("grpcurl", &paths));

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
        tracing::error!("\tcargo paths: {:?}", cargo_paths);
        tracing::error!("\tPATH: {:?}", paths);
    }
    (full_paths, has_all)
}

// Look for a binary in the given paths, return full path or None if not found
fn find_in(binary: &str, paths: &[path::PathBuf]) -> Option<path::PathBuf> {
    for path in paths {
        let candidate = path.join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
