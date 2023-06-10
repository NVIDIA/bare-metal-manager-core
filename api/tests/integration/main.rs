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

use std::{env, fs, path, thread, time};

use sqlx::migrate::MigrateDatabase;

mod api_server;
mod bootstrap;
#[path = "../common/mod.rs"]
mod common;
pub mod forge_dpu_agent;
mod vault;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

/// Integration test that shells out to start the real carbide-api, and then does all the steps
/// that `bootstrap-forge-docker` would do.
/// It requires `grpcurl` and `vault` on PATH, and pre-built `carbide-api` binary in target/debug/.
///
/// Developer note: This is only marked as 'async' because sqlx is async. Everything else is normal
/// threads. Yes they work fine together.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_integration() -> eyre::Result<()> {
    let root_dir =
        path::PathBuf::from(env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT"))?);
    if !has_prerequisites(&root_dir) {
        // don't break CI
        tracing::error!(
            "Skipping carbide-api integration test. Missing pre-requisities. (EASY_GREP)"
        );
        return Ok(());
    }

    // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
    let db_url = env::var("DATABASE_URL")? + "/test_integration";
    if sqlx::Postgres::database_exists(&db_url).await? {
        sqlx::Postgres::drop_database(&db_url).await?;
    }
    sqlx::Postgres::create_database(&db_url).await?;
    let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
    let m = sqlx::migrate!();
    m.run(&db_pool).await?;

    let vault = vault::start()?;

    let api = api_server::start(&root_dir, &db_url, vault.token())?;
    thread::sleep(time::Duration::from_millis(500));
    assert!(api.has_started(), "carbide-api failed to start");

    let hbn_root = bootstrap::bootstrap(&root_dir)?;

    thread::sleep(time::Duration::from_millis(500));
    fs::remove_dir_all(hbn_root)?;
    Ok(())
}

fn has_prerequisites(root_dir: &path::Path) -> bool {
    let mut has_missing = false;
    for binary in ["target/debug/carbide-api", "target/debug/forge-admin-cli"] {
        let p = root_dir.join(binary);
        if !p.exists() {
            tracing::error!("Missing {}", p.display());
            has_missing = true;
        }
    }
    let paths: Vec<path::PathBuf> = env::split_paths(&env::var_os("PATH").unwrap()).collect();
    for binary in ["vault", "grpcurl"] {
        let mut found = false;
        for path in &paths {
            let candidate = path.join(binary);
            if candidate.exists() {
                found = true;
                break;
            }
        }
        if !found {
            tracing::error!("Missing {binary} on PATH");
            has_missing = true;
        }
    }
    !has_missing
}
