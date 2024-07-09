/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use crate::{api_server, find_prerequisites, vault, vault::Vault};
use carbide::logging::setup::{setup_telemetry, TelemetrySetup};
use carbide::redfish::RedfishClientPool;
use eyre::WrapErr;
use lazy_static::lazy_static;
use sqlx::{migrate::MigrateDatabase, Pool, Postgres};
use std::time::Duration;
use std::{
    env,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
    time,
};
use tokio::sync::oneshot::Sender;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::subscriber::NoSubscriber;

lazy_static! {
    // Note: We can only initialize logging once in a process, or else we get an error:
    // "a global default trace dispatcher has already been set".
    //
    // This is because try_init sets a global logger and can only be called once.
    // forge_host_support::init_logging() calls try_init, but so does carbide-api when it starts.
    // - Even if we could get around that (forge_host_support::subscriber().set_default() should
    // set a thread-specific logger), tracing will attempt to initialize the `log` crate (via tracing-log)
    // which can also only be initialized once. What a mess.
    // Error is: "attempted to set a logger after the logging system was already initialized"
    //
    // So we pass a TelemetrySetup object to carbide-api so it can avoid initializing it itself, and
    // we re-use this object for multiple tests.
    static ref TELEMETRY_SETUP: Mutex<Option<TelemetrySetup>> = Mutex::new(None);
}

#[derive(Debug, Clone)]
pub struct IntegrationTestEnvironment {
    pub carbide_api_addr: SocketAddr,
    pub root_dir: PathBuf,
    pub carbide_metrics_addr: SocketAddr,
    pub db_url: String,
    pub db_pool: Pool<Postgres>,
    pub telemetry_setup: TelemetrySetup,
}

impl IntegrationTestEnvironment {
    pub async fn try_from_environment() -> eyre::Result<Option<IntegrationTestEnvironment>> {
        let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT"))
        else {
            eprintln!(
                "Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping."
            );
            return Ok(None);
        };
        let root_dir = PathBuf::from(repo_root.clone());

        // Ask OS for a free port
        let carbide_api_addr = {
            let l = TcpListener::bind("127.0.0.1:0")?;
            l.local_addr()
        }?;

        // TODO: Also pick a free port for metrics
        let carbide_metrics_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();

        let telemetry_setup = {
            let mut locked = TELEMETRY_SETUP.lock().await;
            match locked.as_ref() {
                Some(t) => t.clone(),
                None => {
                    let telemetry_setup = setup_telemetry(0, None::<NoSubscriber>)
                        .await
                        .wrap_err("try_from_environment().setup_telemetry()")?;
                    _ = locked.insert(telemetry_setup.clone());
                    telemetry_setup
                }
            }
        };

        // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
        let db_url = env::var("DATABASE_URL")? + "/test_integration";
        drop_pg_database_with_retry_if_exists(&db_url).await?;
        sqlx::Postgres::create_database(&db_url).await?;
        let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
        Ok(Some(IntegrationTestEnvironment {
            carbide_api_addr,
            root_dir,
            carbide_metrics_addr,
            db_url,
            db_pool,
            telemetry_setup,
        }))
    }
}

async fn drop_pg_database_with_retry_if_exists(db_url: &str) -> eyre::Result<()> {
    if !sqlx::Postgres::database_exists(db_url).await? {
        return Ok(());
    }
    let Some(database) = db_url.split('/').last() else {
        panic!("Invalid DATABASE_URL: {db_url}");
    };

    for attempt in 0..10 {
        match sqlx::Postgres::drop_database(db_url).await {
            Ok(()) => break,
            Err(e) => {
                eprintln!("Could not drop test database at {db_url} (will terminate all connections and retry {} more times): {e}", 10 - attempt)
            }
        }
        let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(db_url).await?;
        let mut txn = db_pool.begin().await?;
        sqlx::query(
            r#"
        SELECT pg_terminate_backend(pg_stat_activity.pid)
        FROM pg_stat_activity
        WHERE datname = $1
        AND pid <> pg_backend_pid()"#,
        )
        .bind(database.to_string())
        .execute(&mut *txn)
        .await?;
        txn.commit().await?;
        db_pool.close().await;
        sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

pub async fn start_api_server(
    test_env: IntegrationTestEnvironment,
    override_redfish_pool: Option<Arc<dyn RedfishClientPool>>,
) -> eyre::Result<ApiServerHandle> {
    env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
    env::set_var("IGNORE_MGMT_VRF", "true");
    // There is unfortunately no support for certificates in the vault dev server, so we have to disable this in code.
    env::set_var("UNSUPPORTED_CERTIFICATE_PROVIDER", "true");
    env::set_var("NO_DPU_CONTAINERS", "true");
    env::set_var("NO_DPU_ARMOS_NETWORK", "true");

    // Destructure into vars to save typing
    let IntegrationTestEnvironment {
        carbide_api_addr,
        db_pool,
        db_url,
        root_dir,
        carbide_metrics_addr: _,
        telemetry_setup,
    } = test_env;

    // We should setup logging here but:
    // - try_init sets a global logger and can only be called once.
    // Error is: "a global default trace dispatcher has already been set".
    // forge_host_support::init_logging() calls try_init, but so does carbide-api when it starts.
    // - Even if we could get around that (forge_host_support::subscriber().set_default() should
    // set a thread-specific logger), tracing will attempt to initialize the `log` crate (via tracing-log)
    // which can also only be initialized once. What a mess.
    // Error is: "attempted to set a logger after the logging system was already initialized"

    let bins = find_prerequisites()?;

    // Put our fake `crictl` on front of path so that forge-dpu-agent's HBN health checks succeed
    let dev_bin = root_dir.join("dev/bin");
    if let Some(path) = env::var_os("PATH") {
        let mut paths = env::split_paths(&path).collect::<Vec<_>>();
        paths.insert(0, dev_bin);
        let new_path = env::join_paths(paths)?;
        env::set_var("PATH", new_path);
    }

    let m = sqlx::migrate!("../api/migrations");

    // Dependencies: Postgres, Vault and a Redfish BMC
    m.run(&db_pool).await?;
    let vault = vault::start(bins.get("vault").unwrap())?;

    let vault_token = vault.token().to_string();
    let root_dir_clone = root_dir.to_str().unwrap().to_string();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let join_handle = tokio::spawn(async move {
        api_server::start(
            carbide_api_addr,
            root_dir_clone,
            db_url,
            vault_token,
            override_redfish_pool,
            telemetry_setup,
            stop_rx,
        )
        .await
        .inspect_err(|e| {
            eprintln!("Failed to start API server: {:#}", e);
        })
    });

    sleep(time::Duration::from_secs(5)).await;

    Ok(ApiServerHandle {
        stop_channel: Some(stop_tx),
        join_handle,
        _vault_handle: vault,
    })
}

/// When dropped, this will invalidate the API server.
pub struct ApiServerHandle {
    stop_channel: Option<Sender<()>>,
    join_handle: JoinHandle<eyre::Result<()>>,
    _vault_handle: Vault,
}

impl ApiServerHandle {
    pub async fn stop(mut self) -> eyre::Result<()> {
        if let Some(stop_channel) = self.stop_channel.take() {
            stop_channel.send(()).unwrap();
        };
        self.join_handle.await??;
        Ok(())
    }
}
