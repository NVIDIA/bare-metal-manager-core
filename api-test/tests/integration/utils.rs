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
use std::{
    env,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    time::Duration,
};

use eyre::Report;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use forge_secrets::forge_vault;
use metrics_endpoint::MetricsSetup;
use sqlx::{migrate::MigrateDatabase, Pool, Postgres};
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use utils::HostPortPair;

use crate::api_server::{ApiServerTestConfig, StartArgs};
use crate::{api_server, find_prerequisites, vault, vault::Vault};

#[derive(Debug, Clone)]
pub struct IntegrationTestEnvironment {
    pub carbide_api_addr: SocketAddr,
    pub root_dir: PathBuf,
    pub carbide_metrics_addr: SocketAddr,
    pub db_url: String,
    pub db_pool: Pool<Postgres>,
    pub metrics: MetricsSetup,
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
            metrics: metrics_endpoint::new_metrics_setup("carbide-api", "forge-system", true)?, // unique to each test
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
    bmc_proxy: Option<HostPortPair>,
    test_config: ApiServerTestConfig,
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
        metrics,
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
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let join_handle = tokio::spawn(async move {
        api_server::start(StartArgs {
            addr: carbide_api_addr,
            root_dir: root_dir_clone,
            db_url,
            vault_token,
            bmc_proxy,
            test_config,
            stop_channel: stop_rx,
            ready_channel: ready_tx,
        })
        .await
        .inspect_err(|e| {
            eprintln!("Failed to start API server: {:#}", e);
        })
    });

    ready_rx.await.unwrap();
    populate_initial_vault_secrets(&metrics).await?;

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

pub async fn populate_initial_vault_secrets(metrics: &MetricsSetup) -> Result<(), Report> {
    let vault_client = forge_vault::create_vault_client(metrics.meter.clone()).await?;
    vault_client
        .set_credentials(
            CredentialKey::BmcCredentials {
                credential_type: forge_secrets::credentials::BmcCredentialType::SiteWideRoot,
            },
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
        )
        .await?;
    vault_client
        .set_credentials(
            CredentialKey::DpuUefi {
                credential_type: forge_secrets::credentials::CredentialType::SiteDefault,
            },
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
        )
        .await?;
    vault_client
        .set_credentials(
            CredentialKey::HostUefi {
                credential_type: forge_secrets::credentials::CredentialType::SiteDefault,
            },
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
        )
        .await?;
    Ok(())
}
