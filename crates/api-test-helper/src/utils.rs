/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{env, path};

use eyre::Report;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use forge_secrets::forge_vault;
use forge_secrets::forge_vault::VaultConfig;
use metrics_endpoint::MetricsSetup;
use sqlx::migrate::MigrateDatabase;
use sqlx::{Pool, Postgres};
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use utils::HostPortPair;

use crate::api_server::StartArgs;
use crate::vault::Vault;
use crate::{api_server, vault};

lazy_static::lazy_static! {
    pub static ref REPO_ROOT: PathBuf = PathBuf::from(env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT")).expect("REPO_ROOT must be set in integration tests"));
    pub static ref LOCALHOST_CERTS: CertPaths = {
        let certs = REPO_ROOT.join("dev/certs/localhost");

        CertPaths {
            ca_cert: certs.join("ca.crt").canonicalize().unwrap(),
            server_cert: certs.join("localhost.crt").canonicalize().unwrap(),
            server_key: certs.join("localhost.key").canonicalize().unwrap(),
            client_cert: certs.join("client.crt").canonicalize().unwrap(),
            client_key: certs.join("client.key").canonicalize().unwrap(),
        }
    };
}

#[derive(Debug, Clone)]
pub struct IntegrationTestEnvironment {
    pub carbide_api_addrs: Vec<SocketAddr>,
    pub root_dir: PathBuf,
    pub carbide_metrics_addrs: Vec<SocketAddr>,
    pub db_url: String,
    pub db_pool: Pool<Postgres>,
    pub metrics: MetricsSetup,
    pub vault_config: VaultConfig,
    pub _vault_handle: Arc<Vault>,
}

pub struct CertPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl IntegrationTestEnvironment {
    pub async fn try_from_environment(
        api_server_count: u8,
        database_name: &str,
    ) -> eyre::Result<Option<IntegrationTestEnvironment>> {
        let Ok(repo_root) = env::var("REPO_ROOT").or_else(|_| env::var("CONTAINER_REPO_ROOT"))
        else {
            eprintln!(
                "Either REPO_ROOT or CONTAINER_REPO_ROOT need to be set to run this test. Skipping."
            );
            return Ok(None);
        };
        let root_dir = PathBuf::from(repo_root.clone());

        // Pick free ports for addresses we need. This is still racy, as it's not guaranteed that
        // the ports will still be available when we start the servers, but it's better than
        // hardcoding them.
        let (carbide_api_addrs, carbide_metrics_addrs, vault_addr) = {
            let mut listeners = vec![]; // hold the listeners so that we don't get the same port twice
            let mut api_addrs = vec![];
            let mut metrics_addrs = vec![];
            for _ in 0..api_server_count {
                api_addrs.push({
                    let l = TcpListener::bind("127.0.0.1:0")?;
                    let addr = l.local_addr()?;
                    listeners.push(l);
                    addr
                });
                metrics_addrs.push({
                    let l = TcpListener::bind("127.0.0.1:0")?;
                    let addr = l.local_addr()?;
                    listeners.push(l);
                    addr
                });
            }

            // Pick an address for vault too
            let vault_addr = {
                let l = TcpListener::bind("127.0.0.1:0")?;
                let addr = l.local_addr()?;
                listeners.push(l);
                addr
            };

            (api_addrs, metrics_addrs, vault_addr)
        };

        let vault = vault::start(vault_addr).await?;

        let vault_config = VaultConfig {
            address: Some(format!("http://{vault_addr}")),
            kv_mount_location: Some("secret".to_string()),
            pki_mount_location: Some("forgeca".to_string()),
            pki_role_name: Some("forge-cluster".to_string()),
            token: Some(vault.token.clone()),
        };

        // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
        let db_url = env::var("DATABASE_URL")? + "/" + database_name;
        drop_pg_database_with_retry_if_exists(&db_url).await?;
        sqlx::Postgres::create_database(&db_url).await?;
        let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
        Ok(Some(IntegrationTestEnvironment {
            carbide_api_addrs,
            root_dir,
            carbide_metrics_addrs,
            vault_config,
            db_url,
            db_pool,
            metrics: metrics_endpoint::new_metrics_setup("carbide-api", "forge-system", true)?, // unique to each test
            _vault_handle: Arc::new(vault),
        }))
    }
}

async fn drop_pg_database_with_retry_if_exists(db_url: &str) -> eyre::Result<()> {
    if !sqlx::Postgres::database_exists(db_url).await? {
        return Ok(());
    }
    let Some(database) = db_url.split('/').next_back() else {
        panic!("Invalid DATABASE_URL: {db_url}");
    };

    for attempt in 0..10 {
        match sqlx::Postgres::drop_database(db_url).await {
            Ok(()) => break,
            Err(e) => {
                eprintln!(
                    "Could not drop test database at {db_url} (will terminate all connections and retry {} more times): {e}",
                    10 - attempt
                )
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
    firmware_directory: PathBuf,
    addr_index: usize,
    put_dev_bin_in_path: bool,
) -> eyre::Result<ApiServerHandle> {
    // Destructure into vars to save typing
    let IntegrationTestEnvironment {
        carbide_api_addrs,
        db_pool,
        db_url,
        root_dir,
        carbide_metrics_addrs,
        metrics,
        vault_config,
        _vault_handle,
    } = test_env;

    unsafe {
        env::set_var("DISABLE_TLS_ENFORCEMENT", "true");
        env::set_var("IGNORE_MGMT_VRF", "true");
        // There is unfortunately no support for certificates in the vault dev server, so we have to disable this in code.
        env::set_var("UNSUPPORTED_CERTIFICATE_PROVIDER", "true");
        env::set_var("NO_DPU_CONTAINERS", "true");
        env::set_var("NO_DPU_ARMOS_NETWORK", "true");

        // Put our fake `crictl` on front of path so that forge-dpu-agent's HBN health checks succeed
        if put_dev_bin_in_path {
            let dev_bin = root_dir.join("dev/bin");
            if let Some(path) = env::var_os("PATH") {
                let mut paths = env::split_paths(&path).collect::<Vec<_>>();
                paths.insert(0, dev_bin);
                let new_path = env::join_paths(paths)?;
                env::set_var("PATH", new_path);
            }
        }
    }

    // We should setup logging here but:
    // - try_init sets a global logger and can only be called once.
    // Error is: "a global default trace dispatcher has already been set".
    // carbide_host_support::init_logging() calls try_init, but so does carbide-api when it starts.
    // - Even if we could get around that (carbide_host_support::subscriber().set_default() should
    // set a thread-specific logger), tracing will attempt to initialize the `log` crate (via tracing-log)
    // which can also only be initialized once. What a mess.
    // Error is: "attempted to set a logger after the logging system was already initialized"

    #[allow(clippy::large_stack_arrays)] // It should be fixed in sqlx.
    let m = sqlx::migrate!("../api-db/migrations");

    // Dependencies: Postgres, Vault and a Redfish BMC
    m.run(&db_pool).await?;

    populate_initial_vault_secrets(&vault_config, &metrics).await?;

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let join_handle = tokio::spawn({
        let root_dir = root_dir.clone();
        async move {
            api_server::start(StartArgs {
                addr: carbide_api_addrs[addr_index],
                metrics_addr: carbide_metrics_addrs[addr_index],
                root_dir,
                db_url,
                bmc_proxy,
                firmware_directory,
                stop_channel: stop_rx,
                ready_channel: ready_tx,
                vault_config,
            })
            .await
            .inspect_err(|e| {
                eprintln!("Failed to start API server: {e:#}");
            })
        }
    });

    ready_rx.await.unwrap();

    Ok(ApiServerHandle {
        stop_channel: Some(stop_tx),
        join_handle,
    })
}

/// When dropped, this will invalidate the API server.
pub struct ApiServerHandle {
    stop_channel: Option<Sender<()>>,
    join_handle: JoinHandle<eyre::Result<()>>,
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

pub async fn populate_initial_vault_secrets(
    vault_config_overrides: &VaultConfig,
    metrics: &MetricsSetup,
) -> Result<(), Report> {
    let vault_client =
        forge_vault::create_vault_client(vault_config_overrides, metrics.meter.clone())?;
    vault_client
        .set_credentials(
            &CredentialKey::BmcCredentials {
                credential_type: forge_secrets::credentials::BmcCredentialType::SiteWideRoot,
            },
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
        )
        .await?;
    vault_client
        .set_credentials(
            &CredentialKey::DpuUefi {
                credential_type: forge_secrets::credentials::CredentialType::SiteDefault,
            },
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
        )
        .await?;
    vault_client
        .set_credentials(
            &CredentialKey::HostUefi {
                credential_type: forge_secrets::credentials::CredentialType::SiteDefault,
            },
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "password".to_string(),
            },
        )
        .await?;
    Ok(())
}

pub fn find_prerequisites() -> eyre::Result<HashMap<String, PathBuf>> {
    let mut bins = HashMap::with_capacity(2);
    let paths: Vec<path::PathBuf> = env::split_paths(&env::var_os("PATH").unwrap()).collect();
    bins.insert("vault", find_first_in("vault", &paths));
    bins.insert("grpcurl", find_first_in("grpcurl", &paths));
    bins.insert("curl", find_first_in("curl", &paths));

    let mut full_paths = HashMap::with_capacity(bins.len());
    for (k, v) in bins.drain() {
        match v {
            Some(full_path) => {
                full_paths.insert(k.to_string(), full_path);
            }
            None => {
                eyre::bail!("Missing prerequisite binary: {k}");
            }
        }
    }

    Ok(full_paths)
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
