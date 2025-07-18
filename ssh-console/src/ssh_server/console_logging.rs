/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use crate::ShutdownHandle;
use crate::config::Config;
use crate::ssh_server::backend_pool::BackendPool;
use chrono::Utc;
use eyre::Context;
use forge_uuid::machine::MachineId;
use futures_util::future::join_all;
use rpc::forge;
use rpc::forge_api_client::ForgeApiClient;
use russh::ChannelMsg;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{RwLock, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

/// Retry interval the first time we see a failure
static RETRY_BASE_DURATION: Duration = Duration::from_secs(10);
/// Max retry interval after subsequent failures
static RETRY_MAX_DURATION: Duration = Duration::from_secs(600);

/// Spawn a ConsoleLoggerPool, returning a [`ConsoleLoggerPoolHandle`] handle. All loggers in the
/// pool will shut down when the handle is dropped.
///
/// A ConsoleLoggerPool is a handle to a group of tasks which watch backend consoles and ship
/// their logs to a file based on the machine. The tasks will shut down when this handle is dropped.
pub fn spawn(
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
    backend_pool: Arc<BackendPool>,
) -> ConsoleLoggerPoolHandle {
    let pool = ConsoleLoggerPool {
        forge_api_client,
        config,
        backend_pool,
    };

    pool.spawn()
}

pub struct ConsoleLoggerPoolHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for ConsoleLoggerPoolHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

struct ConsoleLoggerPool {
    forge_api_client: ForgeApiClient,
    config: Arc<Config>,
    backend_pool: Arc<BackendPool>,
}

struct ConsoleLoggerHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for ConsoleLoggerHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

impl ConsoleLoggerPool {
    fn spawn(self) -> ConsoleLoggerPoolHandle {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let join_handle = tokio::spawn(async move {
            let mut poll_interval = tokio::time::interval(self.config.api_poll_interval);
            poll_interval.set_missed_tick_behavior(MissedTickBehavior::Skip); // Don't try to "catch up" if we're slow
            let console_tasks = Default::default();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        tracing::info!("console logger API polling task shutting down gracefully");
                        break;
                    }

                    _ = poll_interval.tick() => {
                        self.refresh_consoles(&console_tasks)
                            .await
                            .inspect_err(|error| {
                                tracing::error!(
                                    ?error,
                                    "failed to refresh console list, will retry in {}s",
                                    poll_interval.period().as_secs()
                                );
                            })
                            .ok();
                    }
                }
            }

            let task_handles = console_tasks.write().await.drain().collect::<Vec<_>>();

            // Ensure all handles are shutdown before we return. (They already shut down when
            // dropped anyway, but we want to eagerly wait for them to finish, to support callers
            // eagerly waiting for the whole pool to finish.)
            join_all(
                task_handles
                    .into_iter()
                    .map(|(_machine_id, task_handle)| task_handle.shutdown_and_wait()),
            )
            .await;
        });

        ConsoleLoggerPoolHandle {
            shutdown_tx,
            join_handle,
        }
    }

    async fn refresh_consoles(
        &self,
        console_tasks: &RwLock<HashMap<MachineId, ConsoleLoggerHandle>>,
    ) -> eyre::Result<()> {
        // Get all machine ID's from forge, parsing them into forge_uuid::MachineId.
        let machine_ids: HashSet<MachineId> = match &self.config.override_bmcs {
            Some(override_bmcs) => {
                override_bmcs
                    .iter()
                    .filter_map(|b| {
                        b.machine_id
                            .parse()
                            .inspect_err(|error| {
                                tracing::error!(
                                    ?error,
                                    machine_id = b.machine_id,
                                    "invalid machine ID in config, will not do console logging on this machine"
                                )
                            }).ok()
                    })
                    .collect()
            }
            None => {
                self.forge_api_client
                    .find_machine_ids(forge::MachineSearchConfig {
                        include_dpus: self.config.dpus,
                        ..Default::default()
                    })
                    .await
                    .context("error fetching machine ids")?
                    .machine_ids
                    .into_iter()
                    .filter_map(|rpc_machine_id| {
                        rpc_machine_id
                            .id
                            .parse()
                            .inspect_err(|error| {
                                tracing::error!(
                                    ?error,
                                    machine_id = rpc_machine_id.id,
                                    "invalid machine ID, will not do console logging on this machine"
                                )
                            })
                            .ok()
                    })
                    .collect()
            }
        };

        // Reconcile our list with the running tasks
        {
            let mut guard = console_tasks.write().await;

            // Remove any machines that are no longer monitored
            let to_remove = guard
                .keys()
                .filter(|&machine_id| !machine_ids.contains(machine_id))
                .copied()
                .collect::<Vec<_>>();
            for machine_id in to_remove {
                tracing::info!(%machine_id, "removing machine from console logging, no longer found in carbide");
                guard.remove(&machine_id);
            }

            // Add any machines that need to be monitored
            for machine_id in machine_ids {
                if guard.contains_key(&machine_id) {
                    // It's already being logged
                    continue;
                }

                tracing::info!(%machine_id, "begin console logging for machine");
                guard.insert(machine_id, self.spawn_console_logger(machine_id));
            }
        }

        Ok(())
    }

    // Spawns an individual task to read from a BMC console and write to a log file.
    fn spawn_console_logger(&self, machine_id: MachineId) -> ConsoleLoggerHandle {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let join_handle = tokio::spawn({
            let config = self.config.clone();
            let backend_pool = self.backend_pool.clone();
            let forge_api_client = self.forge_api_client.clone();

            async move {
                // First try should not sleep
                let mut retry_time = Duration::ZERO;

                'retry: loop {
                    tokio::time::sleep(retry_time).await;
                    // Subsequent retries should sleep for RETRY_BASE_DURATION and double from there
                    // until we successfully connect.
                    retry_time = Self::next_retry_backoff(retry_time);
                    let backend_handle = match backend_pool
                        .ensure_connected(&machine_id.to_string(), &config, &forge_api_client)
                        .await
                    {
                        Ok(handle) => handle,
                        Err(error) => {
                            tracing::error!(
                                ?error,
                                "error connecting to backend for console logging, will retry in {}s",
                                retry_time.as_secs()
                            );
                            continue 'retry;
                        }
                    };

                    let log_path = Self::log_path(&config, &machine_id, &backend_handle.addr.ip());
                    let mut log_file = match OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                        .await
                    {
                        Ok(f) => f,
                        Err(error) => {
                            tracing::error!(?error, path = %log_path.display(), %machine_id, "could not open log file for writing, will retry in {}s", retry_time.as_secs());
                            continue 'retry;
                        }
                    };

                    let Some(mut msg_rx) = backend_handle.subscribe() else {
                        tracing::error!(%machine_id, "backend disconnected before we could poll for logs, will retry in {}s", retry_time.as_secs());
                        continue 'retry;
                    };

                    // Write to the file when we start so that we know when logs may have been missing
                    if let Err(error) = log_file
                        .write_all(
                            format!(
                                "--- ssh-console connected at {} ---\n",
                                Utc::now().to_rfc3339()
                            )
                            .as_bytes(),
                        )
                        .await
                    {
                        tracing::error!(?error, path = %log_path.display(), %machine_id, "error writing to log file, will retry in {}s", retry_time.as_secs());
                        continue 'retry;
                    }

                    retry_time = Duration::ZERO; // reset the retry interval, since we successfully connected.

                    let mut buffer: Vec<u8> = Vec::new();

                    loop {
                        tokio::select! {
                            // shutdown
                            _ = &mut shutdown_rx => {
                                tracing::info!(%machine_id, "stopping logging task");
                                log_file.write_all(
                                    format!(
                                        "--- ssh-console shutting down at {} ---\n",
                                        Utc::now().to_rfc3339()
                                    ).as_bytes()
                                )
                                .await
                                .ok();

                                break 'retry;
                            }

                            // incoming SSH data
                            res = msg_rx.recv() => match res {
                                Ok(msg) => if let ChannelMsg::Data { data } = msg.as_ref() {
                                    // append new bytes to our buffer
                                    buffer.extend_from_slice(data.as_ref());

                                    // process all complete lines
                                    while let Some(nl) = buffer.iter().position(|&b| b == b'\n') {
                                        // drain through and including the newline
                                        let line_bytes: Vec<u8> = buffer.drain(..=nl).collect();

                                        // strip ANSI escapes (preserves the newline byte)
                                        let clean = strip_ansi_escapes::strip(&line_bytes);

                                        // write it out
                                        if let Err(err) = log_file.write_all(&clean).await {
                                            tracing::error!(
                                                ?err,
                                                path = %log_path.display(),
                                                %machine_id,
                                                "error writing to log file, will retry in {}s",
                                                retry_time.as_secs()
                                            );
                                            continue 'retry;
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(
                                        ?error,
                                        %machine_id,
                                        "backend disconnected, will retry in {}s",
                                        retry_time.as_secs()
                                    );
                                    continue 'retry;
                                }
                            },
                        }
                    }
                }
            }
        });

        ConsoleLoggerHandle {
            shutdown_tx,
            join_handle,
        }
    }

    // Exponential backoff for retrying to connect to a console
    fn next_retry_backoff(prev: Duration) -> Duration {
        static BASE_F64: f64 = RETRY_BASE_DURATION.as_secs_f64();
        static MAX_F64: f64 = RETRY_MAX_DURATION.as_secs_f64();

        if prev == Duration::ZERO {
            return RETRY_BASE_DURATION;
        }

        // Sleep a random interval between prev and prev * 3
        let upper = (prev.as_secs_f64() * 3.0).min(MAX_F64);
        Duration::from_secs_f64(rand::random_range(BASE_F64..upper))
    }

    fn log_path(config: &Config, machine_id: &MachineId, ip_addr: &IpAddr) -> PathBuf {
        config
            .console_logs_path
            .as_path()
            .join(format!("{machine_id}_{ip_addr}.log"))
    }
}
