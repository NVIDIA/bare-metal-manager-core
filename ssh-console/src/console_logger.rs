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

use crate::config::Config;
use crate::shutdown_handle::ShutdownHandle;
use chrono::Utc;
use forge_uuid::machine::MachineId;
use russh::ChannelMsg;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

/// Spawn a background task which logs all output from a BMC
pub fn spawn(
    machine_id: MachineId,
    addr: SocketAddr,
    mut message_rx: broadcast::Receiver<Arc<ChannelMsg>>,
    config: &Config,
) -> ConsoleLoggerHandle {
    let log_path = log_path(config, &machine_id, &addr.ip());
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let join_handle = tokio::spawn(async move {
        let mut log_file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await
        {
            Ok(file) => file,
            Err(error) => {
                tracing::error!(path = log_path.display().to_string(), %machine_id, %error, "could not open log file for writing");
                return;
            }
        };

        log_file
            .write_all(
                format!(
                    "\n--- ssh-console connected at {} ---\n",
                    Utc::now().to_rfc3339()
                )
                .as_bytes(),
            )
            .await
            .ok();

        let mut buffer: Vec<u8> = Vec::new();

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }

                // incoming SSH data
                res = message_rx.recv() => match res {
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
                            log_file.write_all(&clean).await.ok();
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let msg = format!("console logger is lagged by {count} messages (typically bytes). Data may be missing from log");
                        tracing::warn!(%machine_id,"{msg}");
                        log_file.write_all(format!("\n--- {msg} ---\n").as_bytes()).await.ok();
                    }
                },
            }
        }

        tracing::debug!(%machine_id, "shutting down console logger");
        log_file
            .write_all(
                format!(
                    "\n--- ssh-console disconnected at {} ---\n",
                    Utc::now().to_rfc3339()
                )
                .as_bytes(),
            )
            .await
            .ok();
        log_file.flush().await.ok();
    });

    ConsoleLoggerHandle {
        shutdown_tx,
        join_handle,
    }
}

pub struct ConsoleLoggerHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for ConsoleLoggerHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

fn log_path(config: &Config, machine_id: &MachineId, ip_addr: &IpAddr) -> PathBuf {
    config
        .console_logs_path
        .as_path()
        .join(format!("{machine_id}_{ip_addr}.log"))
}
