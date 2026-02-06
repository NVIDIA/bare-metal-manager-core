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
use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use chrono::Utc;
use russh::ChannelMsg;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use crate::bmc::message_proxy::ToFrontendMessage;
use crate::config::Config;
use crate::shutdown_handle::ShutdownHandle;

/// Spawn a background task which logs all output from a BMC
pub fn spawn(
    machine_id: MachineId,
    addr: SocketAddr,
    message_rx: broadcast::Receiver<ToFrontendMessage>,
    config: Arc<Config>,
) -> ConsoleLoggerHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let console_logger = ConsoleLogger::new(config, machine_id, addr);

    let join_handle = tokio::spawn(console_logger.run(shutdown_rx, message_rx));

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

struct ConsoleLogger {
    config: Arc<Config>,
    machine_id: MachineId,
    log_path: PathBuf,
}

impl ConsoleLogger {
    fn new(config: Arc<Config>, machine_id: MachineId, addr: SocketAddr) -> Self {
        Self {
            machine_id,
            log_path: config.console_logs_path.as_path().join(format!(
                "{}_{}.log",
                machine_id,
                addr.ip()
            )),
            config,
        }
    }

    async fn run(
        self,
        mut shutdown_rx: oneshot::Receiver<()>,
        mut message_rx: broadcast::Receiver<ToFrontendMessage>,
    ) {
        let mut log_file = match RotatableLogFile::open(
            self.log_path.clone(),
            self.config.log_rotate_max_size.bytes() as _,
            self.config.log_rotate_max_rotated_files,
        )
        .await
        {
            Ok(file) => file,
            Err(error) => {
                tracing::error!(path = self.log_path.display().to_string(), machine_id=%self.machine_id, %error, "could not open log file for writing");
                return;
            }
        };

        log_file
            .write_all(
                format!(
                    "\n--- ssh-console started at {} ---\n",
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
                    Ok(msg) => {
                        let msg = Arc::<ChannelMsg>::from(msg);
                        if let ChannelMsg::Data { data } = msg.as_ref() {
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
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let msg = format!("console logger is lagged by {count} messages (typically bytes). Data may be missing from log");
                        tracing::warn!(machine_id=%self.machine_id,"{msg}");
                        log_file.write_all(format!("\n--- {msg} ---\n").as_bytes()).await.ok();
                    }
                },
            }
        }

        tracing::debug!(machine_id=%self.machine_id, "shutting down console logger");
        log_file
            .write_all(
                format!(
                    "\n--- ssh-console shutting down at {} ---\n",
                    Utc::now().to_rfc3339()
                )
                .as_bytes(),
            )
            .await
            .ok();
        log_file.flush().await.ok();
    }
}

struct RotatableLogFile {
    file: tokio::fs::File,
    path: PathBuf,
    max_size: usize,
    max_rotated_files: usize,
    byte_count: usize,
}

impl RotatableLogFile {
    async fn open(path: PathBuf, max_size: usize, max_rotated_files: usize) -> io::Result<Self> {
        let file = Self::open_log_file(path.as_path()).await?;
        Ok(Self {
            file,
            path,
            max_size,
            max_rotated_files,
            byte_count: 0,
        })
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.byte_count += data.len();

        if self.byte_count > self.max_size {
            self.byte_count = data.len();
            match self.rotate_logs().await {
                Ok(()) => {
                    self.file = Self::open_log_file(&self.path).await?;
                }
                // If we couldn't rotate, just keep writing to this file.
                Err(error) => tracing::error!("error rotating logs: {error}"),
            }
        }

        self.file.write_all(data).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.file.flush().await
    }

    async fn rotate_logs(&mut self) -> Result<(), LogRotationError> {
        tracing::info!("rotating logs for {}", self.path.display());
        let log_path_as_str = self
            .path
            .to_str()
            .ok_or_else(|| LogRotationError::InvalidPath {
                path: self.path.clone(),
            })?;

        for dst_num in (0..self.max_rotated_files).rev() {
            let src_path = if dst_num == 0 {
                // Move .log to .log.0
                Cow::Borrowed(&self.path)
            } else {
                // Move .log.(i-1) to .log.(i)
                Cow::Owned(
                    PathBuf::from_str(&format!("{}.{}", log_path_as_str, dst_num - 1))
                        // just appending ".0" shouldn't fail.
                        .expect("BUG: known-good log path didn't parse"),
                )
            };

            if !src_path.exists() {
                tracing::debug!("no log file at {}", src_path.display());
                continue;
            }

            let dst_path = if dst_num >= self.max_rotated_files {
                tracing::debug!("deleting oldest log file at {}", src_path.display());
                // Oldest log, more than max allowed rotated file count, delete it and continue
                tokio::fs::remove_file(src_path.as_path())
                    .await
                    .map_err(|error| LogRotationError::Io {
                        error,
                        context: format!("Could not delete old log file at {}", src_path.display()),
                    })?;
                continue;
            } else {
                // Renaming from src_path to this
                PathBuf::from_str(&format!("{log_path_as_str}.{dst_num}"))
                    .expect("BUG: known-good log path didn't parse")
            };

            tracing::debug!("renaming {} to {}", src_path.display(), dst_path.display());

            tokio::fs::rename(src_path.as_path(), dst_path.as_path())
                .await
                .map_err(|error| LogRotationError::Io {
                    error,
                    context: format!(
                        "Could not rename log file from {} to {}",
                        src_path.display(),
                        dst_path.display()
                    ),
                })?;
        }

        Ok(())
    }

    async fn open_log_file(path: &Path) -> io::Result<tokio::fs::File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
    }
}

#[derive(thiserror::Error, Debug)]
enum LogRotationError {
    #[error("Invalid log file path: {path}")]
    InvalidPath { path: PathBuf },
    #[error("error rotating logs: {context}: {error}")]
    Io { context: String, error: io::Error },
}
