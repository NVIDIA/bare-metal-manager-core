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
use std::fmt::Debug;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use nix::errno::Errno;
use nix::pty::OpenptyResult;
use nix::unistd;
use opentelemetry::KeyValue;
use russh::ChannelMsg;
use tokio::io::unix::AsyncFd;
use tokio::process::Child;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::POWER_RESET_COMMAND;
use crate::bmc::client_pool::BmcPoolMetrics;
use crate::bmc::connection_impl::echo_connected_message;
use crate::bmc::message_proxy::{ExecReply, ToBmcMessage, ToFrontendMessage};
use crate::bmc::pending_output_line::PendingOutputLine;
use crate::bmc::vendor::IPMITOOL_ESCAPE_SEQUENCE;
use crate::config::Config;
use crate::io_util::{
    self, PtyAllocError, set_controlling_terminal_on_exec, write_data_to_async_fd,
};

/// Spawn ipmitool in the background to connect to the given BMC specified by `connection_details`,
/// and proxy data between it and the SSH frontend.
///
/// A PTY is opened to control ipmitool, since it's designed to work with one, and having a
/// persistent PTY allows multiple connections to work without worrying about how to interpret
/// multiple client PTY requests.
///
/// `to_frontend_tx` is a [`russh::Channel`] to send data from ipmitool to the SSH frontend.
///
/// Returns a [`mpsc::Sender<ChannelMsg>`] that the frontend can use to send data to ipmitool.
pub async fn spawn(
    connection_details: Arc<ConnectionDetails>,
    to_frontend_tx: broadcast::Sender<ToFrontendMessage>,
    config: Arc<Config>,
    metrics: Arc<BmcPoolMetrics>,
) -> Result<Handle, SpawnError> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let ready_tx = Some(ready_tx); // only send it once

    let machine_id = connection_details.machine_id;
    // Open a PTY to control ipmitool
    let OpenptyResult {
        master: pty_master,
        slave: pty_slave,
    } = io_util::alloc_pty(80, 24)?;
    let pty_master = AsyncFd::new(pty_master).expect("BUG: not in tokio runtime?");

    // Run `ipmitool sol activate` with the appropriate args
    let mut command = tokio::process::Command::new("ipmitool");
    command
        .arg("-I")
        .arg("lanplus")
        .arg("-H")
        .arg(connection_details.addr.ip().to_string())
        .arg("-p")
        .arg(connection_details.addr.port().to_string())
        .arg("-U")
        .arg(&connection_details.user)
        .arg("-P")
        .arg(&connection_details.password)
        // connect stdin/stdout/stderr to the pty
        .stdin(
            pty_slave
                .try_clone()
                .map_err(|error| SpawnError::PtySetup {
                    reason: "error cloning pty fd for stdin",
                    error,
                })?,
        )
        .stdout(
            pty_slave
                .try_clone()
                .map_err(|error| SpawnError::PtySetup {
                    reason: "error cloning pty fd for stdout",
                    error,
                })?,
        )
        .stderr(
            pty_slave
                .try_clone()
                .map_err(|error| SpawnError::PtySetup {
                    reason: "error cloning pty fd for stderr",
                    error,
                })?,
        )
        // Set the xterm env var as a reasonable default.
        .env("TERM", "xterm");

    if config.insecure_ipmi_ciphers {
        command.arg("-C").arg("3"); // use SHA1 ciphers, useful for ipmi_sim
    }
    command.arg("sol").arg("activate");

    // Spawn ipmitool in the controlling pty
    set_controlling_terminal_on_exec(&mut command, pty_slave.as_raw_fd());
    let ipmitool_process = command
        .spawn()
        .map_err(|error| SpawnError::SpawningIpmitool { error })?;

    // Make a channel the frontend can use to send messages to us
    let (from_frontend_tx, from_frontend_rx) = mpsc::channel::<ToBmcMessage>(1);

    let mut ipmitool_proxy = IpmitoolMessageProxy {
        connection_details,
        config,
        ipmitool_process,
        output_buf: [0u8; 4096],
        shutdown_rx,
        pty_master,
        from_frontend_rx,
        to_frontend_tx,
        ready_tx,
        metrics,
        escape_was_pending: false,
        pending_line: PendingOutputLine::with_max_size(1024),
        connected_since: Utc::now(),
        bytes_received: 0,
        output_last_received: None,
    };

    // Send messages to/from ipmitool in the background
    let join_handle = tokio::spawn(async move {
        ipmitool_proxy
            .manage_ipmitool_process()
            .await
            .map_err(|error| SpawnError::ProcessLoop {
                error,
                output: ipmitool_proxy.output_buf_str().to_string(),
            })?;

        let exit_status = ipmitool_proxy
            .ipmitool_process
            .try_wait()
            .map_err(|error| SpawnError::CheckingIpmitoolExitStatus {
                error,
                output: ipmitool_proxy.output_buf_str().to_string(),
            })?;

        match exit_status {
            Some(exit_status) => {
                // Any exit from ipmitool is unexpected: It's supposed to run forever until we shut
                // it down.
                Err(SpawnError::IpmitoolUnexpectedExit {
                    exit_status,
                    output: ipmitool_proxy.output_buf_str().to_string(),
                })
            }
            None => {
                // Process is still running (normal shutdown), we can kill it.
                tracing::debug!(%machine_id, "killing ipmitool process");
                // Kill and wait() on the process (to avoid zombies), but in the background (so we don't
                // block if it's unresponsive.)
                tokio::spawn(async move { ipmitool_proxy.ipmitool_process.kill().await });
                Ok(())
            }
        }
    });

    ready_rx.await.map_err(|_| SpawnError::WaitingForReady)?;

    Ok(Handle {
        to_bmc_msg_tx: from_frontend_tx,
        shutdown_tx,
        join_handle,
    })
}

/// A handle to a BMC connection, which will shut down when dropped.
pub struct Handle {
    pub to_bmc_msg_tx: mpsc::Sender<ToBmcMessage>,
    pub shutdown_tx: oneshot::Sender<()>,
    pub join_handle: JoinHandle<Result<(), SpawnError>>,
}

#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    #[error("error spawning a PTY for ipmitool: {0}")]
    PtyAlloc(#[from] PtyAllocError),
    #[error("error setting up pty: {reason}: {error}")]
    PtySetup {
        reason: &'static str,
        error: std::io::Error,
    },
    #[error("error spawning ipmitool: {error}")]
    SpawningIpmitool { error: std::io::Error },
    #[error("error checking ipmitool exit status: {error}. output: {output}")]
    CheckingIpmitoolExitStatus {
        error: std::io::Error,
        output: String,
    },
    #[error("ipmitool exited unexpectedly: {exit_status}, output: {output}")]
    IpmitoolUnexpectedExit {
        exit_status: ExitStatus,
        output: String,
    },
    #[error("Unknown error waiting for ipmitool to be ready")]
    WaitingForReady,
    #[error("error running ipmitool: {error}. output: {output}")]
    ProcessLoop {
        error: ProcessLoopError,
        output: String,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum ProcessLoopError {
    #[error("Error polling from pty master fd: {error}")]
    PollingFromPty { error: std::io::Error },
    #[error("error writing data from ipmitool to frontend channel: no active receivers")]
    WritingToFrontendChannel,
    #[error("error reading ipmitool output: {error}")]
    ReadingFromIpmitoolPty { error: std::io::Error },
    #[error("error sending frontend message to ipmi console: {0}")]
    SendingFrontendMessageToIpmiConsole(#[from] SendFrontendMessageToIpmiConsoleError),
    #[error("error resetting power: {0}")]
    PowerReset(#[from] PowerResetError),
}

#[derive(thiserror::Error, Debug)]
pub enum SendFrontendMessageToIpmiConsoleError {
    #[error("error writing to ipmitool pty: {error}")]
    WritingToPty { error: std::io::Error },
}

#[derive(thiserror::Error, Debug)]
pub enum PowerResetError {
    #[error("error spawning ipmitool for power reset: {error}")]
    Spawning { error: std::io::Error },
    #[error("ipmitool error running power reset: {error}")]
    Waiting { error: std::io::Error },
    #[error("ipmitool power reset failed: {output}")]
    Failure { output: String },
}

struct IpmitoolMessageProxy {
    connection_details: Arc<ConnectionDetails>,
    config: Arc<Config>,
    ipmitool_process: Child,
    output_buf: [u8; 4096],
    shutdown_rx: oneshot::Receiver<()>,
    pty_master: AsyncFd<OwnedFd>,
    from_frontend_rx: mpsc::Receiver<ToBmcMessage>,
    to_frontend_tx: broadcast::Sender<ToFrontendMessage>,
    ready_tx: Option<oneshot::Sender<()>>,
    metrics: Arc<BmcPoolMetrics>,
    // Keep track of whether the last byte sent from the client was the first byte of an escape sequence.
    escape_was_pending: bool,
    // Keep track of the last data we saw after a newline, so that we can replay it when clients join.
    pending_line: PendingOutputLine,
    // Keep track of bytes received, unfortunately we can't read from a Metrics object so we need to write to our own value.
    bytes_received: usize,
    // Keep track of when the connection started
    connected_since: DateTime<Utc>,
    output_last_received: Option<DateTime<Utc>>,
}

impl IpmitoolMessageProxy {
    /// Poll from the SSH frontend and the ipmitool PTY in the foreground, pumping messages between
    /// them, until either the frontend closes or ipmitool exits.
    ///
    /// This function is tricky because we're dealing with "normal" UNIX file descriptors (set with
    /// O_NONBLOCK), but we want to poll them in a tokio::select loop.  So we have to do the typical
    /// UNIX pattern of reading/writing data until we get EWOULDBLOCK, returning to the main loop, etc.
    async fn manage_ipmitool_process(&mut self) -> Result<(), ProcessLoopError> {
        let machine_id = self.connection_details.machine_id;
        let metrics_attrs = vec![KeyValue::new("machine_id", machine_id.to_string())];
        loop {
            tokio::select! {
                // Poll for any data to be available in pty_master
                guard = self.pty_master.readable() => {
                    let mut guard = guard.map_err(|error| ProcessLoopError::PollingFromPty { error })?;
                    // Read the available data
                    match unistd::read(guard.get_inner(), &mut self.output_buf) {
                        Ok(n) => {
                            if n == 0 {
                                tracing::debug!(%machine_id, "eof from pty fd");
                                break;
                            }
                            self.output_buf[n] = b'\0'; // null-terminate in case we need to print it later
                            // We've gotten at least one byte, we're now ready (ipmitool always outputs a message when connected.)
                            if let Some(ch) = self.ready_tx.take() {
                                self.connected_since = Utc::now();
                                ch.send(()).ok();
                            }
                            let data = &self.output_buf[0..n];
                            self.output_last_received = Some(Utc::now());
                            self.metrics.bmc_bytes_received_total.add(n as _, metrics_attrs.as_slice());
                            self.bytes_received += n;
                            self.pending_line.extend(data);
                            self.to_frontend_tx.send(ToFrontendMessage::Channel(Arc::new(ChannelMsg::Data { data: data.to_vec().into() })))
                                .map_err(|_| ProcessLoopError::WritingToFrontendChannel)?;
                            // Note, we're not clearing the ready state, so the fd will stay readable.
                            // The next time through the loop we'll get EWOULDBLOCK and clear the
                            // status. This lets us handle cases where there's more data to read than
                            // the buf size.
                        }
                        Err(e) if e == Errno::EWOULDBLOCK => {
                            // clear the readiness so we go back to polling
                            guard.clear_ready();
                        }
                        Err(e) => {
                            self.metrics.bmc_rx_errors_total.add(1, metrics_attrs.as_slice());
                            return Err(std::io::Error::from_raw_os_error(e as _))
                                .map_err(|error| ProcessLoopError::ReadingFromIpmitoolPty { error })
                        }
                    };
                }
                // Poll for any messages from the SSH frontend
                res = self.from_frontend_rx.recv() => match res {
                    Some(msg) => {
                        self.send_frontend_message_to_ipmi_console(msg).await.inspect_err(|_| {
                            self.metrics.bmc_tx_errors_total.add(1, metrics_attrs.as_slice());
                        })?;
                    }
                    None => {
                        tracing::info!(%machine_id, "all frontend connections closed, stopping ipmitool");
                        break;
                    }
                },
                // Break if ipmitool exits
                exit_status = self.ipmitool_process.wait() => {
                    tracing::warn!("ipmitool exited with status {:?}", exit_status);
                    break;
                }
                // Break if we're shut down
                _ = &mut self.shutdown_rx => {
                    tracing::debug!("ipmitool_process_loop shutdown received");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn send_frontend_message_to_ipmi_console(
        &mut self,
        msg: ToBmcMessage,
    ) -> Result<(), SendFrontendMessageToIpmiConsoleError> {
        let machine_id = self.connection_details.machine_id;
        let msg = match msg {
            // Filter out escape sequences
            ToBmcMessage::ChannelMsg(
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ext: _ },
            ) => {
                let (data, escape_pending) = IPMITOOL_ESCAPE_SEQUENCE
                    .filter_escape_sequences(data.as_ref(), self.escape_was_pending);
                self.escape_was_pending = escape_pending;
                ToBmcMessage::ChannelMsg(ChannelMsg::Data {
                    data: data.as_ref().into(),
                })
            }
            msg => msg,
        };

        match msg {
            ToBmcMessage::ChannelMsg(ChannelMsg::Eof | ChannelMsg::Close) => {
                // multiple clients can come and go, we don't close just because one of them disconnected.
            }
            ToBmcMessage::ChannelMsg(ChannelMsg::Data { data }) => {
                write_data_to_async_fd(&data, &self.pty_master)
                    .await
                    .map_err(
                        |error| SendFrontendMessageToIpmiConsoleError::WritingToPty { error },
                    )?;
            }
            ToBmcMessage::ChannelMsg(ChannelMsg::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            }) => {
                // update the kernel pty size
                let winsz = libc::winsize {
                    ws_row: row_height.try_into().unwrap_or(80),
                    ws_col: col_width.try_into().unwrap_or(24),
                    ws_xpixel: pix_width.try_into().unwrap_or(0),
                    ws_ypixel: pix_height.try_into().unwrap_or(0),
                };
                // SAFETY: ioctl on master FD
                unsafe {
                    libc::ioctl(self.pty_master.as_raw_fd(), libc::TIOCSWINSZ, &winsz);
                }
            }
            ToBmcMessage::Exec { command, reply_tx } => match String::from_utf8(command) {
                Ok(command) if command == POWER_RESET_COMMAND => match self.power_reset().await {
                    Ok(()) => {
                        reply_tx
                            .send(ExecReply {
                                output: b"Power reset completed successfully\r\n".to_vec(),
                                exit_status: 0,
                            })
                            .ok();
                    }
                    Err(e) => {
                        reply_tx
                            .send(ExecReply {
                                output: format!("{e}\r\n").into_bytes(),
                                exit_status: 1,
                            })
                            .ok();
                    }
                },
                _ => {
                    reply_tx
                        .send(ExecReply {
                            output: b"Unsupported command\r\n".as_slice().into(),
                            exit_status: 127,
                        })
                        .ok();
                }
            },
            ToBmcMessage::EchoConnectionMessage { reply_tx } => {
                echo_connected_message(
                    reply_tx,
                    &self.pending_line,
                    self.bytes_received,
                    self.output_last_received,
                    self.connected_since,
                );
                return Ok(());
            }
            other => {
                tracing::debug!(%machine_id, "Not handling unknown SSH frontend message in ipmitool: {other:?}");
            }
        };
        Ok(())
    }

    async fn power_reset(&mut self) -> Result<(), PowerResetError> {
        let mut command = tokio::process::Command::new("ipmitool");
        command
            .arg("-I")
            .arg("lanplus")
            .arg("-H")
            .arg(self.connection_details.addr.ip().to_string())
            .arg("-p")
            .arg(self.connection_details.addr.port().to_string())
            .arg("-U")
            .arg(&self.connection_details.user)
            .arg("-P")
            .arg(&self.connection_details.password)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if self.config.insecure_ipmi_ciphers {
            command.arg("-C").arg("3"); // use SHA1 ciphers, useful for ipmi_sim
        }
        command.arg("power").arg("reset");

        let output = command
            .spawn()
            .map_err(|error| PowerResetError::Spawning { error })?
            .wait_with_output()
            .await
            .map_err(|error| PowerResetError::Waiting { error })?;

        if output.status.success() {
            Ok(())
        } else {
            Err(PowerResetError::Failure {
                output: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    // output_buf is a 4096-byte array, get the output up to the first null terminator.
    fn output_buf_str(&'_ self) -> Cow<'_, str> {
        if let Some(null_idx) = self.output_buf.iter().position(|c| *c == b'\0') {
            String::from_utf8_lossy(&self.output_buf[0..null_idx])
        } else {
            String::from_utf8_lossy(&self.output_buf)
        }
    }
}

#[derive(Clone)]
pub struct ConnectionDetails {
    pub machine_id: MachineId,
    pub addr: SocketAddr,
    pub user: String,
    pub password: String,
}

impl Debug for ConnectionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip writing the password
        f.debug_struct("IpmiConnectionDetails")
            .field("addr", &self.addr)
            .field("user", &self.user)
            .field("machine_id", &self.machine_id.to_string())
            .finish()
    }
}
