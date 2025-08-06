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

use crate::POWER_RESET_COMMAND;
use crate::bmc::client_pool::BmcPoolMetrics;
use crate::bmc::connection;
use crate::bmc::message_proxy::{ChannelMsgOrExec, ExecReply, proxy_channel_message};
use crate::bmc::vendor::SshBmcVendor;
use eyre::Context;
use forge_uuid::machine::MachineId;
use opentelemetry::KeyValue;
use ringbuf::LocalRb;
use ringbuf::storage::Array;
use ringbuf::traits::RingBuffer;
use russh::client::{AuthResult, GexParams, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::{Channel, ChannelMsg, MethodKind};
use std::fmt::Debug;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};

static RUSSH_CLIENT_CONFIG: LazyLock<Arc<russh::client::Config>> =
    LazyLock::new(russh_client_config);

/// Connect to a BMC one time, returning a [`connection::Handle`]. Will not retry on connection errors.
pub async fn spawn(
    connection_details: Arc<ConnectionDetails>,
    to_frontend_tx: broadcast::Sender<Arc<ChannelMsg>>,
    metrics: Arc<BmcPoolMetrics>,
) -> eyre::Result<connection::Handle> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let (to_bmc_msg_tx, mut to_bmc_msg_rx) = mpsc::channel::<ChannelMsgOrExec>(1);
    let metrics_attrs = vec![KeyValue::new(
        "machine_id",
        connection_details.machine_id.to_string(),
    )];

    let machine_id = connection_details.machine_id;
    let bmc_vendor = connection_details.bmc_vendor;

    let bmc_ssh_client = make_authenticated_client(&connection_details).await?;

    // Channel to send data to/from the BMC
    let mut ssh_client_channel = bmc_ssh_client
        .channel_open_session()
        .await
        .context("Error opening session to BMC")?;

    trigger_and_await_sol_console(machine_id, &mut ssh_client_channel, bmc_vendor)
        .await
        .context("error activating serial console")?;

    let mut output_ringbuf: LocalRb<Array<u8, 1024>> = ringbuf::LocalRb::default();
    let bmc_prompt = bmc_vendor.bmc_prompt();
    let mut prior_escape_pending = false;

    let join_handle = tokio::spawn(async move {
        let (mut ssh_client_rx, ssh_client_tx) = ssh_client_channel.split();

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    tracing::info!(%machine_id, "BMC connection shutting down");
                    break;
                }
                res = ssh_client_rx.wait() => match res {
                    // Data coming from the BMC to the frontend
                    Some(msg) => {
                        if let ChannelMsg::Data { data, .. } = &msg {
                            metrics.bmc_bytes_received_total.add(data.len() as _, metrics_attrs.as_slice());
                            output_ringbuf.push_iter_overwrite(data.iter().copied());
                            if let Some(bmc_prompt) = bmc_prompt {
                                if ringbuf_contains(&output_ringbuf, bmc_prompt) {
                                    let mut ringbuf_str = String::new();
                                    output_ringbuf.read_to_string(&mut ringbuf_str).ok();
                                    tracing::warn!(%machine_id, "BMC dropped to system prompt, exiting. output: {ringbuf_str:?}");
                                    break;
                                }
                            }
                        }
                        to_frontend_tx.send(Arc::new(msg)).context("error sending message from BMC to frontend")?;
                    }
                    None => {
                        metrics.bmc_rx_errors_total.add(1, metrics_attrs.as_slice());
                        tracing::debug!(%machine_id, "BMC channel closed, closing connection");
                        break;
                    }
                },

                res = to_bmc_msg_rx.recv() => match res {
                    Some(msg) => {
                        let msg = match msg {
                            ChannelMsgOrExec::ChannelMsg(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ..}) => {
                                let (data, escape_pending) = bmc_vendor.filter_escape_sequences(data.as_ref(), prior_escape_pending);
                                prior_escape_pending = escape_pending;
                                ChannelMsgOrExec::ChannelMsg(ChannelMsg::Data { data: data.as_ref().into() })
                            }
                            msg => msg,
                        };
                        let msg = match msg {
                            ChannelMsgOrExec::ChannelMsg(msg) => msg,
                            ChannelMsgOrExec::Exec { command, reply_tx} => {
                                let command = String::from_utf8(command);
                                match command {
                                    Ok(command) if command == POWER_RESET_COMMAND => {
                                        reply_tx.send(ExecReply {
                                            output: b"This BMC does not support power reset\r\n".to_vec(),
                                            exit_status: 1,
                                        }).ok();
                                    }
                                    _ => {
                                        reply_tx.send(ExecReply {
                                            output: b"Unsupported command\r\n".to_vec(),
                                            exit_status: 1,
                                        }).ok();
                                    }
                                }
                                continue;
                            }
                        };
                        proxy_channel_message(&msg, &ssh_client_tx)
                            .await
                            .context("error sending message to BMC").inspect_err(|_| {
                            metrics.bmc_tx_errors_total.add(1, metrics_attrs.as_slice());
                        })?;
                    }
                    None => {
                        tracing::debug!(%machine_id, "frontend channel closed, closing connection");
                        break;
                    }
                },
            }
        }
        Ok(())
    });

    Ok(connection::Handle {
        to_bmc_msg_tx,
        shutdown_tx,
        join_handle,
    })
}

/// Builds and authenticates an SSH client to a machine, using credentials from carbide-api or
/// overridden by config.
async fn make_authenticated_client(
    ConnectionDetails {
        addr,
        user,
        password,
        ssh_key_path,
        machine_id,
        ..
    }: &ConnectionDetails,
) -> eyre::Result<russh::client::Handle<Handler>> {
    let mut client = russh::client::connect(RUSSH_CLIENT_CONFIG.clone(), addr, Handler)
        .await
        .with_context(|| format!("Error connecting to {addr}"))?;

    // Use authenticate_none to get a list of methods to try
    let methods = match client
        .authenticate_none(user)
        .await
        .context("error beginning authentication to {addr}")?
    {
        AuthResult::Success => {
            tracing::warn!(%machine_id, %addr, %user, "auth_none succeeded, it shouldn't have!");
            return Ok(client);
        }
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };

    // Loop through each method in order of what the server wants us to try
    for method in methods.iter().copied() {
        match method {
            MethodKind::PublicKey => {
                let Some(ssh_key_path) = &ssh_key_path else {
                    tracing::debug!(
                        %machine_id,
                        "skipping PublicKey authentication as we do not have a configured public key to use"
                    );
                    continue;
                };

                let ssh_key = PrivateKeyWithHashAlg::new(
                    Arc::new(
                        russh::keys::load_secret_key(ssh_key_path, None).with_context(|| {
                            format!(
                                "Error loading SSH key from BMC override at {}",
                                ssh_key_path.display()
                            )
                        })?,
                    ),
                    Some(HashAlg::Sha512),
                );
                match client
                    .authenticate_publickey(user, ssh_key)
                    .await
                    .with_context(|| {
                        format!("Error attempting PublicKey authentication as {user} to {addr}")
                    })? {
                    AuthResult::Success => {
                        tracing::debug!(
                            %machine_id, %user, %addr,
                            "PublicKey authentication succeeded"
                        );
                        return Ok(client);
                    }
                    AuthResult::Failure { .. } => {
                        tracing::warn!(%machine_id, %user, %addr, "PublicKey authentication failed")
                    }
                }
            }
            MethodKind::KeyboardInteractive => {
                let mut response = client
                    .authenticate_keyboard_interactive_start(user, None)
                    .await
                    .with_context(|| {
                        format!("Error attempting KeyboardInteractive authentication as {user} to {addr}")
                    })?;

                loop {
                    match &response {
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                            response = client
                                .authenticate_keyboard_interactive_respond(
                                    prompts.iter().map(|_| password.to_string()).collect(),
                                )
                                .await
                                .with_context(|| format!("Error responding to KeyboardInteractive authentication as {user} to {addr}"))?;
                            // We may get multiple info requests, so we to do this in a loop
                            // until we get a success or failure.
                        }
                        KeyboardInteractiveAuthResponse::Success => {
                            tracing::debug!(
                                %machine_id, %user, %addr,
                                "KeyboardInteractive authentication succeeded"
                            );
                            return Ok(client);
                        }
                        KeyboardInteractiveAuthResponse::Failure { .. } => {
                            tracing::warn!(
                                %machine_id, %user, %addr,
                                "KeyboardInteractive authentication failed"
                            );
                            break;
                        }
                    }
                }
            }
            MethodKind::Password => {
                match client
                    .authenticate_password(user, password)
                    .await
                    .with_context(|| {
                        format!("Error attempting Password authentication as {user} to {addr}")
                    })? {
                    AuthResult::Success => {
                        tracing::debug!(
                            %machine_id, %user, %addr,
                            "Password authentication succeeded"
                        );
                        return Ok(client);
                    }
                    AuthResult::Failure { .. } => {
                        tracing::warn!(%machine_id, %user, %addr, "Password authentication failed");
                    }
                }
            }
            other => {
                tracing::debug!(%machine_id, "Ignoring unsupported auth method {other:?}")
            }
        }
    }

    Err(eyre::format_err!(
        "Could not authenticate to {addr} as {user}, all authentication attempts failed"
    ))
}

// Interact with the serial-on-lan console within the BMC ssh session, calling the vendor's serial
// activation command (`connect com1`, etc) and ensuring we're in the serial console before
// continuing.
async fn trigger_and_await_sol_console(
    machine_id: MachineId,
    ssh_client_channel: &mut Channel<russh::client::Msg>,
    bmc_vendor: SshBmcVendor,
) -> eyre::Result<()> {
    let Some(bmc_prompt) = bmc_vendor.bmc_prompt() else {
        // This vendor lets us get a console directly by SSH'ing in (e.g. a DPU.)
        return Ok(());
    };
    let Some(activate_command) = bmc_vendor.serial_activate_command() else {
        // All vendors in bmc_vendor.rs must either return Some for both bmc_prompt() and
        // serial_activate_command(), or None for both of them.
        panic!("BUG: vendor has a BMC prompt but not a serial_activate_command")
    };

    // BMC activation sequence:
    // - Send PTY and shell requests to establish terminal
    // - Send vendor-specific activation command
    // - Wait for command echo to confirm activation
    // - Only then allow client to use the console

    ssh_client_channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .context("error sending pty request to BMC")?;
    ssh_client_channel
        .request_shell(false)
        .await
        .context("error sending shell request to BMC")?;
    ssh_client_channel
        .data(b"\n".as_slice())
        .await
        .context("error sending newline to BMC")?;

    let mut prompt_buf: Vec<u8> = Vec::with_capacity(1024);
    let timeout = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    // After sending the activate command, wait for this much data to be read back (the command
    // itself echoing back, plus the prompt length) before continuing. (If we let the client use the
    // console before this, we get false positives about seeing a bmc prompt while we're supposed to
    // be in the console.)
    let skip_data_read_len = bmc_prompt.len() + activate_command.len();

    let mut activation_step = SerialConsoleActivationStep::WaitingForBmcPrompt;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(timeout) => {
                return Err(eyre::format_err!("Unable to activate serial console after timeout"))
            }
            res = ssh_client_channel.wait() => {
                let Some(msg) = res else {
                    tracing::error!(%machine_id, "BMC ssh connection closed before entering serial-on-lan console");
                    break
                };
                match msg {
                    ChannelMsg::Data { data } => {
                        prompt_buf.append(&mut data.to_vec());

                        if matches!(activation_step, SerialConsoleActivationStep::WaitingForBmcPrompt) {
                            // Do we see the bmc prompt?
                            if prompt_buf.windows(bmc_prompt.len()).any(|window| window == bmc_prompt) {
                                // We saw the prompt, send the serial activate command (`connect com1`,
                                // etc) one byte at a time: This seems to work better with some
                                // consoles.
                                for byte in activate_command {
                                    ssh_client_channel
                                        .data([*byte].as_slice())
                                        .await
                                        .with_context(|| {
                                            format!(
                                                "error sending serial activate command ({}) to BMC",
                                                String::from_utf8_lossy(activate_command)
                                            )
                                        })?;
                                }
                                ssh_client_channel.data(b"\n".as_slice()).await.context("error sending data to BMC")?;
                                activation_step = SerialConsoleActivationStep::ActivateSent;
                                // Clear the prompt
                                prompt_buf.clear();
                            }
                        }

                        // If we've sent the activate command, wait for it to be echoed back to us
                        // before continuing. (If we let the client use the console before this, we
                        // get false positives about seeing a bmc prompt while we're supposed to be
                        // in the console.)
                        if matches!(activation_step, SerialConsoleActivationStep::ActivateSent)
                            && prompt_buf.len() > skip_data_read_len {
                            tracing::debug!(%machine_id, "confirmed serial activate command sent, letting client use console");
                            break;
                        }
                    }
                    msg => {
                        tracing::debug!(
                            %machine_id,
                            "message from BMC while activating serial prompt: {msg:?}"
                        )
                    }
                }
            }
        }
    }

    Ok(())
}

struct Handler;

impl russh::client::Handler for Handler {
    type Error = eyre::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: known_hosts support?
        Ok(true)
    }
}

/// Configuration for russh's SSH client connections
fn russh_client_config() -> Arc<russh::client::Config> {
    let russh_config = russh::client::Config {
        // Some BMC's use a Diffie-Hellman group size of 2048, which is not allowed by default.
        gex: GexParams::new(2048, 8192, 8192)
            .expect("BUG: static DH group parameters must be valid"),
        keepalive_interval: Some(Duration::from_secs(60)),
        keepalive_max: 2,
        ..Default::default()
    };
    Arc::new(russh_config)
}

enum SerialConsoleActivationStep {
    WaitingForBmcPrompt,
    ActivateSent,
}

/// Returns `true` if `buf` contains the byte sequence `pat` anywhere
/// (contiguously), running in O(n*m) time (n = buf.len(), m = pat.len())
/// and doing no heap allocations.
fn ringbuf_contains<T, RB>(buf: &RB, pat: &[T]) -> bool
where
    RB: ringbuf::consumer::Consumer<Item = T>,
    T: std::cmp::PartialEq,
{
    let pat_len = pat.len();

    // Empty pattern always matches
    if pat_len == 0 {
        return true;
    }
    // If pattern is longer than buffer, can't match
    if pat_len > buf.occupied_len() {
        return false;
    }

    // Get the two contiguous slices that back the ring buffer
    let (s1, s2) = buf.as_slices();

    // 1) Search wholly inside the first slice
    if s1.windows(pat_len).any(|w| w == pat) {
        return true;
    }
    // 2) Search wholly inside the second slice
    if s2.windows(pat_len).any(|w| w == pat) {
        return true;
    }

    // 3) Search across the wrap-around boundary:
    //    for each split k (1..pat_len-1),
    //    check last k bytes of s1 == pat[..k]
    //    and first pat_len-k bytes of s2 == pat[k..]
    let s1_len = s1.len();
    let s2_len = s2.len();
    for k in 1..pat_len {
        if k <= s1_len
            && pat_len - k <= s2_len
            && s1[s1_len - k..] == pat[..k]
            && s2[..pat_len - k] == pat[k..]
        {
            return true;
        }
    }

    false
}

#[test]
fn test_ringbuf_contains() {
    let mut rb = LocalRb::new(6);
    rb.push_slice_overwrite(b"rustacean");
    // buffer holds "tacean" (last 6 of "rustacean")

    assert!(ringbuf_contains(&rb, b"ace"));
    assert!(ringbuf_contains(&rb, b"cean"));
    assert!(ringbuf_contains(&rb, b"tacean"));
    assert!(!ringbuf_contains(&rb, b"rust"));
    assert!(ringbuf_contains(&rb, b"")); // empty always true
    assert!(!ringbuf_contains(&rb, b"rustacean")); // longer than buf
    assert!(!ringbuf_contains(&rb, b"aean")); // non-contiguous
}

#[derive(Clone)]
pub struct ConnectionDetails {
    pub machine_id: MachineId,
    pub addr: SocketAddr,
    pub user: String,
    pub password: String,
    pub ssh_key_path: Option<PathBuf>,
    pub bmc_vendor: SshBmcVendor,
}

impl Debug for ConnectionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip writing the password
        f.debug_struct("SshConnectionDetails")
            .field("addr", &self.addr)
            .field("user", &self.user)
            .field("ssh_key_path", &self.ssh_key_path)
            .field("bmc_vendor", &self.bmc_vendor)
            .field("machine_id", &self.machine_id.to_string())
            .finish()
    }
}
