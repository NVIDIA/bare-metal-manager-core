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
use crate::bmc_vendor::BmcVendor;
use eyre::{Context, ContextCompat};
use forge_uuid::machine::MachineId;
use ringbuf::LocalRb;
use ringbuf::storage::Array;
use ringbuf::traits::RingBuffer;
use rpc::forge;
use rpc::forge_api_client::ForgeApiClient;
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::{Channel, ChannelMsg, MethodKind};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
pub struct BackendHandle {
    /// Writer to send messages (including data) to backend
    pub channel_writer: russh::ChannelWriteHalf<russh::client::Msg>,
    /// Which BMC vendor is this backend (needed for detecting escape sequences and BMC prompts)
    pub bmc_vendor: BmcVendor,
    /// If true, the last byte of data we received was the first half of this vendor's escape
    /// sequence. Important for filtering out escape sequences to the underlying serial console.
    pub pending_escape_byte: bool,
}

/// Connect to the backend for an instance or machine, returning a [`BackendHandle`]
pub async fn spawn(
    machine_or_instance_id: &str,
    frontend_channel: russh::Channel<russh::server::Msg>,
    config: Arc<crate::config::Config>,
    forge_api_client: ForgeApiClient,
) -> eyre::Result<BackendHandle> {
    let connection_details =
        lookup_connection_details(machine_or_instance_id, &config, &forge_api_client).await?;
    let bmc_vendor = connection_details.bmc_vendor;
    let client = make_authenticated_client(connection_details).await?;

    // Channel to send data to/from the backend (BMC)
    let mut backend_channel = client
        .channel_open_session()
        .await
        .context("Error opening session to backend")?;

    trigger_and_await_sol_console(&mut backend_channel, bmc_vendor)
        .await
        .context("error activating serial console")?;

    let (mut backend_reader, backend_writer) = backend_channel.split();
    let mut backend_ringbuf: LocalRb<Array<u8, 32>> = ringbuf::LocalRb::default();
    let bmc_prompt = bmc_vendor.bmc_prompt();
    tokio::spawn({
        async move {
            loop {
                // Data coming from the BMC to the frontend
                let Some(msg) = backend_reader.wait().await else {
                    tracing::debug!("backend channel closed, closing frontend connection");
                    break;
                };

                if let ChannelMsg::Data { data, .. } = &msg {
                    backend_ringbuf.push_iter_overwrite(data.iter().copied());
                    if ringbuf_contains(&backend_ringbuf, bmc_prompt) {
                        tracing::warn!("backend dropped to BMC, exiting");
                        break;
                    }
                }

                proxy_channel_message(msg, &frontend_channel)
                    .await
                    .context("error sending message to frontend")?;
            }

            frontend_channel.eof().await.ok();
            frontend_channel.close().await.ok();
            Ok::<(), eyre::Error>(())
        }
    });

    Ok(BackendHandle {
        channel_writer: backend_writer,
        bmc_vendor,
        pending_escape_byte: false,
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
        ..
    }: ConnectionDetails<'_>,
) -> eyre::Result<russh::client::Handle<Handler>> {
    let russh_config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect(russh_config, addr, Handler)
        .await
        .with_context(|| format!("Error connecting to {addr}"))?;

    // Use authenticate_none to get a list of methods to try
    let methods = match client
        .authenticate_none(&*user)
        .await
        .context("error beginning authentication to {addr}")?
    {
        AuthResult::Success => {
            tracing::warn!(%addr, %user, "auth_none succeeded, it shouldn't have!");
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
                    .authenticate_publickey(&*user, ssh_key)
                    .await
                    .with_context(|| {
                        format!("Error attempting PublicKey authentication as {user} to {addr}")
                    })? {
                    AuthResult::Success => {
                        tracing::debug!(
                            %user, %addr,
                            "PublicKey authentication succeeded"
                        );
                        return Ok(client);
                    }
                    AuthResult::Failure { .. } => {
                        tracing::warn!(%user, %addr, "PublicKey authentication failed")
                    }
                }
            }
            MethodKind::KeyboardInteractive => {
                let mut response = client
                    .authenticate_keyboard_interactive_start(&*user, None)
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
                                %user, %addr,
                                "KeyboardInteractive authentication succeeded"
                            );
                            return Ok(client);
                        }
                        KeyboardInteractiveAuthResponse::Failure { .. } => {
                            tracing::warn!(
                                %user, %addr,
                                "KeyboardInteractive authentication failed"
                            );
                            break;
                        }
                    }
                }
            }
            MethodKind::Password => {
                match client
                    .authenticate_password(&*user, &*password)
                    .await
                    .with_context(|| {
                        format!("Error attempting Password authentication as {user} to {addr}")
                    })? {
                    AuthResult::Success => {
                        tracing::debug!(
                            %user, %addr,
                            "Password authentication succeeded"
                        );
                        return Ok(client);
                    }
                    AuthResult::Failure { .. } => {
                        tracing::warn!(%user, %addr, "Password authentication failed");
                    }
                }
            }
            other => {
                tracing::debug!("Ignoring unsupported auth method {other:?}")
            }
        }
    }

    Err(eyre::format_err!(
        "Could not authenticate to {addr} as {user}, all authentication attempts failed"
    ))
}

/// Get the address and auth details to use for a connection to a given machine or instance ID.
///
/// This information is normally gotten by calling GetBMCMetadData on carbide-api, but it can
/// also obey overridden information from ssh-console's config.
async fn lookup_connection_details<'a>(
    machine_or_instance_id: &'_ str,
    config: &'a crate::config::Config,
    forge_api_client: &'_ ForgeApiClient,
) -> eyre::Result<ConnectionDetails<'a>> {
    if let Some(override_bmc) = config.override_bmcs.as_ref().and_then(|override_bmcs| {
        override_bmcs.iter().find(|bmc| {
            bmc.machine_id == machine_or_instance_id
                || bmc
                    .instance_id
                    .as_ref()
                    .is_some_and(|i| i.as_str() == machine_or_instance_id)
        })
    }) {
        let connection_details = ConnectionDetails {
            addr: override_bmc.addr(),
            user: Cow::Borrowed(&override_bmc.user),
            password: Cow::Borrowed(&override_bmc.password),
            ssh_key_path: override_bmc.ssh_key_path.as_deref(),
            bmc_vendor: override_bmc.bmc_vendor,
        };
        tracing::info!(
            "Overriding bmc connection to {machine_or_instance_id} with {connection_details:?}"
        );
        return Ok(connection_details);
    }

    let machine_id = if MachineId::from_str(machine_or_instance_id).is_ok() {
        Cow::Borrowed(machine_or_instance_id)
    } else if let Ok(uuid) = Uuid::from_str(machine_or_instance_id) {
        Cow::Owned(
            forge_api_client
                .find_instances(forge::InstanceSearchQuery {
                    id: Some(rpc::Uuid {
                        value: uuid.to_string(),
                    }),
                    label: None,
                })
                .await
                .with_context(|| format!("Error looking up instance ID {uuid}"))?
                .instances
                .into_iter()
                .next()
                .with_context(|| format!("Could not find instance with id {uuid}"))?
                .machine_id
                .with_context(|| format!("Instance {uuid} has no machine_id"))?
                .id,
        )
    } else {
        return Err(eyre::format_err!(
            "Could not parse {machine_or_instance_id} into a machine ID or instance ID"
        ));
    };

    let machine = forge_api_client
        .get_machine(&*machine_id)
        .await
        .with_context(|| format!("Error getting machine {machine_id}"))?;
    let Some(sys_vendor) = machine
        .discovery_info
        .and_then(|d| d.dmi_data)
        .map(|d| d.sys_vendor)
    else {
        return Err(eyre::format_err!(
            "Machine {machine_id} has no known sys_vendor, cannot connect to BMC"
        ));
    };

    let bmc_vendor = BmcVendor::from_str(&sys_vendor)
        .with_context(|| format!("Unknown or unsupported vendor for machine: {sys_vendor}"))?;

    let forge::BmcMetaDataGetResponse {
        ip,
        user,
        password,
        mac: _,
        port: _,
        ssh_port,
    } = forge_api_client
        .get_bmc_meta_data(forge::BmcMetaDataGetRequest {
            machine_id: Some(rpc::MachineId {
                id: machine_id.into_owned(),
            }),
            role: 0,
            request_type: forge::BmcRequestType::Ipmi.into(),
            bmc_endpoint_request: None,
        })
        .await
        .context("Error calling forge.GetBmcMetaData")?;

    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("Error parsing IP address from forge.GetBmcMetaData: {}", ip))?;

    let port = ssh_port
        .map(u16::try_from)
        .transpose()
        .context("invalid ssh port from forge.GetBmcMetaData")?
        .unwrap_or(config.bmc_ssh_port);

    let addr = SocketAddr::new(ip, port);

    Ok(ConnectionDetails {
        addr,
        user: Cow::Owned(user),
        password: Cow::Owned(password),
        ssh_key_path: None,
        bmc_vendor,
    })
}

async fn trigger_and_await_sol_console(
    backend_channel: &mut Channel<russh::client::Msg>,
    bmc_vendor: BmcVendor,
) -> eyre::Result<()> {
    // BMC activation sequence:
    // - Send PTY and shell requests to establish terminal
    // - Send newlines until we see the BMC prompt
    // - Send vendor-specific activation command
    // - Wait for command echo to confirm activation
    // - Only then allow client to use the console

    backend_channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .context("error sending pty request to backend")?;
    backend_channel
        .request_shell(false)
        .await
        .context("error sending shell request to backend")?;
    backend_channel
        .data(&b"\n"[..])
        .await
        .context("error sending data to backend")?;

    let bmc_prompt = bmc_vendor.bmc_prompt();
    let activate_command = bmc_vendor.serial_activate_command();

    let mut prompt_buf: Vec<u8> = Vec::with_capacity(1024);
    let timeout = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let expected_activate_echo = [bmc_prompt, activate_command].concat();

    let mut newline_interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
    let mut prompt_seen = false;
    let mut activate_sent = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(timeout) => {
                return Err(eyre::format_err!("Unable to activate serial console after timeout"))
            }
            _ = newline_interval.tick() => {
                // Send newlines every 100ms until we see a prompt
                if !prompt_seen {
                    backend_channel.data(b"\r\n".as_slice()).await.context("error sending data to backend")?;
                }
            }
            res = backend_channel.wait() => {
                let Some(msg) = res else { break };
                match msg {
                    ChannelMsg::Data { data } => {
                        prompt_buf.append(&mut data.to_vec());
                        if !prompt_seen && prompt_buf.windows(bmc_prompt.len()).any(|window| window == bmc_prompt) {
                            prompt_buf.clear();
                            prompt_seen = true;
                        }

                        if prompt_seen && !activate_sent {
                            for byte in bmc_vendor.serial_activate_command() {
                                backend_channel
                                    .data([*byte].as_slice())
                                    .await
                                    .with_context(|| {
                                        format!(
                                            "error sending serial activate command ({}) to backend",
                                            String::from_utf8_lossy(bmc_vendor.serial_activate_command())
                                        )
                                    })?;
                            }
                            backend_channel.data(b"\r\n".as_slice()).await.context("error sending data to backend")?;
                            activate_sent = true;
                        }

                        if activate_sent && prompt_buf.windows(expected_activate_echo.len()).any(|window| window == expected_activate_echo) {
                            // Ok we saw our activate get sent back to us, all ready for use.
                            // (If we let the client use the console before this, we get false
                            // positives about seeing a bmc prompt.)
                            tracing::info!("confirmed serial activate command sent, letting client use console");
                            break;
                        }
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        return Err(eyre::format_err!("Exit before we saw a BMC prompt"));
                    }
                    msg => {
                        tracing::debug!(
                            "Ignoring unknown message from BMC while activating serial prompt: {msg:?}"
                        )
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ConnectionDetails<'a> {
    addr: SocketAddr,
    user: Cow<'a, str>,
    password: Cow<'a, str>,
    ssh_key_path: Option<&'a Path>,
    bmc_vendor: BmcVendor,
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

/// Take a russh::ChannelMsg being sent in either direction from the frontend or backend, and call
/// the appropriate method on the underlying channel.
///
/// This is the main proxy logic between the client SSH connection and the server SSH connection.
/// This whole thing would be unnecessary if [`russh::channels::ChanelWriteHalf::send_msg`] were
/// public. :(
async fn proxy_channel_message<S>(
    channel_msg: russh::ChannelMsg,
    channel: &russh::Channel<S>,
) -> eyre::Result<()>
where
    S: From<(russh::ChannelId, russh::ChannelMsg)> + Send + Sync + 'static,
{
    match channel_msg {
        ChannelMsg::Open { .. } => {}
        ChannelMsg::Data { data } => {
            channel
                .data(data.iter().as_slice())
                .await
                .context("error sending data")?;
        }
        ChannelMsg::ExtendedData { data, ext } => {
            channel
                .extended_data(ext, data.iter().as_slice())
                .await
                .context("error sending extended data")?;
        }
        ChannelMsg::Eof => {
            channel.eof().await.context("error sending eof")?;
        }
        ChannelMsg::Close => {
            channel.close().await.context("error sending close")?;
        }
        ChannelMsg::RequestPty {
            want_reply,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes,
        } => {
            channel
                .request_pty(
                    want_reply,
                    &term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    &terminal_modes,
                )
                .await
                .context("error sending pty request")?;
        }
        ChannelMsg::RequestShell { want_reply } => {
            channel
                .request_shell(want_reply)
                .await
                .context("error sending shell request")?;
        }
        ChannelMsg::Signal { signal } => {
            channel
                .signal(signal)
                .await
                .context("error sending signal")?;
        }
        ChannelMsg::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => {
            channel
                .window_change(col_width, row_height, pix_width, pix_height)
                .await
                .context("error sending window change")?;
        }
        _ => {
            tracing::debug!("Ignoring unknown channel message {channel_msg:?}");
        }
    }

    Ok(())
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
