use crate::bmc_vendor::SshBmcVendor;
use crate::proxy_channel_message;
use crate::ssh_server::backend::SshConnectionDetails;
use eyre::Context;
use ringbuf::LocalRb;
use ringbuf::storage::Array;
use ringbuf::traits::RingBuffer;
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::{Channel, ChannelMsg, MethodKind};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

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

/// Connect to the backend for an instance or machine, returning a [`BackendHandle`]
pub async fn spawn(
    connection_details: &SshConnectionDetails,
    to_frontend_tx: broadcast::Sender<Arc<ChannelMsg>>,
) -> eyre::Result<mpsc::Sender<ChannelMsg>> {
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

    let mut backend_ringbuf: LocalRb<Array<u8, 32>> = ringbuf::LocalRb::default();
    let bmc_prompt = bmc_vendor.bmc_prompt();
    let (to_backend_msg_tx, mut to_backend_msg_rx) = mpsc::channel::<ChannelMsg>(1);
    tokio::spawn({
        async move {
            let mut prior_escape_pending = false;
            loop {
                tokio::select! {
                    res = backend_channel.wait() => match res {
                        // Data coming from the BMC to the frontend
                        Some(msg) => {
                            if let ChannelMsg::Data { data, .. } = &msg {
                                backend_ringbuf.push_iter_overwrite(data.iter().copied());
                                if ringbuf_contains(&backend_ringbuf, bmc_prompt) {
                                    tracing::warn!("backend dropped to BMC, exiting");
                                    break;
                                }
                            }
                            to_frontend_tx.send(Arc::new(msg)).context("error sending message from ssh backend to frontend")?;
                        }
                        None => {
                            tracing::debug!("backend channel closed, closing connection");
                            break;
                        }
                    },
                    res = to_backend_msg_rx.recv() => match res {
                        Some(msg) => {
                            let msg = match msg {
                                ChannelMsg::Data { data } => {
                                    let (data, escape_pending) = bmc_vendor.filter_escape_sequences(data.as_ref(), prior_escape_pending);
                                    prior_escape_pending = escape_pending;
                                    ChannelMsg::Data { data: data.as_ref().into() }
                                }
                                ChannelMsg::ExtendedData { data, ext } => {
                                    let (data, escape_pending) = bmc_vendor.filter_escape_sequences(data.as_ref(), prior_escape_pending);
                                    prior_escape_pending = escape_pending;
                                    ChannelMsg::ExtendedData { data: data.as_ref().into(), ext }
                                }
                                msg => msg,
                            };
                            proxy_channel_message(&msg, &backend_channel)
                                .await
                                .context("error sending message to backend")?;
                        }
                        None => {
                            tracing::debug!("frontend channel closed, closing connection");
                            break;
                        }
                    },
                }
            }

            Ok::<(), eyre::Error>(())
        }
    });

    Ok(to_backend_msg_tx)
}

/// Builds and authenticates an SSH client to a machine, using credentials from carbide-api or
/// overridden by config.
async fn make_authenticated_client(
    SshConnectionDetails {
        addr,
        user,
        password,
        ssh_key_path,
        ..
    }: &SshConnectionDetails,
) -> eyre::Result<russh::client::Handle<Handler>> {
    let russh_config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect(russh_config, addr, Handler)
        .await
        .with_context(|| format!("Error connecting to {addr}"))?;

    // Use authenticate_none to get a list of methods to try
    let methods = match client
        .authenticate_none(user)
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
                    .authenticate_publickey(user, ssh_key)
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
                    .authenticate_password(user, password)
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

// Interact with the serial-on-lan console within the BMC ssh session, calling the vendor's serial
// activation command (`connect com1`, etc) and ensuring we're in the serial console before
// continuing.
async fn trigger_and_await_sol_console(
    backend_channel: &mut Channel<russh::client::Msg>,
    bmc_vendor: SshBmcVendor,
) -> eyre::Result<()> {
    // BMC activation sequence:
    // - Send PTY and shell requests to establish terminal
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
        .data(b"\n".as_slice())
        .await
        .context("error sending newline to backend")?;

    let bmc_prompt = bmc_vendor.bmc_prompt();
    let activate_command = bmc_vendor.serial_activate_command();

    let mut prompt_buf: Vec<u8> = Vec::with_capacity(1024);
    let timeout = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
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
            res = backend_channel.wait() => {
                let Some(msg) = res else {
                    tracing::error!("backend ssh connection closed before entering serial-on-lan console");
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
                                backend_channel.data(b"\n".as_slice()).await.context("error sending data to backend")?;
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
                            tracing::debug!("confirmed serial activate command sent, letting client use console");
                            break;
                        }
                    }
                    msg => {
                        tracing::debug!(
                            "message from BMC while activating serial prompt: {msg:?}"
                        )
                    }
                }
            }
        }
    }

    Ok(())
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
