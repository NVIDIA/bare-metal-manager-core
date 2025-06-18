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

use std::path::Path;
use std::time::Duration;

use eyre::Context;
use russh::ChannelMsg;
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(Copy, Clone)]
pub struct ConnectionConfig<'a> {
    pub connection_name: &'a str,
    pub user: &'a str,
    pub private_key_path: &'a Path,
    pub addr: SocketAddr,
    pub expected_prompt: &'a str,
}

pub async fn assert_connection_works_with_retries_and_timeout(
    connection_config: ConnectionConfig<'_>,
    retry_count: u8,
    per_try_timeout: Duration,
) -> eyre::Result<()> {
    let mut retries = retry_count;
    loop {
        match tokio::time::timeout(per_try_timeout, assert_connection_works(connection_config))
            .await
        {
            Ok(result) => match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    tracing::error!(
                        ?error,
                        connection_name = connection_config.connection_name,
                        "Error asserting working connection, will retry",
                    );
                    if retries > 0 {
                        retries -= 1;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    } else {
                        return Err(error).context(format!(
                            "Could not connect to {} after {} retries",
                            connection_config.connection_name, retry_count,
                        ));
                    }
                }
            },
            Err(elapsed) => {
                return Err(elapsed).context(format!(
                    "Timed out asserting working connection to {}",
                    connection_config.connection_name
                ));
            }
        }
    }
}

async fn assert_connection_works(
    ConnectionConfig {
        connection_name,
        user,
        private_key_path,
        addr,
        expected_prompt,
    }: ConnectionConfig<'_>,
) -> eyre::Result<()> {
    // Connect to the server and authenticate
    let session = {
        let mut session = russh::client::connect(
            Arc::new(russh::client::Config {
                ..Default::default()
            }),
            addr,
            PermissiveSshClient,
        )
        .await?;

        session
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(
                    Arc::new(
                        russh::keys::load_secret_key(private_key_path, None)
                            .context("error loading ssh private key")?,
                    ),
                    None,
                ),
            )
            .await
            .context("Error authenticating with public key")?;

        Ok::<_, eyre::Error>(session)
    }?;

    // Open a session channel
    let mut channel = session
        .channel_open_session()
        .await
        .context("Error opening session")?;

    // Request PTY
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .context("Error requesting PTY")?;

    // Request Shell
    channel.request_shell(false).await?;

    let mut output_buf = String::new();
    let mut prompt_found = false;
    let mut newline_interval = tokio::time::interval(Duration::from_secs(1));

    // Every second, write a newline to the connection, until we see a prompt.
    loop {
        tokio::select! {
            _ = newline_interval.tick() => {
                // Write a newline, unless we already saw the prompt, in which case we're waiting
                // for EOF and shouldn't send anything else.
                if !prompt_found {
                    channel.make_writer().write_all(b"\r\n").await.context("Writing newline to server")?;
                }
            }
            result = channel.wait() => match result {
                Some(msg) => match msg {
                    ChannelMsg::Data { data } => {
                        output_buf.push_str(&String::from_utf8_lossy(&data));
                        if output_buf.ends_with(expected_prompt) {
                            tracing::info!(connection_name, "Got prompt, success!");
                            prompt_found = true;
                            channel.eof().await?;
                        }
                    }
                    ChannelMsg::Eof => {
                        tracing::info!(connection_name, "Server sent EOF, all done");
                        break;
                    }
                    ChannelMsg::WindowAdjusted { .. } => {}
                    _ => {
                        // For now, just error out on unexpected messages, to spot issues sooner. If
                        // this becomes not worth it we can just log and move on.
                        return Err(eyre::format_err!(format!("Unexpected message from server: {:?}", msg)));
                    }
                }
                None => {
                    break;
                }
            }
        }
    }

    if !prompt_found {
        return Err(eyre::format_err!(format!(
            "Did not detect a prompt after connecting to {connection_name}"
        )));
    }

    Ok(())
}

struct PermissiveSshClient;

impl russh::client::Handler for PermissiveSshClient {
    type Error = eyre::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
