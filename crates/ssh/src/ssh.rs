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

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use async_ssh2_tokio::{AuthMethod, Client, ServerCheckMethod};

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct SshError(#[from] pub async_ssh2_tokio::Error);

/// Configuration for russh's SSH client connections
fn russh_client_config() -> russh::client::Config {
    russh::client::Config {
        // Some BMC's use a Diffie-Hellman group size of 2048, which is not allowed by default.
        gex: russh::client::GexParams::new(2048, 8192, 8192)
            .expect("BUG: static DH group parameters must be valid"),
        keepalive_interval: Some(Duration::from_secs(60)),
        keepalive_max: 2,
        window_size: 2097152 * 3,
        maximum_packet_size: 65535,
        ..Default::default()
    }
}

async fn execute_command(
    command: &str,
    ip_address: SocketAddr,
    username: &str,
    password: &str,
) -> Result<(String, u32), SshError> {
    let auth_method = AuthMethod::with_password(password);
    let client = Client::connect_with_config(
        ip_address,
        username,
        auth_method,
        ServerCheckMethod::NoCheck,
        russh_client_config(),
    )
    .await?;
    let result = client.execute(command).await?;

    Ok((result.stdout, result.exit_status))
}

async fn scp_write<LOCAL, REMOTE>(
    local_path: LOCAL,
    remote_path: REMOTE,
    ip_address: SocketAddr,
    username: &str,
    password: &str,
) -> Result<(), SshError>
where
    LOCAL: AsRef<Path> + std::fmt::Display,
    REMOTE: Into<String>,
{
    let auth_method = AuthMethod::with_password(password);
    let client = Client::connect_with_config(
        ip_address,
        username,
        auth_method,
        ServerCheckMethod::NoCheck,
        russh_client_config(),
    )
    .await?;
    let timeout_secs = 20 * 60; // i'm seeing transfer speeds of 1.3MiB/sec with a 1.3GiB file, so....
    let buffer_size_bytes = 1024 * 1024; // this needs to be fairly large for a large file.
    let show_progress = true;
    client
        .upload_file(
            local_path,
            remote_path,
            Some(timeout_secs),
            Some(buffer_size_bytes),
            show_progress,
        )
        .await
        .map_err(|err| {
            tracing::error!("error during client.upload_file: {err:?}");
            err.into()
        })
}

pub async fn disable_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
) -> Result<(), SshError> {
    let command = "systemctl disable --now rshim";
    let (_stdout, _exit_code) =
        execute_command(command, ip_address, username.as_str(), password.as_str()).await?;
    Ok(())
}

pub async fn enable_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
) -> Result<(), SshError> {
    let command = "systemctl enable --now rshim";
    let (_stdout, _exit_code) =
        execute_command(command, ip_address, username.as_str(), password.as_str()).await?;
    Ok(())
}

pub async fn is_rshim_enabled(
    ip_address: SocketAddr,
    username: String,
    password: String,
) -> Result<bool, SshError> {
    let command = "systemctl is-active rshim";
    let (stdout, _exit_code) =
        execute_command(command, ip_address, username.as_str(), password.as_str()).await?;
    Ok(stdout.trim() == "active")
}

pub async fn copy_bfb_to_bmc_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
    bfb_path: String,
) -> Result<(), SshError> {
    scp_write(
        bfb_path,
        "/dev/rshim0/boot",
        ip_address,
        username.as_str(),
        password.as_str(),
    )
    .await?;
    Ok(())
}

pub async fn read_obmc_console_log(
    ip_address: SocketAddr,
    username: String,
    password: String,
) -> Result<String, SshError> {
    let command = "cat /var/log/obmc-console.log";
    let (stdout, _exit_code) =
        execute_command(command, ip_address, username.as_str(), password.as_str()).await?;
    Ok(stdout)
}
