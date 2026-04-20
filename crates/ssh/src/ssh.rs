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

/// Copy a BFB file to the BMC rshim device using the system `scp` binary.
/// The password is passed via `SSH_ASKPASS` with a temp script.
pub async fn copy_bfb_to_bmc_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
    bfb_path: String,
    is_bf2: bool,
) -> Result<(), SshError> {
    let timeout_secs: u64 = if is_bf2 { 80 * 60 } else { 30 * 60 };

    scp_cmd_write(
        &bfb_path,
        "/dev/rshim0/boot",
        ip_address,
        &username,
        &password,
        timeout_secs,
    )
    .await
}

/// Run a file copy using the system `scp` binary.
/// Password auth is handled via `SSH_ASKPASS` backed by a temp script.
async fn scp_cmd_write(
    local_path: &str,
    remote_path: &str,
    ip_address: SocketAddr,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<(), SshError> {
    let ip_str = ip_address.ip().to_string();
    let port_str = ip_address.port().to_string();

    tracing::info!(
        local_path,
        remote_path,
        %ip_address,
        "starting system scp copy to BMC rshim",
    );

    let askpass_dir = tempfile::tempdir().map_err(io_ssh_error)?;
    let askpass_path = askpass_dir.path().join("askpass.sh");
    {
        use std::os::unix::fs::PermissionsExt;
        let escaped = password.replace('\'', "'\\''");
        std::fs::write(
            &askpass_path,
            format!("#!/bin/sh\nprintf '%s' '{escaped}'\n"),
        )
        .map_err(io_ssh_error)?;
        std::fs::set_permissions(&askpass_path, std::fs::Permissions::from_mode(0o700))
            .map_err(io_ssh_error)?;
    }

    let mut child = tokio::process::Command::new("scp")
        .args([
            "-v",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "PubkeyAuthentication=no",
            "-P",
            &port_str,
            local_path,
            &format!("{username}@{ip_str}:{remote_path}"),
        ])
        .env("SSH_ASKPASS", &askpass_path)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "dummy")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(io_ssh_error)?;

    let stderr_pipe = child.stderr.take();
    let stderr_handle = tokio::spawn(async move {
        let mut saw_truncate_error = false;
        let mut saw_bytes_transferred = false;
        if let Some(stderr) = stderr_pipe {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.contains("truncate: Invalid argument") {
                    saw_truncate_error = true;
                }
                if line.contains("Bytes per second:") || line.starts_with("Transferred: sent") {
                    saw_bytes_transferred = true;
                }
            }
        }
        (saw_truncate_error, saw_bytes_transferred)
    });

    let result = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await;

    let (saw_truncate_error, saw_bytes_transferred) = stderr_handle.await.unwrap_or((false, false));

    let status = result
        .map_err(|_| {
            io_ssh_error(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("scp timed out after {} minutes", timeout_secs / 60),
            ))
        })?
        .map_err(io_ssh_error)?;

    if status.success() {
        tracing::info!(%ip_address, "scp copy to rshim completed");
        return Ok(());
    }

    if saw_truncate_error || saw_bytes_transferred {
        tracing::info!(
            %ip_address,
            saw_truncate_error,
            saw_bytes_transferred,
            "scp exited with {status} but transfer succeeded (device file write)",
        );
        return Ok(());
    }

    Err(io_ssh_error(std::io::Error::other(format!(
        "scp failed with {status} and no signs of successful transfer"
    ))))
}

fn io_ssh_error(e: std::io::Error) -> SshError {
    SshError(async_ssh2_tokio::Error::IoError(e))
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

/// Connect to the DPU serial console via `obmc-console-client` and check
/// whether any line matches the provided patterns. Returns `true` if at
/// least one pattern is found in the console output.
pub async fn check_console_for_markers(
    ip_address: SocketAddr,
    username: String,
    password: String,
    markers: &[&str],
) -> Result<bool, SshError> {
    let command = r#"(printf '\n'; sleep 2) | timeout 5 obmc-console-client 2>/dev/null; true"#;
    let (stdout, _exit_code) =
        execute_command(command, ip_address, username.as_str(), password.as_str()).await?;

    let found = stdout
        .lines()
        .any(|line| markers.iter().any(|marker| line.contains(marker)));
    Ok(found)
}
