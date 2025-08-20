/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use humantime::format_duration;
use ssh2::Session;
use std::fs::{File, metadata};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fmt, io};
use thiserror::Error;
use tokio::task::JoinError;

pub const DEFAULT_TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
// Copying the BFB takes roughly 6 minutes. Our chunk size is 1MB
pub const DEFAULT_TCP_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_SSH_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Error, Debug)]
pub enum SshError {
    #[error("SSH error: {0}")]
    Ssh2Error(#[from] ssh2::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Join error: {0}")]
    JoinError(#[from] JoinError),

    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub tcp_connection_timeout: Duration,
    pub tcp_read_timeout: Duration,
    pub tcp_write_timeout: Duration,
    pub ssh_session_timeout: Duration,
}

impl SshConfig {
    fn valid(&self) -> bool {
        self.ssh_session_timeout < MAX_TIMEOUT
            && self.tcp_write_timeout < MAX_TIMEOUT
            && self.tcp_read_timeout < MAX_TIMEOUT
            && self.tcp_connection_timeout < MAX_TIMEOUT
    }
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            tcp_connection_timeout: DEFAULT_TCP_CONNECTION_TIMEOUT,
            tcp_read_timeout: DEFAULT_TCP_READ_TIMEOUT,
            tcp_write_timeout: DEFAULT_TCP_WRITE_TIMEOUT,
            ssh_session_timeout: DEFAULT_SSH_SESSION_TIMEOUT,
        }
    }
}

impl fmt::Display for SshConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone)]
struct SshClient {
    session: Session,
    ip_address: IpAddr,
}

impl SshClient {
    fn connect(
        ip_address: SocketAddr,
        username: String,
        password: String,
        config: Option<SshConfig>,
    ) -> Result<Self, SshError> {
        let config = config.unwrap_or_default();
        if !config.valid() {
            return Err(SshError::Other(format!("Invalid SSH config {config:#}")));
        }

        // Establish TCP connection to BMC
        // set tcp connection timeout
        let tcp = TcpStream::connect_timeout(&ip_address, config.tcp_connection_timeout)?;

        // set tcp read/write timeout
        tcp.set_read_timeout(Some(config.tcp_read_timeout))?;
        tcp.set_write_timeout(Some(config.tcp_write_timeout))?;

        tracing::info!(
            "Established TCP connection to BMC {ip_address} with a connection timeout of {}, a read timeout of {}, and a write timeout of {}",
            format_duration(config.tcp_connection_timeout),
            format_duration(config.tcp_read_timeout),
            format_duration(config.tcp_write_timeout),
        );

        // Initialize SSH session
        let mut session = Session::new()?;
        session.set_tcp_stream(tcp.try_clone()?);
        session.handshake()?;

        // set SSH session timeout
        session.set_timeout(config.ssh_session_timeout.as_millis() as u32);

        tracing::info!(
            "Initialized SSH session with BMC {ip_address} with a session timeout of {}",
            format_duration(config.ssh_session_timeout)
        );

        // Authenticate with username/password
        session.userauth_password(&username, &password)?;

        // Verify authentication succeeded
        if session.authenticated() {
            Ok(Self {
                session,
                ip_address: ip_address.ip(),
            })
        } else {
            Err(SshError::Other("Authentication failed".into()))
        }
    }

    fn close(&self) -> Result<(), SshError> {
        // Explicitly clean up the SSH session and TCP connection
        self.session.disconnect(None, "Session closed", None)?;
        // The TCP connection will be closed when the value is dropped
        Ok(())
    }

    fn scp_write(&self, local_path: String, remote_path: String) -> Result<(), SshError> {
        let file_size = metadata(local_path.clone())?.len();
        let mut local_file = File::open(local_path.clone())?;

        let mut remote_file =
            self.session
                .scp_send(Path::new(&remote_path), 0o644, file_size, None)?;

        let ip = self.ip_address;
        let mut buffer = vec![0; 1024 * 1024]; // 1 MB buffer
        let mut total_bytes_copied = 0;
        let mut next_progress_marker = 10.0;

        let start_time = Instant::now();
        loop {
            let n = local_file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            remote_file.write_all(&buffer[..n])?;
            total_bytes_copied += n as u64;
            let progress = (total_bytes_copied as f64 / file_size as f64) * 100.0;
            if progress >= next_progress_marker {
                tracing::info!(
                    "Progress of SCP from {local_path} to {ip}:{remote_path}: {:.0}%",
                    next_progress_marker
                );
                next_progress_marker += 10.0;
            }
        }

        remote_file.send_eof()?;
        remote_file.wait_eof()?;
        remote_file.wait_close()?;

        tracing::info!(
            "SCP from {local_path} to {ip}:{remote_path} completed successfully in {}",
            format_duration(start_time.elapsed())
        );

        Ok(())
    }

    fn execute_command(&self, command: &str) -> Result<(String, i32), SshError> {
        let mut channel = self.session.channel_session()?;
        channel.exec(command)?;
        let mut output = String::new();
        channel.read_to_string(&mut output)?;
        channel.send_eof()?;
        channel.wait_eof()?;
        channel.wait_close()?;
        Ok((output, channel.exit_status()?))
    }
}

struct AsyncSshClient {
    ip_address: SocketAddr,
    username: String,
    password: String,
    config: Option<SshConfig>,
}

impl AsyncSshClient {
    async fn scp_write(&self, local_path: String, remote_path: String) -> Result<(), SshError> {
        let local_path = local_path.clone();
        let remote_path = remote_path.clone();
        let ip_address = self.ip_address;
        let username = self.username.clone();
        let password = self.password.clone();
        let config = self.config.clone();

        tokio::task::spawn_blocking(move || {
            let client = SshClient::connect(ip_address, username, password, config)?;
            client.scp_write(local_path, remote_path)?;
            client.close()
        })
        .await?
    }

    async fn execute_command(&self, command: &str) -> Result<(String, i32), SshError> {
        let command = command.to_string();
        let ip_address = self.ip_address;
        let username = self.username.clone();
        let password = self.password.clone();
        let config = self.config.clone();

        tokio::task::spawn_blocking(move || {
            let client = SshClient::connect(ip_address, username, password, config)?;
            let result = client.execute_command(&command)?;
            client.close()?;
            Ok(result)
        })
        .await?
    }
}

pub async fn disable_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
    config: Option<SshConfig>,
) -> Result<(), SshError> {
    let _ = AsyncSshClient {
        ip_address,
        username,
        password,
        config,
    }
    .execute_command("systemctl disable --now rshim")
    .await?;
    Ok(())
}

pub async fn enable_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
    config: Option<SshConfig>,
) -> Result<(), SshError> {
    let _ = AsyncSshClient {
        ip_address,
        username,
        password,
        config,
    }
    .execute_command("systemctl enable --now rshim")
    .await?;
    Ok(())
}

pub async fn is_rshim_enabled(
    ip_address: SocketAddr,
    username: String,
    password: String,
    config: Option<SshConfig>,
) -> Result<bool, SshError> {
    let (output, _status_code) = AsyncSshClient {
        ip_address,
        username,
        password,
        config,
    }
    .execute_command("systemctl is-active rshim")
    .await?;

    Ok(output.trim() == "active")
}

pub async fn copy_bfb_to_bmc_rshim(
    ip_address: SocketAddr,
    username: String,
    password: String,
    config: Option<SshConfig>,
    bfb_path: String,
) -> Result<(), SshError> {
    AsyncSshClient {
        ip_address,
        username,
        password,
        config,
    }
    .scp_write(bfb_path, "/dev/rshim0/boot".to_string())
    .await?;
    Ok(())
}

pub async fn read_obmc_console_log(
    ip_address: SocketAddr,
    username: String,
    password: String,
    config: Option<SshConfig>,
) -> Result<String, SshError> {
    let (output, _status_code) = AsyncSshClient {
        ip_address,
        username,
        password,
        config,
    }
    .execute_command("cat /var/log/obmc-console.log")
    .await?;

    Ok(output)
}
