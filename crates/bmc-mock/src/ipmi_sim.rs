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

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::BmcState;
use crate::redfish::account_service::PasswordUpdater;
use crate::redfish::manager::ManagerState;

const START_ATTEMPTS: usize = 5;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const PASSWORD_UPDATE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct IpmiSimConfig {
    pub bind_ip: IpAddr,
    pub stable_id: String,
    pub console_prompt: String,
}

pub struct IpmiSimHandle {
    child: tokio::process::Child,
    _temp_dir: TempDir,
    _console: MockConsole,
    manager: Arc<ManagerState>,
    _password_updater: Arc<dyn PasswordUpdater>,
    pub ipmi_sim_lan_port: u16,
}

impl std::fmt::Debug for IpmiSimHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IpmiSimHandle")
            .field("ipmi_sim_lan_port", &self.ipmi_sim_lan_port)
            .finish_non_exhaustive()
    }
}

impl Drop for IpmiSimHandle {
    fn drop(&mut self) {
        self.child.start_kill().ok();
        self.manager.set_ipmi_endpoint(None);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the BMC mock has no administrative account")]
    MissingAdministrativeAccount,
    #[error("the IPMI simulator {0} contains unsupported characters")]
    UnsupportedCredentialCharacters(&'static str),
    #[error("failed to prepare IPMI simulator: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipmi_sim exited during startup with status {0}")]
    EarlyExit(std::process::ExitStatus),
    #[error("ipmi_sim did not claim its ports within {READY_TIMEOUT:?}")]
    ReadinessTimeout,
    #[error("ipmi_sim failed to start after {START_ATTEMPTS} attempts: {0}")]
    AttemptsExhausted(Box<Error>),
}

struct Reservations {
    ipmi_sim_lan_socket: UdpSocket,
    ipmi_sim_serial_listener: TcpListener,
}

impl Reservations {
    fn new(bind_ip: IpAddr) -> Result<Self, std::io::Error> {
        Ok(Self {
            ipmi_sim_lan_socket: UdpSocket::bind(SocketAddr::new(bind_ip, 0))?,
            ipmi_sim_serial_listener: TcpListener::bind((
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ))?,
        })
    }

    fn ipmi_sim_lan_port(&self) -> Result<u16, std::io::Error> {
        Ok(self.ipmi_sim_lan_socket.local_addr()?.port())
    }

    fn ipmi_sim_serial_port(&self) -> Result<u16, std::io::Error> {
        Ok(self.ipmi_sim_serial_listener.local_addr()?.port())
    }
}

pub async fn start(state: &BmcState, config: IpmiSimConfig) -> Result<IpmiSimHandle, Error> {
    let (username, password) = state
        .account_service_state
        .administrator_credentials()
        .ok_or(Error::MissingAdministrativeAccount)?;
    validate_credential("username", &username)?;
    validate_credential("password", &password)?;
    let temp_dir = tempfile::Builder::new()
        .prefix("bmc-mock-ipmi-")
        .tempdir()?;
    std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700))?;

    let console = MockConsole::start(config.console_prompt.clone()).await?;
    let mut last_error = None;

    for attempt in 1..=START_ATTEMPTS {
        let reservations = Reservations::new(config.bind_ip)?;
        let ipmi_sim_lan_port = reservations.ipmi_sim_lan_port()?;
        let ipmi_sim_serial_port = reservations.ipmi_sim_serial_port()?;
        let state_dir = temp_dir.path().join(format!("state-{attempt}"));
        std::fs::create_dir(&state_dir)?;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        write_config(
            temp_dir.path(),
            &config,
            &username,
            &password,
            ipmi_sim_lan_port,
            ipmi_sim_serial_port,
            console.bmc_mock_console_port,
        )?;

        drop(reservations);
        let mut child = tokio::process::Command::new("ipmi_sim")
            .current_dir(temp_dir.path())
            .arg("-c")
            .arg(temp_dir.path().join("lan.conf"))
            .arg("-f")
            .arg(temp_dir.path().join("cmd.conf"))
            .arg("-s")
            .arg(state_dir)
            .arg("--nostdio")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;

        match wait_until_ready(
            &mut child,
            config.bind_ip,
            ipmi_sim_lan_port,
            ipmi_sim_serial_port,
        )
        .await
        {
            Ok(()) => {
                let connect_ip = if config.bind_ip.is_unspecified() {
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                } else {
                    config.bind_ip
                };
                let password_updater: Arc<dyn PasswordUpdater> = Arc::new(IpmiPasswordUpdater {
                    connect_ip,
                    ipmi_sim_lan_port,
                });
                state
                    .account_service_state
                    .set_password_updater(&password_updater);
                state.manager.set_ipmi_endpoint(Some(ipmi_sim_lan_port));
                return Ok(IpmiSimHandle {
                    child,
                    _temp_dir: temp_dir,
                    _console: console,
                    manager: state.manager.clone(),
                    _password_updater: password_updater,
                    ipmi_sim_lan_port,
                });
            }
            Err(error) => {
                child.kill().await.ok();
                last_error = Some(error);
                tracing::warn!(
                    attempt,
                    ipmi_sim_lan_port,
                    ipmi_sim_serial_port,
                    "ipmi_sim startup failed; retrying"
                );
            }
        }
    }

    Err(Error::AttemptsExhausted(Box::new(
        last_error.expect("at least one startup attempt ran"),
    )))
}

struct IpmiPasswordUpdater {
    connect_ip: IpAddr,
    ipmi_sim_lan_port: u16,
}

impl PasswordUpdater for IpmiPasswordUpdater {
    fn update_password<'a>(
        &'a self,
        username: &'a str,
        current_password: &'a str,
        new_password: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let connect_ip = self.connect_ip.to_string();
            let ipmi_sim_lan_port = self.ipmi_sim_lan_port.to_string();
            let mut command = [
                "-I",
                "lanplus",
                "-H",
                connect_ip.as_str(),
                "-p",
                ipmi_sim_lan_port.as_str(),
                "-U",
                username,
                "-E",
                "-C",
                "3",
                "user",
                "set",
                "password",
                "3",
                new_password,
                "20",
            ]
            .into_iter()
            .fold(
                tokio::process::Command::new("ipmitool"),
                |mut command, argument| {
                    command.arg(argument);
                    command
                },
            );
            command
                .env("IPMI_PASSWORD", current_password)
                .kill_on_drop(true);
            let output = tokio::time::timeout(PASSWORD_UPDATE_TIMEOUT, command.output())
                .await
                .map_err(|_| format!("ipmitool timed out after {PASSWORD_UPDATE_TIMEOUT:?}"))?
                .map_err(|error| format!("failed to execute ipmitool: {error}"))?;
            if output.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "ipmitool exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        })
    }
}

fn validate_credential(field: &'static str, value: &str) -> Result<(), Error> {
    if value
        .chars()
        .any(|character| character == '"' || character == '\\' || character.is_control())
    {
        return Err(Error::UnsupportedCredentialCharacters(field));
    }
    Ok(())
}

fn write_config(
    base: &Path,
    config: &IpmiSimConfig,
    username: &str,
    password: &str,
    ipmi_sim_lan_port: u16,
    ipmi_sim_serial_port: u16,
    bmc_mock_console_port: u16,
) -> Result<(), std::io::Error> {
    let lan_config = format!(
        r#"name "ManagedHostBmc"
set_working_mc 0x20

startlan 1
  addr {} {ipmi_sim_lan_port}
  priv_limit admin
  allowed_auths_admin none md2 md5 straight none
  guid {}
endlan

user 1 true "" "" user 10 none md2 md5 straight none
user 2 true "admin" "admin" admin 10 none md2 md5 straight none
user 3 true "{username}" "{password}" admin 10 none md2 md5 straight none

chassis_control "./chassis-control.sh 0x20"
serial 15 127.0.0.1 {ipmi_sim_serial_port} codec VM ipmb 0x20
sol "telnet:127.0.0.1:{bmc_mock_console_port}" 115200
"#,
        config.bind_ip,
        stable_guid(&config.stable_id),
    );

    write_private_file(&base.join("lan.conf"), lan_config.as_bytes(), 0o600)?;
    write_private_file(
        &base.join("cmd.conf"),
        include_bytes!("../../../dev/ipmi/cmd.conf"),
        0o600,
    )?;
    write_private_file(
        &base.join("chassis-control.sh"),
        include_bytes!("../../../dev/ipmi/ipmi_sim_chassiscontrol.sh"),
        0o700,
    )?;
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), std::io::Error> {
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn stable_guid(stable_id: &str) -> String {
    let mut bytes = [0_u8; 16];
    for (index, value) in stable_id.bytes().enumerate() {
        let slot = index % bytes.len();
        bytes[slot] = bytes[slot]
            .wrapping_mul(31)
            .wrapping_add(value)
            .wrapping_add(index as u8);
    }
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

async fn wait_until_ready(
    child: &mut tokio::process::Child,
    bind_ip: IpAddr,
    ipmi_sim_lan_port: u16,
    ipmi_sim_serial_port: u16,
) -> Result<(), Error> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Error::EarlyExit(status));
        }

        if udp_port_is_claimed(bind_ip, ipmi_sim_lan_port)?
            && tcp_port_is_claimed(ipmi_sim_serial_port)?
        {
            tokio::time::sleep(READY_POLL_INTERVAL).await;
            if let Some(status) = child.try_wait()? {
                return Err(Error::EarlyExit(status));
            }
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(Error::ReadinessTimeout);
        }
        tokio::time::sleep(READY_POLL_INTERVAL).await;
    }
}

fn udp_port_is_claimed(bind_ip: IpAddr, port: u16) -> Result<bool, std::io::Error> {
    port_is_claimed(UdpSocket::bind(SocketAddr::new(bind_ip, port)))
}

fn tcp_port_is_claimed(port: u16) -> Result<bool, std::io::Error> {
    port_is_claimed(TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)))
}

fn port_is_claimed<T>(result: Result<T, std::io::Error>) -> Result<bool, std::io::Error> {
    match result {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == ErrorKind::AddrInUse => Ok(true),
        Err(error) => Err(error),
    }
}

struct MockConsole {
    bmc_mock_console_port: u16,
    task: JoinHandle<()>,
}

impl Drop for MockConsole {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockConsole {
    async fn start(prompt: String) -> Result<Self, std::io::Error> {
        let listener = TokioTcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let bmc_mock_console_port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let prompt = prompt.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_console(stream, &prompt).await {
                        tracing::debug!(%error, "mock SOL console connection closed with error");
                    }
                });
            }
        });
        Ok(Self {
            bmc_mock_console_port,
            task,
        })
    }
}

async fn serve_console(mut stream: TcpStream, prompt: &str) -> Result<(), std::io::Error> {
    let mut input = Vec::new();
    let mut buffer = [0_u8; 32];
    loop {
        let length = stream.read(&mut buffer).await?;
        if length == 0 {
            return Ok(());
        }
        input.extend_from_slice(&buffer[..length]);
        stream.write_all(&buffer[..length]).await?;
        if input.ends_with(b"\n") || input.ends_with(b"\r") {
            input.clear();
            stream.write_all(format!("\r\n{prompt}").as_bytes()).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, MockConsole, stable_guid, validate_credential};

    #[test]
    fn stable_guid_is_stable_and_has_ipmi_length() {
        assert_eq!(stable_guid("machine-1"), stable_guid("machine-1"));
        assert_ne!(stable_guid("machine-1"), stable_guid("machine-2"));
        assert_eq!(stable_guid("machine-1").len(), 32);
    }

    #[test]
    fn credential_validation_rejects_ipmi_sim_syntax_characters() {
        for value in [
            "double\"quote",
            "back\\slash",
            "line\nfeed",
            "carriage\rreturn",
            "nul\0byte",
        ] {
            assert!(matches!(
                validate_credential("password", value),
                Err(Error::UnsupportedCredentialCharacters("password"))
            ));
        }
    }

    #[test]
    fn credential_validation_accepts_plain_credentials() {
        assert!(validate_credential("username", "root-admin").is_ok());
        assert!(validate_credential("password", "Welcome123! @$%^&*()").is_ok());
    }

    #[tokio::test]
    async fn dropping_mock_console_releases_listener() {
        let console = MockConsole::start("prompt".to_string()).await.unwrap();
        let port = console.bmc_mock_console_port;

        drop(console);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("failed to probe console listener: {error}"),
                }
            }
        })
        .await
        .expect("mock console listener was not released");
    }
}
