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
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use api_test_helper::utils::REPO_ROOT;
use eyre::Context;
use lazy_static::lazy_static;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::openpty;
use nix::unistd;
use temp_dir::TempDir;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::util::log_stdout_and_stderr;

lazy_static! {
    static ref IPMI_SCRIPTS_DIR: PathBuf = REPO_ROOT.join("dev/ipmi").canonicalize().unwrap();
}

pub struct IpmiSimHandle {
    _ipmi_sim: tokio::process::Child,
    _temp_dir: TempDir,
    _mock_serial_console: MockSerialConsoleHandle,
    pub port: u16,
}

pub struct ActiveSolSession {
    _ipmitool: tokio::process::Child,
    _pty_master: AsyncFd<OwnedFd>,
}

impl ActiveSolSession {
    pub async fn assert_console_works(&self, expected_prompt: &[u8]) -> eyre::Result<()> {
        const PROBE: &[u8] = b"original-sol-owner-probe\r";

        tokio::time::timeout(Duration::from_secs(10), async {
            let mut written = 0;
            while written < PROBE.len() {
                let mut guard = self._pty_master.writable().await?;
                match unistd::write(&self._pty_master, &PROBE[written..]) {
                    Ok(0) => return Err(eyre::eyre!("conflicting SOL session PTY closed")),
                    Ok(n) => written += n,
                    Err(Errno::EWOULDBLOCK) => guard.clear_ready(),
                    Err(error) => return Err(error.into()),
                }
            }

            let mut output = Vec::new();
            let mut buf = [0; 1024];
            loop {
                let mut guard = self._pty_master.readable().await?;
                match unistd::read(guard.get_inner(), &mut buf) {
                    Ok(0) | Err(Errno::EIO) => {
                        return Err(eyre::eyre!(
                            "conflicting SOL session closed while probing it: {}",
                            String::from_utf8_lossy(&output)
                        ));
                    }
                    Ok(n) => {
                        output.extend_from_slice(&buf[..n]);
                        if output
                            .windows(PROBE.len())
                            .position(|window| window == PROBE)
                            .is_some_and(|probe_start| {
                                output[probe_start + PROBE.len()..]
                                    .windows(expected_prompt.len())
                                    .any(|window| window == expected_prompt)
                            })
                        {
                            return Ok::<(), eyre::Report>(());
                        }
                    }
                    Err(Errno::EWOULDBLOCK) => guard.clear_ready(),
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
        .context("timed out probing the original conflicting SOL session")?
    }
}

pub async fn activate_sol(port: u16) -> eyre::Result<ActiveSolSession> {
    let pty = openpty(None, None).context("failed to allocate ipmitool pty")?;
    set_nonblocking(&pty.master).context("failed to make ipmitool pty nonblocking")?;

    let mut command = tokio::process::Command::new("ipmitool");
    command
        .arg("-I")
        .arg("lanplus")
        .arg("-H")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .arg("-U")
        .arg("root")
        .arg("-P")
        .arg("password")
        .arg("-C")
        .arg("3")
        .arg("sol")
        .arg("activate")
        .stdin(pty.slave.try_clone().context("clone pty for stdin")?)
        .stdout(pty.slave.try_clone().context("clone pty for stdout")?)
        .stderr(pty.slave.try_clone().context("clone pty for stderr")?)
        .kill_on_drop(true);

    let pty_slave_fd = pty.slave.as_raw_fd();
    // SAFETY: this runs in the child between fork and exec to give interactive ipmitool a terminal.
    unsafe {
        command.pre_exec(move || {
            unistd::setsid()?;
            if libc::ioctl(pty_slave_fd, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let ipmitool = command
        .spawn()
        .context("failed to start conflicting SOL session")?;
    drop(command);
    drop(pty.slave);
    let pty_master = AsyncFd::new(pty.master).context("failed to register ipmitool pty")?;

    tokio::time::timeout(Duration::from_secs(10), async {
        let mut output = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let mut guard = pty_master.readable().await?;
            match unistd::read(guard.get_inner(), &mut buf) {
                Ok(0) | Err(Errno::EIO) => {
                    return Err(eyre::eyre!(
                        "ipmitool exited before activating SOL: {}",
                        String::from_utf8_lossy(&output)
                    ));
                }
                Ok(n) => {
                    output.extend_from_slice(&buf[..n]);
                    if output
                        .windows(b"SOL Session operational".len())
                        .any(|window| window == b"SOL Session operational")
                    {
                        return Ok::<(), eyre::Report>(());
                    }
                }
                Err(Errno::EWOULDBLOCK) => guard.clear_ready(),
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("timed out waiting for the conflicting SOL session to activate")??;

    Ok(ActiveSolSession {
        _ipmitool: ipmitool,
        _pty_master: pty_master,
    })
}

fn set_nonblocking(fd: &OwnedFd) -> nix::Result<()> {
    let current_flags = fcntl(fd, FcntlArg::F_GETFL)?;
    fcntl(
        fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(current_flags) | OFlag::O_NONBLOCK),
    )?;
    Ok(())
}

/// Run an instance of ipmi_sim and a corresponding instance of a mock serial console, for tests to
/// use. Accepts a `prompt` parameter which will be echoed back when the clients send data (for
/// tests to assert that it's the expected host.)
pub async fn run(prompt: String) -> eyre::Result<IpmiSimHandle> {
    // Run a simple echo server to pretend it's a serial console. ipmi_sim talks to this through
    // telnet to emulate a serial connection.
    let mock_serial_console = run_mock_serial_console(prompt).await?;

    let temp_dir = TempDir::new()?;

    // Allocate 2 ports for ipmi_sim: One for lanplus communication, and another for serial
    // communications
    let ipmi_sim_lanplus_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?.port()
    };
    let ipmi_sim_serial_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?.port()
    };

    tracing::debug!(
        "ipmi_sim will listen on port {ipmi_sim_lanplus_port} and {ipmi_sim_serial_port}"
    );

    let mock_serial_console_port = mock_serial_console.port;

    let ipmi_state_dir = temp_dir.path().join("ipmi_state");
    let lan_conf = temp_dir.path().join("lan.conf");
    let cmd_conf = temp_dir.path().join("cmd.conf");
    let chassis_control = temp_dir.path().join("ipmi_sim_chassiscontrol.sh");

    // Build config to talk to our mock console for `sol activate` commands
    std::fs::create_dir(&ipmi_state_dir)?;
    std::fs::write(
        &lan_conf,
        format!(
            r#"
name "ManagedHostBmC"
set_working_mc 0x20

startlan 1
  addr 0.0.0.0 {ipmi_sim_lanplus_port}
  priv_limit admin
  allowed_auths_admin none md2 md5 straight none
  guid 61120bdcc43211edb674ef2f47d8b462
endlan

user 1 true  ""      ""      user     10       none md2 md5 straight none
user 2 true  "admin" "admin" admin    10       none md2 md5 straight none
user 3 true  "root" "password" admin    10       none md2 md5 straight none

# Note: chassis_control is unused right now, but it's in the dev/ipmi directory and can be used to
# simulate power control commands.
chassis_control "./ipmi_sim_chassiscontrol.sh 0x20"
serial 15 0.0.0.0 {ipmi_sim_serial_port} codec VM ipmb 0x20
sol "telnet:127.0.0.1:{mock_serial_console_port}" 115200
    "#
        ),
    )?;

    std::fs::write(&cmd_conf, include_bytes!("../../../../dev/ipmi/cmd.conf"))?;

    std::fs::write(
        &chassis_control,
        include_bytes!("../../../../dev/ipmi/ipmi_sim_chassiscontrol.sh"),
    )?;
    std::fs::set_permissions(&chassis_control, PermissionsExt::from_mode(0o755))?;

    // Then run ipmi_sim
    tracing::info!("Launching ipmi_sim");
    let mut process = tokio::process::Command::new("ipmi_sim")
        .current_dir(temp_dir.path())
        .arg("-c")
        .arg(lan_conf.as_path())
        .arg("-f")
        .arg(cmd_conf.as_path())
        .arg("-s")
        .arg(ipmi_state_dir.as_path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn ipmi_sim")?;
    log_stdout_and_stderr(&mut process, "ipmi_sim");

    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(IpmiSimHandle {
        _ipmi_sim: process,
        _temp_dir: temp_dir,
        _mock_serial_console: mock_serial_console,
        port: ipmi_sim_lanplus_port,
    })
}

pub async fn run_mock_serial_console(prompt: String) -> eyre::Result<MockSerialConsoleHandle> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tracing::debug!("mock serial console: listening on port {port}");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((tcp_stream, addr)) => {
                            tracing::debug!("mock serial console: got connection from {addr}");
                            tokio::spawn({
                                let prompt = prompt.clone();
                                async move {
                                    match handle_mock_console_client(tcp_stream, prompt.clone()).await {
                                        Ok(()) => {}
                                        Err(error) => {
                                            tracing::error!(?error, "mock serial console: error handling client in mock_serial_console");
                                        }
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            tracing::error!(?error, "mock serial console: error accepting connection");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::debug!("mock serial console: shutting down");
                    break;
                }
            }
        }
    });
    Ok(MockSerialConsoleHandle {
        _shutdown_tx: shutdown_tx,
        port,
    })
}

pub struct MockSerialConsoleHandle {
    _shutdown_tx: oneshot::Sender<()>,
    pub port: u16,
}

async fn handle_mock_console_client(mut tcp_stream: TcpStream, prompt: String) -> eyre::Result<()> {
    let mut input = Vec::new();
    let mut read_buf = [0u8; 32];
    loop {
        match tcp_stream.read(&mut read_buf).await {
            Ok(len) => {
                if len == 0 {
                    tracing::debug!("eof from mock console client");
                    break;
                }
                input.extend_from_slice(&read_buf[..len]);
                tcp_stream.write_all(&read_buf[..len]).await?;
                if input.ends_with(b"\n") || input.ends_with(b"\r") {
                    input.clear();
                    tcp_stream
                        .write_all(format!("\r\n{prompt}").as_bytes())
                        .await?;
                }
            }
            Err(error) => {
                return Err(eyre::format_err!(
                    "error reading from mock console client: {error:?}"
                ));
            }
        }
    }

    Ok(())
}
