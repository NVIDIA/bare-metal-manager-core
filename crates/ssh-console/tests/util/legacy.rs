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

use std::fs;
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Stdio;

use api_test_helper::utils::REPO_ROOT;
use eyre::Context;
use lazy_static::lazy_static;
use temp_dir::TempDir;

use crate::util::fixtures::{
    API_CA_CERT, API_CLIENT_CERT, API_CLIENT_KEY, AUTHORIZED_KEYS_PATH, SSH_HOST_KEY,
};
use crate::util::{BaselineTestEnvironment, MockBmcHandle, log_stdout_and_stderr};

lazy_static! {
    pub static ref LEGACY_SSH_CONSOLE_DIR: PathBuf =
        REPO_ROOT.join("crates/ssh-console/legacy/ssh-console");
    pub static ref LEGACY_SSH_CONSOLE_METRICS_PATH: PathBuf = "/tmp/ssh_console/metrics".into();
}

pub struct LegacySshConsoleHandle {
    pub addr: SocketAddr,
    _process: tokio::process::Child,
}

pub async fn run(
    env: &BaselineTestEnvironment,
    temp: &TempDir,
) -> eyre::Result<LegacySshConsoleHandle> {
    setup()
        .await
        .context("Error setting up legacy ssh-console")?;

    let addr = {
        // Pick an open port
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
            .to_socket_addrs()?
            .next()
            .expect("No socket available")
    };

    // Make sure the metrics path is created
    tokio::fs::create_dir_all(LEGACY_SSH_CONSOLE_METRICS_PATH.parent().unwrap()).await?;

    let bin = LEGACY_SSH_CONSOLE_DIR.join("ssh_console");

    tracing::info!("Launching legacy ssh-console at {}", bin.to_string_lossy());

    let known_hosts_path = temp.path().join("known_hosts");
    {
        let known_hosts_file = std::fs::File::create(&known_hosts_path)?;
        let mut writer = BufWriter::new(known_hosts_file);

        for mock_bmc_handle in &env.mock_bmc_handles {
            if let MockBmcHandle::Ssh(mock_ssh_server) = &mock_bmc_handle {
                writeln!(
                    writer,
                    "127.0.0.1:{} ssh-ed25519 {}",
                    mock_ssh_server.port, mock_ssh_server.host_pubkey
                )?;
            }
        }
    }

    assert_eq!(
        env.mock_bmc_handles.len(),
        1,
        "legacy tests only work against a single mock server"
    );
    let bmc_ssh_or_ipmi_port = env.mock_bmc_handles[0].port();

    let mut process = tokio::process::Command::new(&bin)
        .current_dir(LEGACY_SSH_CONSOLE_DIR.as_path())
        .arg("-v")
        .arg("-a")
        .arg(AUTHORIZED_KEYS_PATH.to_string_lossy().to_string())
        .arg("--insecure-ipmi-cipher")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("--bmc-ssh-port")
        .arg(bmc_ssh_or_ipmi_port.to_string())
        .arg("--ipmi-port")
        .arg(bmc_ssh_or_ipmi_port.to_string())
        .arg("-u")
        .arg(format!("localhost:{}", env.mock_api_server.addr.port()))
        .arg("-e")
        .arg(SSH_HOST_KEY.as_path())
        .arg("-k")
        .arg(known_hosts_path.as_os_str())
        .env("FORGE_ROOT_CA_PATH", API_CA_CERT.as_os_str())
        .env("CLIENT_CERT_PATH", API_CLIENT_CERT.as_os_str())
        .env("CLIENT_KEY_PATH", API_CLIENT_KEY.as_os_str())
        .env("SSH_PORT_OVERRIDE", "2222")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    log_stdout_and_stderr(&mut process, "legacy ssh-console");

    Ok(LegacySshConsoleHandle {
        addr,
        _process: process,
    })
}

pub async fn setup() -> eyre::Result<()> {
    if !LEGACY_SSH_CONSOLE_DIR.exists() {
        return Err(eyre::format_err!(
            "Legacy ssh-console source not found in {}. Either clone ssh-console from gitlab-master.nvidia.com/nvmetal/ssh-console, or symlink an existing clone to have working legacy tests.",
            LEGACY_SSH_CONSOLE_DIR.display()
        ));
    }
    if fs::exists(LEGACY_SSH_CONSOLE_DIR.join("ssh_console"))
        .context("Error checking if ssh_console binary exists")?
    {
        tracing::debug!("ssh_console binary already exists, not running setup");
        return Ok(());
    }

    let result = tokio::process::Command::new("make")
        .current_dir(LEGACY_SSH_CONSOLE_DIR.as_path())
        .spawn()
        .context("Error spawning `make` in legacy/ssh-console")?
        .wait()
        .await
        .context("Error running `make` in legacy/ssh-console")?;

    if !result.success() {
        return Err(eyre::eyre!(
            "`make` in legacy/ssh_console did not exit successfully"
        ));
    }
    Ok(())
}
