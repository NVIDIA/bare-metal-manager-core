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

use crate::util::log_stdout_and_stderr;
use api_test_helper::utils::REPO_ROOT;
use eyre::Context;
use lazy_static::lazy_static;
use machine_a_tron::HostMachineHandle;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Stdio;
use std::{
    fs,
    io::{BufWriter, Write},
};
use temp_dir::TempDir;

lazy_static! {
    static ref LEGACY_SSH_CONSOLE_DIR: PathBuf = REPO_ROOT.join("ssh-console/legacy/ssh-console");
    static ref LEGACY_SSH_HOST_PUBKEY: PathBuf = REPO_ROOT
        .join("ssh-console/legacy/ssh_host_ed25519_key.pub")
        .canonicalize()
        .unwrap();
    static ref LEGACY_SSH_HOST_KEY: PathBuf = REPO_ROOT
        .join("ssh-console/legacy/ssh_host_ed25519_key")
        .canonicalize()
        .unwrap();
    pub static ref API_CA_CERT: PathBuf = REPO_ROOT
        .join("dev/certs/localhost/ca.crt")
        .canonicalize()
        .unwrap();
    pub static ref API_CLIENT_CERT: PathBuf = REPO_ROOT
        .join("dev/certs/localhost/client.crt")
        .canonicalize()
        .unwrap();
    pub static ref API_CLIENT_KEY: PathBuf = REPO_ROOT
        .join("dev/certs/localhost/client.key")
        .canonicalize()
        .unwrap();
}

pub struct LegacySshConsoleHandle {
    pub addr: SocketAddr,
    _process: tokio::process::Child,
}

pub async fn run(
    carbide_port: u16,
    host_machine_handles: &[HostMachineHandle],
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

    let bin = LEGACY_SSH_CONSOLE_DIR.join("ssh_console");

    tracing::info!("Launching legacy ssh-console at {}", bin.to_string_lossy());

    let known_hosts_path = temp.path().join("known_hosts");
    {
        let known_hosts_file = std::fs::File::create(&known_hosts_path)?;
        let mut writer = BufWriter::new(known_hosts_file);

        for machine in host_machine_handles {
            if let (Some(bmc_ip), Some(bmc_host_pubkey)) =
                (machine.bmc_ip(), machine.bmc_ssh_host_pubkey())
            {
                writeln!(writer, "{} ssh-ed25519 {}", bmc_ip, bmc_host_pubkey)?;
            }
        }
    }

    let mut process = tokio::process::Command::new(&bin)
        .current_dir(LEGACY_SSH_CONSOLE_DIR.as_path())
        .arg("-v")
        .arg("-i")
        .arg("--insecure-ipmi-cipher")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("--bmc-ssh-port")
        .arg("2222")
        .arg("--ipmi-port")
        .arg("1623")
        .arg("-u")
        .arg(format!("localhost:{carbide_port}"))
        .arg("-e")
        .arg(LEGACY_SSH_HOST_KEY.as_path())
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
