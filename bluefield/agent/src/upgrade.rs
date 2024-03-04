/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use data_encoding::BASE64;
use eyre::WrapErr;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

const UPGRADE_CMD: &str = "ip vrf exec mgmt apt-get update -o Dir::Etc::sourcelist=sources.list.d/forge.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 && DEBIAN_FRONTEND=noninteractive ip vrf exec mgmt apt-get install --yes --only-upgrade --reinstall forge-dpu";

/// Check if forge-dpu-agent needs upgrading to a new version, and if yes perform the upgrade
/// Returns true if we just updated and hence need to exit, so the new version can start instead.
pub async fn upgrade(
    forge_api: &str,
    client_config: ForgeClientConfig,
    machine_id: &str,
    // allow integration test to replace UPGRADE_CMD
    override_upgrade_cmd: Option<&str>,
) -> eyre::Result<bool> {
    let resp = match upgrade_check(forge_api, client_config, machine_id).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!("Failed upgrade check, forcing upgrade: {err:#}");
            UpgradeCheckResult {
                should_upgrade: true,
                ..Default::default()
            }
        }
    };
    if !resp.should_upgrade {
        tracing::trace!("forge-dpu-agent is up to date");
        return Ok(false);
    }

    // Upgrading!

    let binary_path = env::current_exe()?;

    // We do this for two reasons:
    // - Move the file back on upgrade failure
    // - Kernel prevents overwriting inode of running binary, we'd get ETXTBSY.
    let mut backup = binary_path.clone();
    backup.set_extension("BAK");

    // If the updates are overridden for unit-test purposes, then don't move
    // the binary. It will not be replaced by an update - and running the
    // unit-test would require it to be rebuilt
    if override_upgrade_cmd.is_none() {
        if let Err(err) = fs::rename(&binary_path, &backup) {
            tracing::warn!(
                "Failed backing up current binary: 'mv {} {}', {err}",
                binary_path.display(),
                backup.display()
            );
            // keep going - if the rename fails we still want the upgrade
        }
    }

    let upgrade_cmd = override_upgrade_cmd.unwrap_or(UPGRADE_CMD);
    tracing::info!(
        local_build = forge_version::v!(build_version),
        remote_build = resp.server_version,
        to_package_version = resp.package_version,
        upgrade_cmd,
        version = forge_version::v!(build_version),
        "Upgrading myself, goodbye.",
    );
    match run_upgrade_cmd(upgrade_cmd).await {
        Ok(()) => {
            // Upgrade succeeded, we need to restart. We do this by exiting and letting
            // systemd restart us.
            Ok(true)
        }
        Err(err) => {
            tracing::error!(upgrade_cmd, err = format!("{err:#}"), "Upgrade failed");
            if override_upgrade_cmd.is_none() {
                fs::rename(backup, binary_path)?;
            }
            eyre::bail!("run_upgrade_cmd failed");
        }
    }
}

async fn upgrade_check(
    forge_api: &str,
    client_config: ForgeClientConfig,
    machine_id: &str,
) -> eyre::Result<UpgradeCheckResult> {
    let binary_path = env::current_exe()?;
    let binary_mtime = mtime(binary_path.as_path())?;
    let binary_hash = hash_file(binary_path.as_path())?;
    network_upgrade_check(
        forge_api,
        client_config,
        machine_id,
        binary_mtime,
        binary_hash,
    )
    .await
}

fn mtime(p: &Path) -> eyre::Result<SystemTime> {
    let stat = fs::metadata(p).wrap_err_with(|| format!("Failed stat of '{}'", p.display()))?;
    let Ok(binary_mtime) = stat.modified() else {
        eyre::bail!(
            "Failed reading mtime of forge-dpu-agent binary at '{}'",
            p.display()
        );
    };
    Ok(binary_mtime)
}

fn hash_file(p: &Path) -> eyre::Result<String> {
    // blake3 is almost 2x faster than sha2's sha256 in release mode, and 35x faster in debug mode
    let mut hasher = blake3::Hasher::new();
    let mut f = fs::File::open(p).wrap_err_with(|| format!("open {}", p.display()))?;
    let mut buf = [0; 32768];
    loop {
        match f.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                hasher.update(&buf[..n]);
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(err.into());
            }
        }
    }
    let hash: [u8; 32] = hasher.finalize().into();
    Ok(BASE64.encode(&hash))
}

#[derive(Debug, Default)]
struct UpgradeCheckResult {
    should_upgrade: bool,
    package_version: Option<String>,
    server_version: Option<String>,
}

async fn network_upgrade_check(
    forge_api: &str,
    client_config: ForgeClientConfig,
    machine_id: &str,
    binary_mtime: SystemTime,
    binary_hash: String,
) -> eyre::Result<UpgradeCheckResult> {
    let local_build = forge_version::v!(build_version);
    let req = rpc::DpuAgentUpgradeCheckRequest {
        machine_id: machine_id.to_string(),
        current_agent_version: local_build.to_string(),
        binary_mtime: Some(binary_mtime.into()),
        binary_sha: binary_hash,
    };

    let mut client = forge_tls_client::ForgeTlsClient::new_and_connect(&ApiConfig::new(
        forge_api,
        client_config,
    ))
    .await?;
    let resp = client
        .dpu_agent_upgrade_check(tonic::Request::new(req))
        .await
        .map(|response| response.into_inner())?;

    Ok(UpgradeCheckResult {
        should_upgrade: resp.should_upgrade,
        package_version: Some(resp.package_version),
        server_version: Some(resp.server_version),
    })
}

async fn run_upgrade_cmd(upgrade_cmd: &str) -> eyre::Result<()> {
    let mut cmd = TokioCommand::new("bash");
    // Do not kill the upgrade command even if it hangs because that risks losing `/usr/bin/forge-dpu-agent`
    cmd.arg("-c").arg(upgrade_cmd).kill_on_drop(false);
    // This can easily take 60 seconds. systemd watchdog gives us 5 mins, so take 3.
    let out = timeout(Duration::from_secs(180), cmd.output())
        .await
        .wrap_err("Timeout")?
        .wrap_err("Error running command")?;
    if !out.status.success() {
        tracing::error!(" STDOUT: {}", String::from_utf8_lossy(&out.stdout));
        tracing::error!(" STDERR: {}", String::from_utf8_lossy(&out.stderr));
        eyre::bail!("Failed running upgrade command. Check logs for stdout/stderr.");
    }
    Ok(())
}
