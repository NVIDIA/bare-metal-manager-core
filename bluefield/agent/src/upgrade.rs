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

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientConfig};
use data_encoding::BASE64;
use eyre::WrapErr;
use tokio::process::Command as TokioCommand;

// __PKG_VERSION__ will be replaced by the package version
const UPGRADE_CMD: &str = "ip vrf exec mgmt apt-get update -o Dir::Etc::sourcelist=sources.list.d/forge.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 && ip vrf exec mgmt apt-get install --yes --only-upgrade forge-dpu=__PKG_VERSION__";

/// Check if forge-dpu-agent needs upgrading to a new version, and if yes perform the upgrade
/// Returns true if we just updated and hence need to exit, so the new version can start instead.
pub async fn upgrade_check(
    forge_api: &str,
    client_config: ForgeClientConfig,
    machine_id: &str,
    // allow integration test to replace UPGRADE_CMD
    override_upgrade_cmd: Option<&str>,
) -> eyre::Result<bool> {
    let binary_path = env::current_exe()?;
    let stat = fs::metadata(&binary_path)
        .wrap_err_with(|| format!("Failed stat of '{}'", binary_path.display()))?;
    let Ok(binary_mtime) = stat.modified() else {
        eyre::bail!(
            "Failed reading mtime of forge-dpu-agent binary at '{}'",
            binary_path.display()
        );
    };

    // blake3 is almost 2x faster than sha2's sha256 in release mode, and 35x faster in debug mode
    let mut hasher = blake3::Hasher::new();
    let mut f =
        fs::File::open(&binary_path).wrap_err_with(|| format!("open {}", binary_path.display()))?;
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

    let local_build = forge_version::v!(build_version);
    let req = rpc::DpuAgentUpgradeCheckRequest {
        machine_id: machine_id.to_string(),
        current_agent_version: local_build.to_string(),
        binary_mtime: Some(binary_mtime.into()),
        binary_sha: BASE64.encode(&hash),
    };

    let mut client = forge_tls_client::ForgeTlsClient::new(client_config)
        .connect(forge_api)
        .await?;
    let resp = client
        .dpu_agent_upgrade_check(tonic::Request::new(req))
        .await
        .map(|response| response.into_inner())?;

    if resp.should_upgrade {
        // We do this for two reason:
        // - Move the file back on upgrade failure
        // - Kernel prevents overwriting inode of running binary, we'd get ETXTBSY.
        let mut backup = binary_path.clone();
        backup.set_extension("BAK");
        fs::rename(&binary_path, &backup)
            .wrap_err_with(|| format!("mv {} {}", binary_path.display(), backup.display()))?;

        let upgrade_cmd = override_upgrade_cmd
            .unwrap_or(UPGRADE_CMD)
            .replace("__PKG_VERSION__", &resp.package_version);
        tracing::info!(
            local_build,
            remote_build = resp.server_version,
            to_package_version = resp.package_version,
            upgrade_cmd,
            version = forge_version::v!(build_version),
            "Upgrading myself, goodbye.",
        );
        match run_upgrade_cmd(&upgrade_cmd).await {
            Ok(()) => {
                // Upgrade succeeded, we need to restart. We do this by exiting and letting
                // systemd restart us.
                return Ok(true);
            }
            Err(err) => {
                tracing::error!(upgrade_cmd, err = format!("{err:#}"), "Upgrade failed");
                fs::rename(backup, binary_path)?;
                eyre::bail!("run_upgrade_cmd failed");
            }
        }
    } else {
        tracing::trace!("forge-dpu-agent is up to date");
    }
    Ok(false)
}

async fn run_upgrade_cmd(upgrade_cmd: &str) -> eyre::Result<()> {
    let out = TokioCommand::new("bash")
        .arg("-c")
        .arg(upgrade_cmd)
        .output()
        .await?;
    if !out.status.success() {
        tracing::error!(" STDOUT: {}", String::from_utf8_lossy(&out.stdout));
        tracing::error!(" STDERR: {}", String::from_utf8_lossy(&out.stderr));
        eyre::bail!("Failed running upgrade command. Check logs for stdout/stderr.");
    }
    Ok(())
}
