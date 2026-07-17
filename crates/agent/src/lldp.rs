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
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use carbide_uuid::machine::MachineId;
use eyre::WrapErr;

// FIXME: This should probably be configurable and come from the API's config
// file.
const SITE_OPERATOR: &str = "Forge-SRE (ngc-forge-sre@exchange.nvidia.com)";
const LLDP_INTERFACES_CONFIG: &str = "/etc/lldpd.d/lldp-interfaces.conf";
const DISABLED_LLDP_INTERFACES_CONFIG: &str = "/etc/lldpd.d/lldp-interfaces.conf.disabled";
const LLDPD_DEFAULT_CONFIG: &str = "/etc/default/lldpd";
const LLDPD_DAEMON_ARGS: &str = "DAEMON_ARGS=\"-M 1\"";
const LLDPD_RESTART_ATTEMPTS: u8 = 3;
const LLDP_MED_CONFIGURATION_CHECK_ATTEMPTS: u8 = 3;

pub(crate) fn prepare_lldp() -> eyre::Result<()> {
    let interfaces_config_disabled = disable_interfaces_config()?;
    let daemon_args_updated = ensure_lldpd_daemon_args()?;

    if interfaces_config_disabled || daemon_args_updated {
        restart_lldpd()?;
    }

    ensure_lldp_med_inventory_enabled()
}

fn disable_interfaces_config() -> eyre::Result<bool> {
    let source_path = Path::new(LLDP_INTERFACES_CONFIG);
    if !source_path.try_exists().wrap_err_with(|| {
        format!(
            "couldn't check existence of LLDP interfaces config {path}",
            path = source_path.display()
        )
    })? {
        return Ok(false);
    }

    let destination_path = Path::new(DISABLED_LLDP_INTERFACES_CONFIG);
    fs::rename(source_path, destination_path).wrap_err_with(|| {
        format!(
            "couldn't rename LLDP interfaces config from {source} to {destination}",
            source = source_path.display(),
            destination = destination_path.display()
        )
    })?;
    tracing::info!(
        source_path = %source_path.display(),
        destination_path = %destination_path.display(),
        "Disabled LLDP interfaces config"
    );

    Ok(true)
}

fn ensure_lldpd_daemon_args() -> eyre::Result<bool> {
    let current_contents =
        fs::read_to_string(LLDPD_DEFAULT_CONFIG).wrap_err("couldn't read lldpd default config")?;
    let mut daemon_args_found = false;
    let mut desired_contents = String::with_capacity(current_contents.len());

    for line in current_contents.split_inclusive('\n') {
        let line_contents = line.strip_suffix('\n').unwrap_or(line);
        let line_contents = line_contents.strip_suffix('\r').unwrap_or(line_contents);
        if line_contents.trim_start().starts_with("DAEMON_ARGS=") {
            daemon_args_found = true;
            desired_contents.push_str(LLDPD_DAEMON_ARGS);
            if line.ends_with("\r\n") {
                desired_contents.push_str("\r\n");
            } else if line.ends_with('\n') {
                desired_contents.push('\n');
            }
        } else {
            desired_contents.push_str(line);
        }
    }

    if !daemon_args_found {
        if !desired_contents.is_empty() && !desired_contents.ends_with('\n') {
            desired_contents.push('\n');
        }
        desired_contents.push_str(LLDPD_DAEMON_ARGS);
        desired_contents.push('\n');
    }

    let mut config_file =
        crate::agent_platform::ManagedFile::new(PathBuf::from(LLDPD_DEFAULT_CONFIG));
    let updated = config_file.ensure_contents(desired_contents.as_bytes())?;
    if updated {
        tracing::info!(
            path = LLDPD_DEFAULT_CONFIG,
            "Updated lldpd daemon arguments"
        );
    }

    Ok(updated)
}

fn lldp_med_inventory_disabled() -> eyre::Result<bool> {
    let output = Command::new("lldpcli")
        .args(["show", "configuration", "-f", "json0"])
        .output()
        .wrap_err("couldn't run lldpcli show configuration -f json0")?;
    if !output.status.success() {
        eyre::bail!(
            "lldpcli show configuration -f json0 failed with status {status}: {stderr}",
            status = output.status,
            stderr = String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let configuration: serde_json::Value = serde_json::from_slice(&output.stdout)
        .wrap_err("lldpcli returned invalid JSON configuration")?;
    let inventory_disabled = configuration
        .pointer("/configuration/0/config/0/lldpmed-no-inventory/0/value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("lldpcli configuration did not report LLDP-MED inventory"))?;

    match inventory_disabled {
        "yes" => Ok(true),
        "no" => Ok(false),
        value => eyre::bail!("lldpcli returned unexpected LLDP-MED inventory value {value:?}"),
    }
}

fn ensure_lldp_med_inventory_enabled() -> eyre::Result<()> {
    let mut attempt = 1;
    loop {
        match lldp_med_inventory_disabled() {
            Ok(false) => return Ok(()),
            Ok(true) if attempt == LLDP_MED_CONFIGURATION_CHECK_ATTEMPTS => {
                eyre::bail!(
                    "LLDP-MED inventory remained disabled after {attempt} configuration checks"
                );
            }
            Err(error) if attempt == LLDP_MED_CONFIGURATION_CHECK_ATTEMPTS => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "couldn't verify LLDP-MED inventory after {attempt} configuration checks"
                    )
                });
            }
            Ok(true) => {
                tracing::warn!(
                    attempt,
                    "LLDP-MED inventory is disabled, restarting lldpd service"
                );
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    attempt,
                    "Couldn't query LLDP-MED inventory, restarting lldpd service"
                );
            }
        }

        restart_lldpd()?;
        attempt += 1;
    }
}

fn restart_lldpd() -> eyre::Result<()> {
    let mut attempt = 1;
    loop {
        let restart_result = Command::new("systemctl")
            .args(["restart", "lldpd.service"])
            .status()
            .wrap_err("couldn't run systemctl restart lldpd.service")
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    eyre::bail!("systemctl restart lldpd.service failed with status {status}")
                }
            });

        match restart_result {
            Ok(()) => {
                tracing::info!(attempt, "Restarted lldpd service");
                return Ok(());
            }
            Err(error) if attempt == LLDPD_RESTART_ATTEMPTS => {
                tracing::error!(
                    error = %error,
                    attempt_count = attempt,
                    "Couldn't restart lldpd service"
                );
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(error = %error, attempt, "Couldn't restart lldpd service, retrying");
                std::thread::sleep(Duration::from_secs(u64::from(attempt)));
                attempt += 1;
            }
        }
    }
}

pub fn set_lldp_system_description(machine_id: &MachineId) -> eyre::Result<()> {
    let system_description = format!("{SITE_OPERATOR}, {machine_id}");
    let lldp_config = LldpConfig {
        system_description: Some(system_description),
    };
    let writer = LldpdConfigFileWriter::default();

    let file_updated = writer.ensure_file(&lldp_config)?;

    // If the file contents were updated, we'll ask lldpcli to read it in, which
    // updates the running config in the lldpd service.
    match file_updated {
        true => writer.daemon_read(),
        false => Ok(()),
    }
}

#[derive(Debug)]
pub struct LldpConfig {
    pub system_description: Option<String>,
}

#[derive(Debug)]
pub struct LldpdConfigFileWriter {
    pub filename: PathBuf,
    pub header_comments: Vec<String>,
}

impl LldpdConfigFileWriter {
    pub fn ensure_file(&self, config: &LldpConfig) -> eyre::Result<bool> {
        let file_contents = self.render_contents(config);
        let mut config_file = crate::agent_platform::ManagedFile::new(self.filename.to_owned());
        config_file.ensure_contents(file_contents.as_bytes())
    }

    fn render_contents(&self, config: &LldpConfig) -> String {
        let mut contents = String::new();

        for comment_line in self.header_comments.iter() {
            writeln!(&mut contents, "# {comment_line}").unwrap();
        }

        let LldpConfig { system_description } = config;
        if let Some(system_description) = system_description {
            writeln!(
                &mut contents,
                "configure system description \"{system_description}\""
            )
            .unwrap();
        }

        contents
    }

    // Ask lldpcli to read in the config file commands (which will be passed
    // to the running lldpd service).
    pub fn daemon_read(&self) -> eyre::Result<()> {
        let mut command = Command::new("lldpcli");
        command.arg("-c");
        command.arg(self.filename.as_os_str());
        match command.status() {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(eyre::eyre!("unsuccessful exit status from lldpcli: {s}")),
            Err(e) => Err(eyre::eyre!("couldn't run lldpcli: {e}")),
        }
    }
}

impl Default for LldpdConfigFileWriter {
    fn default() -> Self {
        Self {
            filename: "/etc/lldpd.d/forge.conf".into(),
            header_comments: vec!["This file is managed by the Forge DPU agent".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lldp_contents() {
        let lldp_config = LldpConfig {
            system_description: Some("deluxe toaster".into()),
        };
        let lldpd_writer = LldpdConfigFileWriter::default();
        let contents = lldpd_writer.render_contents(&lldp_config);

        let expected_contents = "# This file is managed by the Forge DPU agent\n\
            configure system description \"deluxe toaster\"\n";

        assert_eq!(contents.as_str(), expected_contents);
    }
}
