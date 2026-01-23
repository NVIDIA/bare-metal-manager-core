/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::Write;
use std::path::PathBuf;
use std::process::Command;

use carbide_uuid::machine::MachineId;

// FIXME: This should probably be configurable and come from the API's config
// file.
const SITE_OPERATOR: &str = "Forge-SRE (ngc-forge-sre@exchange.nvidia.com)";

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
    pub fn new(filename: PathBuf, header_comments: Vec<String>) -> Self {
        Self {
            filename,
            header_comments,
        }
    }

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
            Ok(s) => Err(eyre::eyre!("Unsuccessful exit status from lldpcli: {s}")),
            Err(e) => Err(eyre::eyre!("Couldn't run lldpcli: {e}")),
        }
    }
}

impl Default for LldpdConfigFileWriter {
    fn default() -> Self {
        let filename = "/etc/lldpd.d/forge.conf".into();
        let header_comment = vec!["This file is managed by the Forge DPU agent".into()];
        Self::new(filename, header_comment)
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
