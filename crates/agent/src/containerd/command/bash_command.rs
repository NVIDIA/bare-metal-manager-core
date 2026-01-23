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
use std::time::Duration;

use eyre::WrapErr;

use crate::containerd::command::Command;
use crate::pretty_cmd;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BashCommand {
    command: String,
    args: Vec<String>,
    output: Option<String>,
}

impl BashCommand {
    pub fn new(command: &str) -> Self {
        BashCommand {
            command: command.to_string(),
            args: Vec::new(),
            output: None,
        }
    }

    pub fn args(self, args: Vec<&str>) -> Self {
        BashCommand {
            command: self.command,
            args: args.iter().map(|x| x.to_string()).collect(),
            output: self.output,
        }
    }
}

#[async_trait::async_trait]
impl Command for BashCommand {
    async fn run(&mut self) -> eyre::Result<String> {
        let mut cmd = tokio::process::Command::new(&self.command);
        let fullcmd = cmd.args(&self.args);
        fullcmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(fullcmd.as_std());

        let output = tokio::time::timeout(COMMAND_TIMEOUT, fullcmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {cmd_str:?}"))??;

        let fout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(fout)
    }
}
