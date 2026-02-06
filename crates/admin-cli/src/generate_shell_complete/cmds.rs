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

use std::io;
use std::io::Write;

use ::rpc::admin_cli::CarbideCliResult;
use clap::CommandFactory;

use super::args::Shell;
use crate::cfg::cli_options::CliOptions;

pub fn generate(shell: Shell) -> CarbideCliResult<()> {
    let mut cmd = CliOptions::command();
    match shell {
        Shell::Bash => {
            clap_complete::generate(
                clap_complete::shells::Bash,
                &mut cmd,
                "forge-admin-cli",
                &mut io::stdout(),
            );
            // Make completion work for alias `fa`
            io::stdout().write_all(
                b"complete -F _forge-admin-cli -o nosort -o bashdefault -o default fa\n",
            )?;
        }
        Shell::Fish => {
            clap_complete::generate(
                clap_complete::shells::Fish,
                &mut cmd,
                "forge-admin-cli",
                &mut io::stdout(),
            );
        }
        Shell::Zsh => {
            clap_complete::generate(
                clap_complete::shells::Zsh,
                &mut cmd,
                "forge-admin-cli",
                &mut io::stdout(),
            );
        }
    }
    Ok(())
}
