/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
