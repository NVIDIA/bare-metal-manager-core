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

use std::fs::OpenOptions;
use std::io::Write;

use clap::CommandFactory;

include!("src/cfg/carbide_options.rs");

fn main() -> Result<(), std::io::Error> {
    forge_version::build();

    // Generate shell completion files for forge-admin-cli
    // They will appear in dev/shell/
    // For bash symlink it into `/etc/bash_completion.d` and restart your shell.

    if let Ok(root_dir) = std::env::var("REPO_ROOT") {
        let path = PathBuf::from(root_dir).join("dev").join("shell");
        let mut cmd = CarbideOptions::command();

        let bash_file = clap_complete::generate_to(
            clap_complete::shells::Bash,
            &mut cmd,
            "forge-admin-cli",
            &path,
        )?;
        // Make completion work for alias `fa`
        let mut f = OpenOptions::new().append(true).open(bash_file)?;
        let _ =
            f.write(b"complete -F _forge-admin-cli -o nosort -o bashdefault -o default fa\n")?;
        drop(f);

        clap_complete::generate_to(
            clap_complete::shells::Fish,
            &mut cmd,
            "forge-admin-cli",
            &path,
        )?;
        clap_complete::generate_to(
            clap_complete::shells::Zsh,
            &mut cmd,
            "forge-admin-cli",
            &path,
        )?;
    }
    Ok(())
}
