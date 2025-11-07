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
mod workspace_deps;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "xtask")]
enum Xtask {
    #[clap(
        name = "check-workspace-deps",
        about = "Check for any dependency versions defined in crate-level Cargo.toml's instead of the workspace root"
    )]
    CheckWorkspaceDeps(CheckWorkspaceDeps),
}

#[derive(Parser, Debug)]
struct CheckWorkspaceDeps {
    #[clap(
        short,
        long,
        help = "Fix any dependencies defined in crate-level Cargo.toml's by moving them to the workspace root"
    )]
    fix: bool,
}

fn main() -> eyre::Result<()> {
    match Xtask::parse() {
        Xtask::CheckWorkspaceDeps(CheckWorkspaceDeps { fix }) => {
            workspace_deps::check(fix)?.report_and_exit()
        }
    };
}
