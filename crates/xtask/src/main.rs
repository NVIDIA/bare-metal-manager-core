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
