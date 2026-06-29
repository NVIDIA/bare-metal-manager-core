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
mod affected_packages;
mod isolated_package_builds;
mod workspace_deps;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "xtask")]
enum Xtask {
    #[clap(
        name = "affected-packages",
        about = "List changed workspace packages and their transitive workspace dependents"
    )]
    AffectedPackages(AffectedPackages),
    #[clap(
        name = "check-workspace-deps",
        about = "Check for any dependency versions defined in crate-level Cargo.toml's instead of the workspace root"
    )]
    CheckWorkspaceDeps(CheckWorkspaceDeps),
    #[clap(
        name = "check-isolated-package-builds",
        about = "Check that each workspace package builds independently with its default features"
    )]
    IsolatedPackageBuilds(IsolatedPackageBuilds),
}

#[derive(Parser, Debug)]
struct AffectedPackages {
    #[clap(
        long,
        value_name = "REVISION",
        default_value = "origin/main",
        help = "Revision whose merge-base with HEAD is used to find changed paths"
    )]
    base: String,
}

#[derive(Parser, Debug)]
struct IsolatedPackageBuilds {
    #[clap(
        short = 'p',
        long = "package",
        value_name = "PACKAGE",
        help = "Workspace package to check (repeatable; defaults to all packages)"
    )]
    packages: Vec<String>,
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
        Xtask::AffectedPackages(AffectedPackages { base }) => affected_packages::run(&base),
        Xtask::CheckWorkspaceDeps(CheckWorkspaceDeps { fix }) => {
            workspace_deps::check(fix)?.report_and_exit()
        }
        Xtask::IsolatedPackageBuilds(IsolatedPackageBuilds { packages }) => {
            isolated_package_builds::check(&packages)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn affected_packages_base(arguments: &[&str]) -> String {
        let command = Xtask::try_parse_from(arguments).unwrap();
        let Xtask::AffectedPackages(AffectedPackages { base }) = command else {
            panic!("expected affected-packages command");
        };
        base
    }

    #[test]
    fn affected_packages_base_defaults_to_origin_main_and_accepts_an_override() {
        assert_eq!(
            affected_packages_base(&["xtask", "affected-packages"]),
            "origin/main"
        );
        assert_eq!(
            affected_packages_base(&["xtask", "affected-packages", "--base", "upstream/main",]),
            "upstream/main"
        );
    }
}
