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
use std::collections::BTreeSet;
use std::process::Command;

use cargo_metadata::MetadataCommand;
use eyre::{Context, ContextCompat, bail};

#[derive(Debug, PartialEq, Eq)]
struct WorkspacePackage {
    name: String,
    cargo_selector: String,
}

/// Checks workspace packages independently with default features.
///
/// An empty package selection preserves the original full-workspace behavior.
pub fn check(selected_packages: &[String]) -> eyre::Result<()> {
    let workspace_packages = workspace_packages()?;
    let packages = select_packages(&workspace_packages, selected_packages)?;
    let mut failures = Vec::new();

    for package in packages {
        println!("Checking isolated package build for {package}");

        // Keep the check read-only; stale lockfiles should fail in CI.
        let status = Command::new(cargo())
            .args(["check", "--locked", "-p", &package])
            .status()
            .with_context(|| format!("failed to run cargo check for {package}"))?;

        if !status.success() {
            failures.push(package);
        }
    }

    if failures.is_empty() {
        return Ok(());
    }

    eprintln!(
        "Isolated package builds failed for: {}",
        failures.join(", ")
    );

    bail!("one or more isolated package builds failed")
}

fn select_packages(
    workspace_packages: &[WorkspacePackage],
    selected_packages: &[String],
) -> eyre::Result<Vec<String>> {
    if selected_packages.is_empty() {
        return Ok(workspace_packages
            .iter()
            .map(|package| package.cargo_selector.clone())
            .collect());
    }

    let selected_packages = selected_packages
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let mut cargo_selectors = BTreeSet::new();
    for selected_package in selected_packages {
        let Some(workspace_package) = workspace_packages.iter().find(|package| {
            package.name == selected_package || package.cargo_selector == selected_package
        }) else {
            bail!("unknown workspace package: {selected_package}");
        };
        cargo_selectors.insert(workspace_package.cargo_selector.clone());
    }

    Ok(cargo_selectors.into_iter().collect())
}

fn workspace_packages() -> eyre::Result<Vec<WorkspacePackage>> {
    // Metadata runs before the checks, so prevent it from repairing a stale lockfile.
    let metadata = MetadataCommand::new()
        .no_deps()
        .other_options(vec!["--locked".to_string()])
        .exec()
        .context("failed to run cargo metadata")?;

    metadata
        .workspace_members
        .iter()
        .map(|member| {
            metadata
                .packages
                .iter()
                .find(|package| &package.id == member)
                .map(|package| WorkspacePackage {
                    name: package.name.clone(),
                    cargo_selector: format!("{}@{}", package.name, package.version),
                })
                .with_context(|| format!("workspace member {member} missing from cargo metadata"))
        })
        .collect::<eyre::Result<Vec<_>>>()
}

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

#[cfg(test)]
mod tests {
    use super::{WorkspacePackage, select_packages};

    fn package(name: &str, version: &str) -> WorkspacePackage {
        WorkspacePackage {
            name: name.to_string(),
            cargo_selector: format!("{name}@{version}"),
        }
    }

    #[test]
    fn empty_selection_uses_every_workspace_package() {
        let workspace = vec![package("beta", "2.0.0"), package("alpha", "1.0.0")];

        assert_eq!(
            select_packages(&workspace, &[]).unwrap(),
            ["beta@2.0.0", "alpha@1.0.0"]
        );
    }

    #[test]
    fn explicit_selection_is_validated_sorted_and_deduplicated() {
        let workspace = vec![package("alpha", "1.0.0"), package("beta", "2.0.0")];
        let selected = vec![
            "beta".to_string(),
            "alpha@1.0.0".to_string(),
            "beta".to_string(),
        ];

        assert_eq!(
            select_packages(&workspace, &selected).unwrap(),
            ["alpha@1.0.0", "beta@2.0.0"]
        );
        assert!(select_packages(&workspace, &["missing".to_string()]).is_err());
    }
}
