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
pub mod package;
pub mod sources;

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::sync::Once;

use anyhow::{Context, Result};

static INIT: Once = Once::new();

pub fn ensure_apt_initialized() {
    INIT.call_once(|| {
        if let Err(e) = apt_get_update() {
            tracing::error!("Failed to update apt cache: {}", e);
        }
    });
}

/// Check if a package is installed
pub fn is_package_installed(package_name: &str) -> bool {
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Status}", package_name])
        .output();

    if let Ok(output) = output {
        let status = String::from_utf8_lossy(&output.stdout);
        output.status.success() && status.contains("install ok installed")
    } else {
        false
    }
}

/// Ensure a package is installed, installing it if necessary
pub fn ensure_package_installed(package_name: &str) -> Result<()> {
    if is_package_installed(package_name) {
        tracing::debug!("Package {package_name} is already installed");
        return Ok(());
    }

    tracing::info!("Installing package: {package_name}");
    ensure_apt_initialized();

    let output = Command::new("apt-get")
        .args(["install", "-y", "--no-install-recommends", package_name])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run apt-get install")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Failed to install {package_name}: {stderr}");
        return Err(anyhow::anyhow!(
            "Failed to install {package_name}: {stderr}"
        ));
    }

    tracing::info!("Successfully installed {package_name}");
    Ok(())
}

/// Setup Debian source repositories
fn setup_source_repositories() -> Result<()> {
    tracing::info!("Setting up Debian source repositories...");
    tracing::info!("Creating directory: /etc/apt/sources.list.d/");
    std::fs::create_dir_all("/etc/apt/sources.list.d/")?;
    tracing::info!("Writing sources.list.d/debian-source.sources");
    let sources_content = r"Types: deb-src
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
";

    std::fs::write(
        "/etc/apt/sources.list.d/debian-source.sources",
        sources_content,
    )?;

    Ok(())
}

fn apt_get_update() -> Result<()> {
    setup_source_repositories()?;
    tracing::info!("Updating apt cache...");
    let status = Command::new("apt-get")
        .args(["update", "-qq"])
        .stdout(Stdio::null())
        .status()
        .context("Failed to run apt-get update")?;

    if !status.success() {
        tracing::error!("apt-get update failed");
        return Err(anyhow::anyhow!("apt-get update failed"));
    }

    Ok(())
}

/// Get all dependencies for packages recursively
pub fn get_all_dependencies(packages: &[String]) -> Result<HashSet<String>> {
    ensure_apt_initialized();
    let mut all_packages = HashSet::new();

    for pkg in packages {
        tracing::info!("Getting dependencies for {pkg}");
        all_packages.insert(pkg.clone());

        let output = Command::new("apt-cache")
            .args([
                "depends",
                pkg,
                "--recurse",
                "--no-recommends",
                "--no-suggests",
                "--no-conflicts",
                "--no-breaks",
                "--no-replaces",
                "--no-enhances",
            ])
            .output()
            .context("Failed to run apt-cache depends")?;

        if !output.status.success() {
            tracing::error!("apt-cache depends failed for {pkg}");
            return Err(anyhow::anyhow!("apt-cache depends failed for {pkg}"));
        }

        if output.status.success() {
            let deps_output = String::from_utf8_lossy(&output.stdout);
            tracing::info!("Dependencies output: {deps_output}");
            for line in deps_output.lines() {
                tracing::info!("Dependency line: {line}");
                if let Some(dep) = line.trim().strip_prefix("Depends:")
                    && let Some(dep_name) = dep.split_whitespace().next()
                    && !dep_name.starts_with('<')
                {
                    all_packages.insert(dep_name.to_string());
                }
            }
        }
    }

    Ok(all_packages)
}
