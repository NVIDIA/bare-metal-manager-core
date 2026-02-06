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
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::{ensure_apt_initialized, get_all_dependencies};
use crate::types::{DISTROLESS_BASE_PACKAGES, PackageConfig};

/// Get source package name for a binary package
/// Uses apt-cache show which works for non-installed packages
fn get_source_package_name(package_name: &str) -> Result<String> {
    tracing::info!("Getting source package name for {package_name}");

    let output = Command::new("apt-cache")
        .args(["show", package_name])
        .output()
        .context("Failed to run apt-cache show")?;

    if !output.status.success() {
        tracing::error!("apt-cache show failed for {package_name}");
        return Err(anyhow::anyhow!("apt-cache show failed for {package_name}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for "Source: <name>" line (may include version like "Source: newt (0.52.21-4)")
    for line in stdout.lines() {
        if let Some(source) = line.strip_prefix("Source: ") {
            // Take first word (source package name without version)
            let source_pkg = source.split_whitespace().next().unwrap_or(package_name);
            tracing::debug!("Source package for {package_name}: {source_pkg}");
            return Ok(source_pkg.to_string());
        }
    }

    // No Source field means binary package name == source package name
    tracing::debug!("No Source field, using package name: {package_name}");
    Ok(package_name.to_string())
}

/// Check if source package already downloaded
fn is_source_downloaded(output_dir: &Path, source_pkg: &str) -> bool {
    if let Ok(entries) = std::fs::read_dir(output_dir) {
        tracing::debug!("Checking if source package is downloaded: {output_dir:?}");
        for entry in entries.flatten() {
            if let Some(filename) = entry.file_name().to_str()
                && filename.starts_with(&format!("{source_pkg}_"))
                && filename.ends_with(".dsc")
            {
                tracing::debug!("Source package is downloaded: {filename}");
                return true;
            }
        }
    }
    false
}

/// Download source package using apt-get source
fn download_source_package(source_pkg: &str, output_dir: &Path) -> Result<()> {
    ensure_apt_initialized();
    tracing::info!("Downloading source package: {source_pkg}");

    let output = Command::new("apt-get")
        .args(["source", "--download-only", source_pkg])
        .current_dir(output_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run apt-get source")?;

    if !output.status.success() {
        tracing::error!("Failed to download source for {source_pkg}");
        return Err(anyhow::anyhow!(
            "Failed to download source for {source_pkg}"
        ));
    }

    Ok(())
}

/// Download sources for packages
pub fn download_sources<S: ::std::hash::BuildHasher + Default>(
    packages: &[String],
    output_dir: &Path,
    excluded: &HashSet<String, S>,
) -> Result<()> {
    ensure_apt_initialized();
    // Create output directory
    tracing::info!("Creating output directory: {output_dir:?}");
    std::fs::create_dir_all(output_dir)?;

    // Get packages to process
    let packages_to_process = get_all_dependencies(packages)?;

    tracing::debug!("Filtering out excluded packages");
    let (to_exclude, to_process): (Vec<String>, Vec<String>) = packages_to_process
        .into_iter()
        .partition(|pkg| excluded.contains(pkg));

    tracing::info!("Excluded packages count: {}", to_exclude.len());
    tracing::info!("Packages to process count: {}", to_process.len());

    // Track downloaded sources
    let mut downloaded_sources = HashSet::new();
    for pkg in to_process {
        tracing::info!("Processing source package: {pkg}");
        // Get source package name
        let Ok(source_pkg) = get_source_package_name(&pkg) else {
            tracing::error!("Failed to get source package name for {pkg}");
            return Err(anyhow::anyhow!(
                "Failed to get source package name for {pkg}"
            ));
        };

        // Skip if source package is in the exclusion list
        // (e.g., liblzma5 has source "xz-utils" which is in DISTROLESS_BASE_PACKAGES)
        if excluded.contains(&source_pkg) {
            tracing::debug!("Skipping source {source_pkg} (from binary {pkg}) - in exclusion list");
            continue;
        }

        // Skip if already processed
        if downloaded_sources.contains(&source_pkg) {
            continue;
        }

        // Check if already downloaded
        if is_source_downloaded(output_dir, &source_pkg) {
            downloaded_sources.insert(source_pkg);
            continue;
        }

        // Download source package
        if let Err(e) = download_source_package(&source_pkg, output_dir) {
            tracing::error!("Failed to download source for {source_pkg}: {e}");
            continue;
        }

        downloaded_sources.insert(source_pkg);
    }

    tracing::info!("Downloaded source packages to {}", output_dir.display());

    Ok(())
}

pub fn download_sources_from_config(deps_file: &Path, output_dir: &Path) -> Result<()> {
    tracing::info!("Loading configuration from {}", deps_file.display());
    let file = File::open(deps_file)
        .with_context(|| format!("Failed to open deps file: {}", deps_file.display()))?;
    let config: PackageConfig = serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("Failed to parse deps file: {}", deps_file.display()))?;

    // Use the static list of base packages for exclusion
    let excluded: HashSet<String> = DISTROLESS_BASE_PACKAGES
        .iter()
        .map(::std::string::ToString::to_string)
        .collect();
    tracing::info!(
        "Downloading sources for {} packages (excluding {} base packages)",
        config.packages().len(),
        excluded.len()
    );
    download_sources(&config.packages(), output_dir, &excluded)
}
