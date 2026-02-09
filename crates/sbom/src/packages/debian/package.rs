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
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use super::ensure_apt_initialized;
use crate::types::PackageConfig;

/// Install packages from deps.json into /distroless
/// Downloads .deb files and extracts them using dpkg (not apt-get install)
/// Exclusions are NOT applied here - they're applied during `copy_files` step
pub fn install_packages(deps_file: &Path) -> Result<()> {
    ensure_apt_initialized();
    tracing::info!(
        "Installing packages to /distroless from {}",
        deps_file.display()
    );

    // Load configuration
    let file = File::open(deps_file)
        .with_context(|| format!("Failed to open deps file: {}", deps_file.display()))?;
    let config: PackageConfig = serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("Failed to parse deps file: {}", deps_file.display()))?;

    let packages = config.packages();

    if packages.is_empty() {
        tracing::info!("No packages to install");
        return Ok(());
    }

    tracing::info!(
        "Downloading and extracting {} packages to /distroless",
        packages.len()
    );

    // Create directories
    let download_dir = std::path::PathBuf::from("/tmp/sbom-debs");
    let distroless_root = std::path::PathBuf::from("/distroless");

    std::fs::create_dir_all(&download_dir).context("Failed to create download directory")?;
    std::fs::create_dir_all(&distroless_root).context("Failed to create /distroless directory")?;

    // Download all .deb files
    tracing::info!("Downloading .deb packages...");
    let mut download_cmd = Command::new("apt-get");
    download_cmd.arg("download").current_dir(&download_dir);

    for pkg in &packages {
        tracing::info!("Downloading package: {pkg}");
        download_cmd.arg(pkg);
    }

    let output = download_cmd
        .output()
        .context("Failed to run apt-get download")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Failed to download packages: {}", packages.join(", "));
        tracing::error!("Error: {}", stderr);
        return Err(anyhow::anyhow!("apt-get download failed: {stderr}"));
    }

    // Extract each .deb file to /distroless
    tracing::info!("Extracting .deb packages to /distroless...");
    let deb_files: Vec<_> = std::fs::read_dir(&download_dir)
        .context("Failed to read download directory")?
        .filter_map(::std::result::Result::ok)
        .filter(|entry| entry.path().extension().and_then(|s| s.to_str()) == Some("deb"))
        .collect();

    tracing::debug!("Found {} .deb files to extract", deb_files.len());

    for deb_entry in deb_files {
        let deb_path = deb_entry.path();
        tracing::debug!("Extracting: {}", deb_path.display());

        let output = Command::new("dpkg")
            .arg("-x")
            .arg(&deb_path)
            .arg(&distroless_root)
            .output()
            .with_context(|| format!("Failed to extract {}", deb_path.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("Failed to extract {}: {}", deb_path.display(), stderr);
            return Err(anyhow::anyhow!(
                "dpkg -x failed for {}: {}",
                deb_path.display(),
                stderr
            ));
        }
    }

    // Clean up downloaded .deb files
    tracing::debug!("Cleaning up downloaded .deb files...");
    std::fs::remove_dir_all(&download_dir).ok();

    // Remove extracted docs - they'll be selectively copied by copy_files with proper filtering
    // This prevents base package docs from leaking into the final container
    let extracted_docs = distroless_root.join("usr/share/doc");
    if extracted_docs.exists() {
        tracing::debug!("Removing extracted docs (will be handled by copy_files)...");
        std::fs::remove_dir_all(&extracted_docs).ok();
    }

    tracing::info!(
        "✓ Successfully extracted {} packages to /distroless",
        packages.len()
    );

    Ok(())
}
