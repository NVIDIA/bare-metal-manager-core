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

use crate::packages::debian::{ensure_package_installed, get_all_dependencies};
use crate::types::{PackageConfig, is_base_package};

const USR_LIB_DIR: &str = "/usr/lib";
const LIB_DIR: &str = "/lib/";
const BIN_DIR: &str = "/bin/";
const SBIN_DIR: &str = "/sbin/";
const LIBEXEC_DIR: &str = "/libexec/";
const USR_SHARE_DIR: &str = "/usr/share/";

/// Copy library files from a package to distroless/lib
fn copy_so_files(package_name: &str, lib_dir: impl AsRef<Path>) -> Result<()> {
    ensure_package_installed(package_name)?;
    tracing::debug!("Running dpkg -L {package_name}");
    let output = Command::new("dpkg")
        .args(["-L", package_name])
        .output()
        .context("Failed to run dpkg -L")?;

    if !output.status.success() {
        tracing::error!(
            "Failed to run dpkg -L for package {package_name} - {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!(
            "Failed to run dpkg -L for package {package_name} - {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let files = String::from_utf8_lossy(&output.stdout);

    // Copy files from THIS package that are in lib directories
    for file in files.lines() {
        tracing::info!(
            "Copying file: {file} from package {package_name} to {}",
            lib_dir.as_ref().display()
        );
        let path = std::path::Path::new(file);

        // Determine relative path to preserve directory structure
        // /usr/lib/x86_64-linux-gnu/libcurl.so.4 → x86_64-linux-gnu/libcurl.so.4
        // /lib/x86_64-linux-gnu/libc.so.6 → x86_64-linux-gnu/libc.so.6
        let relative_path = file
            .strip_prefix(USR_LIB_DIR)
            .or_else(|| file.strip_prefix(LIB_DIR))
            .map(|p| p.trim_start_matches('/'));

        if let Some(rel_path) = relative_path
            && !rel_path.is_empty()
        {
            let dest = lib_dir.as_ref().join(rel_path);

            // Create parent directory if needed
            if let Some(parent) = dest.parent() {
                tracing::info!("Creating parent directory if needed: {parent:?}");
                std::fs::create_dir_all(parent).ok();
            }

            if path.is_file() {
                if let Err(e) = std::fs::copy(file, &dest) {
                    tracing::error!("    Warning: Failed to copy {file}: {e}");
                    return Err(anyhow::anyhow!("Failed to copy {file}: {e}"));
                }
            } else if path.is_symlink() {
                if let Ok(target) = std::fs::read_link(file) {
                    tracing::info!("Preserving symlink: {target:?}");
                    let _ = std::os::unix::fs::symlink(target, &dest);
                } else {
                    tracing::error!("Failed to read symlink: {file}");
                    return Err(anyhow::anyhow!("Failed to read symlink: {file}"));
                }
            }
        }
    }
    tracing::info!(
        "Copied library files from package {package_name} to {}",
        lib_dir.as_ref().display()
    );

    Ok(())
}

/// Copy binaries from a package to distroless/bin
fn copy_binaries(package_name: &str, bin_dir: impl AsRef<Path>) -> Result<()> {
    ensure_package_installed(package_name)?;
    tracing::debug!("Running dpkg -L {package_name}");
    let output = Command::new("dpkg")
        .args(["-L", package_name])
        .output()
        .context("Failed to run dpkg -L")?;

    if !output.status.success() {
        tracing::error!(
            "Failed to run dpkg -L for package {package_name} - {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!(
            "Failed to run dpkg -L for package {package_name} - {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let files = String::from_utf8_lossy(&output.stdout);
    for file in files.lines() {
        tracing::info!(
            "Copying file: {file} from package {package_name} to {}",
            bin_dir.as_ref().display()
        );
        let path = std::path::Path::new(file);

        // Check if it's in bin directories
        if (file.contains(BIN_DIR) || file.contains(SBIN_DIR) || file.contains(LIBEXEC_DIR))
            && let Some(filename) = path.file_name()
        {
            let dest = bin_dir.as_ref().join(filename);

            if path.is_file() {
                // Copy regular file
                if let Err(e) = std::fs::copy(file, &dest) {
                    tracing::error!("    Warning: Failed to copy {file}: {e}");
                }
            } else if path.is_symlink() {
                // Preserve symlinks
                if let Ok(target) = std::fs::read_link(file) {
                    tracing::info!("Preserving symlink: {target:?}");
                    let _ = std::os::unix::fs::symlink(target, &dest);
                }
            }
        }
    }
    tracing::info!(
        "Copied binaries from package {package_name} to {}",
        bin_dir.as_ref().display()
    );

    Ok(())
}

/// Copy /usr/share files from a package (perl modules, docs, etc.) to distroless/share
fn copy_share_files(package_name: &str, share_dir: impl AsRef<Path>) -> Result<()> {
    ensure_package_installed(package_name)?;
    tracing::debug!("Running dpkg -L {package_name} for share files");
    let output = Command::new("dpkg")
        .args(["-L", package_name])
        .output()
        .context("Failed to run dpkg -L")?;

    if !output.status.success() {
        tracing::error!(
            "Failed to run dpkg -L for package {package_name} - {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!(
            "Failed to run dpkg -L for package {package_name} - {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let files = String::from_utf8_lossy(&output.stdout);

    for file in files.lines() {
        let path = std::path::Path::new(file);

        // Handle all /usr/share files (including docs, perl modules, etc.)
        if let Some(rel_path) = file.strip_prefix(USR_SHARE_DIR) {
            let rel_path = rel_path.trim_start_matches('/');
            if rel_path.is_empty() {
                continue;
            }

            let dest = share_dir.as_ref().join(rel_path);

            // Create parent directory if needed
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).ok();
            }

            if path.is_file() {
                tracing::debug!("Copying share file: {file} -> {}", dest.display());
                if let Err(e) = std::fs::copy(file, &dest) {
                    tracing::error!("Failed to copy {file}: {e}");
                    return Err(anyhow::anyhow!("Failed to copy {file}: {e}"));
                }
            } else if path.is_symlink()
                && let Ok(target) = std::fs::read_link(file)
            {
                tracing::debug!("Preserving share symlink: {file} -> {:?}", target);
                let _ = std::os::unix::fs::symlink(target, &dest);
            }
        }
    }

    tracing::info!(
        "Copied share files from package {package_name} to {}",
        share_dir.as_ref().display()
    );

    Ok(())
}

/// Recursively copy a directory
pub fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    tracing::debug!("Creating directory: {dst:?}");
    std::fs::create_dir_all(dst)?;
    tracing::debug!("Reading directory: {src:?}");
    for entry in std::fs::read_dir(src)? {
        tracing::debug!("Reading entry: {entry:?}");
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        tracing::debug!("Source path: {src_path:?}");
        tracing::debug!("Destination path: {dst_path:?}");
        if file_type.is_dir() {
            tracing::info!("Copying directory: {src_path:?} to {dst_path:?}");
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            // Preserve symlinks
            tracing::debug!("Preserving symlink: {src_path:?} to {dst_path:?}");
            if let Ok(target) = std::fs::read_link(&src_path) {
                let _ = std::os::unix::fs::symlink(target, &dst_path);
            }
        } else {
            tracing::info!("Copying file: {src_path:?} to {dst_path:?}");
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    tracing::info!("Copied directory: {src:?} to {dst:?}");
    Ok(())
}

/// Save package metadata
fn save_package_metadata(package_name: &str, dpkg_dir: &std::path::Path) -> Result<()> {
    ensure_package_installed(package_name)?;
    tracing::debug!("Saving package metadata for {package_name} to {dpkg_dir:?}");
    let output = Command::new("dpkg")
        .args(["-s", package_name])
        .output()
        .context("Failed to run dpkg -s")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to run dpkg -s for package metadata: {package_name}"
        ));
    }

    tracing::debug!("Getting package version for {package_name}");
    let version_output = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", package_name])
        .output()
        .context("Failed to run dpkg-query -W -f=${Version}")?;

    if !version_output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to run dpkg-query -W -f=\"${{Version}}\"for package metadata: {package_name}"
        ));
    }

    let version = String::from_utf8_lossy(&version_output.stdout);
    tracing::debug!("Package version: {version}");
    tracing::info!("Creating metadata file: {dpkg_dir:?}/{package_name}_{version}");
    let metadata_file = dpkg_dir.join(format!("{package_name}_{version}"));

    std::fs::write(&metadata_file, output.stdout)?;
    tracing::info!(
        "Saved package metadata for {package_name} to {}",
        metadata_file.display()
    );

    Ok(())
}

/// Copy files from packages to distroless directories
pub fn copy_files(deps_file: &Path, distroless_dir: &Path) -> Result<()> {
    // Load configuration
    tracing::info!("Loading configuration from {deps_file:?}");
    let file = File::open(deps_file)
        .with_context(|| format!("Failed to open deps file: {}", deps_file.display()))?;
    let config: PackageConfig = serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("Failed to parse deps file: {}", deps_file.display()))?;

    // Create distroless directories mirroring final filesystem structure
    let usr_lib_dir = distroless_dir.join("usr/lib");
    let usr_bin_dir = distroless_dir.join("usr/bin");
    let usr_share_dir = distroless_dir.join("usr/share");
    let dpkg_dir = distroless_dir.join("var/lib/dpkg/status.d");

    std::fs::create_dir_all(&usr_lib_dir)?;
    std::fs::create_dir_all(&usr_bin_dir)?;
    std::fs::create_dir_all(&usr_share_dir)?;
    std::fs::create_dir_all(&dpkg_dir)?;

    // Get packages to process
    let packages_to_process = get_all_dependencies(&config.packages())?;

    // Partition packages into excluded (base container) and to-copy
    let (excluded, copied): (Vec<String>, Vec<String>) = packages_to_process
        .into_iter()
        .partition(|pkg| is_base_package(pkg));

    for package in &copied {
        // Copy files from this package
        copy_so_files(package, &usr_lib_dir)?;
        copy_binaries(package, &usr_bin_dir)?;
        copy_share_files(package, &usr_share_dir)?;
        save_package_metadata(package, &dpkg_dir)?;
    }

    tracing::info!(
        "Packages copied into distroless container: {}",
        copied.join(", ")
    );
    tracing::info!(
        "Packages excluded from copying into distroless container: {}",
        excluded.join(", ")
    );

    Ok(())
}
