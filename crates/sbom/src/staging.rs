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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::files::copy_dir_recursive;

/// Merge a source directory into a destination directory
fn merge_directory(src: &Path, dest: &Path) -> Result<()> {
    if !src.exists() {
        tracing::warn!("Source directory not found (skipping): {}", src.display());
        return Ok(());
    }

    tracing::info!(
        "Merging directory: {} into {}",
        src.display(),
        dest.display()
    );
    std::fs::create_dir_all(dest)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        if src_path.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            copy_dir_recursive(&src_path, &dest_path)?;
        } else {
            std::fs::copy(&src_path, &dest_path)?;
        }
    }

    Ok(())
}

/// Create staging directory that mirrors final runtime filesystem
pub fn assemble_staging_directory(
    rootfs: &Path,
    app_dir: Option<&Path>,
    distroless_dir: Option<&Path>,
    additional_files: Vec<String>,
    output: &Path,
    syft_config: Option<&Path>,
) -> Result<()> {
    tracing::debug!("Creating staging directory at {}", output.display());

    // Create base staging directory
    std::fs::create_dir_all(output)
        .with_context(|| format!("Failed to create staging directory: {}", output.display()))?;

    // Copy rootfs as the base
    if rootfs.exists() {
        tracing::info!("Copying rootfs from {}", rootfs.display());
        copy_dir_recursive(rootfs, output)
            .with_context(|| format!("Failed to copy rootfs from {}", rootfs.display()))?;
    } else {
        tracing::error!("Rootfs directory not found: {}", rootfs.display());
        return Err(anyhow::anyhow!(
            "Rootfs directory not found: {}",
            rootfs.display()
        ));
    }

    // Copy app directory
    if let Some(app) = app_dir {
        if app.exists() {
            tracing::info!("Copying app directory from {}", app.display());
            let dest_app = output.join("app");
            std::fs::create_dir_all(&dest_app)?;
            copy_dir_recursive(app, &dest_app)
                .with_context(|| format!("Failed to copy app directory from {}", app.display()))?;
        } else {
            tracing::error!("App directory not found: {}", app.display());
            return Err(anyhow::anyhow!(
                "App directory not found: {}",
                app.display()
            ));
        }
    }

    // Copy distroless directory structure
    // The distroless directory mirrors the final filesystem layout:
    //   /distroless/usr/lib     → /usr/lib
    //   /distroless/usr/bin     → /usr/bin
    //   /distroless/usr/share   → /usr/share
    //   /distroless/var         → /var
    //   /distroless/src         → /app/packages (special case)
    if let Some(distroless) = distroless_dir {
        if distroless.exists() {
            // Merge /distroless/usr into output/usr
            merge_directory(&distroless.join("usr"), &output.join("usr"))?;

            // Merge /distroless/var into output/var
            merge_directory(&distroless.join("var"), &output.join("var"))?;

            // Special case: /distroless/src → /app/packages
            let src_dir = distroless.join("src");
            if src_dir.exists() {
                let dest = output.join("app/packages");
                tracing::info!(
                    "Copying directory: {} to {}",
                    src_dir.display(),
                    dest.display()
                );
                std::fs::create_dir_all(&dest)?;
                copy_dir_recursive(&src_dir, &dest)?;
            }
        } else {
            tracing::warn!("Distroless directory not found: {}", distroless.display());
        }
    }

    // Copy additional files to the staging directory
    for spec in additional_files {
        // Parse SRC:DEST format
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 2 {
            tracing::error!("Invalid include spec (expected SRC:DEST): {spec}");
            return Err(anyhow::anyhow!(
                "Invalid include spec (expected SRC:DEST): {spec}"
            ));
        }

        let src = PathBuf::from(parts[0]);
        let dest = output.join(parts[1]);

        if src.exists() {
            tracing::info!("Copying {} -> {}", src.display(), dest.display());

            // Create parent directory
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create parent directory: {}", parent.display())
                })?;
            }

            if src.is_dir() {
                copy_dir_recursive(&src, &dest).with_context(|| {
                    format!("Failed to copy {} to {}", src.display(), dest.display())
                })?;
            } else {
                std::fs::copy(&src, &dest).with_context(|| {
                    format!("Failed to copy {} to {}", src.display(), dest.display())
                })?;
            }
        } else {
            tracing::error!("Source file not found: {}", src.display());
            return Err(anyhow::anyhow!("Source file not found: {}", src.display()));
        }
    }

    // 5. Copy syft config if provided
    if let Some(config) = syft_config {
        if config.exists() {
            let dest = output.join(".syft.yaml");
            tracing::info!("Copying syft config to .syft.yaml");
            std::fs::copy(config, &dest)
                .with_context(|| format!("Failed to copy syft config from {}", config.display()))?;
        } else {
            tracing::error!("Syft config not found: {}", config.display());
            return Err(anyhow::anyhow!(
                "Syft config not found: {}",
                config.display()
            ));
        }
    }

    tracing::info!("\n✓ Staging directory created at {}", output.display());
    tracing::info!(
        "  Ready for SBOM generation with: syft scan dir:{}",
        output.display()
    );

    Ok(())
}
