use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::files::copy_dir_recursive;

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
    if let Some(distroless) = distroless_dir {
        if distroless.exists() {
            // Creates a mapping of staging directories to the directories in the distroless container
            // Debian package depdendencies are installed into the staging directory and then copied to the distroless container
            let mut staging_directory_to_distroless_directory = HashMap::new();
            staging_directory_to_distroless_directory
                .insert(distroless.join("lib"), output.join("usr/lib"));
            staging_directory_to_distroless_directory
                .insert(distroless.join("bin"), output.join("usr/bin"));
            staging_directory_to_distroless_directory
                .insert(distroless.join("doc"), output.join("usr/share/doc"));
            staging_directory_to_distroless_directory.insert(
                distroless.join("dpkg"),
                output.join("var/lib/dpkg/status.d"),
            );
            staging_directory_to_distroless_directory
                .insert(distroless.join("src"), output.join("app/packages"));

            for (staging_directory, distroless_directory) in
                staging_directory_to_distroless_directory
            {
                if staging_directory.exists() {
                    tracing::info!(
                        "Copying directory: {} to {}",
                        staging_directory.display(),
                        distroless_directory.display()
                    );
                    std::fs::create_dir_all(&distroless_directory)?;
                    copy_dir_recursive(&staging_directory, &distroless_directory)?;
                } else {
                    tracing::warn!(
                        "Staging directory not found (skipping): {}",
                        staging_directory.display()
                    );
                }
            }

            // Also copy /distroless/usr if it exists (handles case where copy-files
            // preserved the full /usr/lib path structure)
            let distroless_usr = distroless.join("usr");
            if distroless_usr.exists() {
                tracing::info!(
                    "Copying directory: {} to {}",
                    distroless_usr.display(),
                    output.join("usr").display()
                );
                let output_usr = output.join("usr");
                std::fs::create_dir_all(&output_usr)?;
                // Merge /distroless/usr into /sbom-staging/usr
                for entry in std::fs::read_dir(&distroless_usr)? {
                    let entry = entry?;
                    let src_path = entry.path();
                    let dest_path = output_usr.join(entry.file_name());

                    if src_path.is_dir() {
                        tracing::info!(
                            "Merging directory: {} into {}",
                            src_path.display(),
                            dest_path.display()
                        );
                        std::fs::create_dir_all(&dest_path)?;
                        copy_dir_recursive(&src_path, &dest_path)?;
                    } else {
                        tracing::info!(
                            "Copying file: {} to {}",
                            src_path.display(),
                            dest_path.display()
                        );
                        std::fs::copy(&src_path, &dest_path)?;
                    }
                }
            }
        } else {
            eprintln!(
                "  Warning: distroless directory not found: {}",
                distroless.display()
            );
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
