use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::{ensure_apt_initialized, get_all_dependencies};
use crate::types::{DISTROLESS_BASE_PACKAGES, PackageConfig};

/// Get source package name for a binary package
fn get_source_package_name(package_name: &str) -> Result<String> {
    tracing::info!("Getting source package name for {package_name}");
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Source}", package_name])
        .output()
        .context("Failed to run dpkg-query")?;

    if !output.status.success() {
        tracing::error!("dpkg-query failed for {package_name}");
        return Err(anyhow::anyhow!(
            "dpkg-query -W -f=\"${{Source}}\" failed for {package_name}"
        ));
    }

    let source_field = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Source field: {source_field}");
    // Source field may contain version like "curl (7.88.1-10)"
    let source_pkg = source_field
        .split_whitespace()
        .next()
        .unwrap_or(package_name)
        .to_string();

    Ok(if source_pkg.is_empty() {
        tracing::error!("Source package is empty for {package_name}");
        package_name.to_string()
    } else {
        tracing::debug!("Source package: {source_pkg}");
        source_pkg
    })
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
