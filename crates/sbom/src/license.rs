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
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;

use crate::types::{License, PackageInfo, SpdxDocument};

lazy_static! {
    static ref LICENSE_REGEX: Regex = Regex::new(r"^License:\s+(.+)$").unwrap();
}

#[must_use]
pub fn should_include_license(license_expr: &str) -> bool {
    // Skip NOASSERTION and NONE, include everything else
    !(license_expr == "NOASSERTION" || license_expr == "NONE" || license_expr.is_empty())
}

impl License {
    //TODO: This is not flexible enough to handle different license file formats.
    // Implement a more flexible license file parser.
    pub fn from_file(path: &PathBuf) -> Result<Vec<Self>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut licenses = Vec::new();
        let mut current_license_name: Option<String> = None;
        let mut current_license_content: Vec<String> = Vec::new();

        for line in reader.lines() {
            let line = line?;

            // Check if this is a new license section
            if let Some(caps) = LICENSE_REGEX.captures(&line) {
                // Save previous license if we have one
                if let Some(name) = current_license_name.take()
                    && !current_license_content.is_empty()
                {
                    licenses.push(License {
                        name,
                        content: current_license_content.clone(),
                    });
                }

                // Start new license
                // Strip out the whitespace from copyright file
                current_license_name = Some(caps[1].trim().to_string());
                current_license_content.clear();
            } else if current_license_name.is_some() {
                // We're in a license section
                if line.starts_with(' ') || line.starts_with('\t') {
                    // This is license content (indented)
                    current_license_content.push(line.trim_start().to_string());
                } else if line.trim().is_empty() {
                    // Blank line - could be part of license or end
                    if !current_license_content.is_empty() {
                        current_license_content.push(String::new());
                    }
                } else {
                    // Non-indented, non-blank line means end of license section
                    if let Some(name) = current_license_name.take()
                        && !current_license_content.is_empty()
                    {
                        licenses.push(License {
                            name,
                            content: current_license_content.clone(),
                        });
                        current_license_content.clear();
                    }
                }
            }
        }

        // Don't forget the last license
        if let Some(name) = current_license_name
            && !current_license_content.is_empty()
        {
            licenses.push(License {
                name,
                content: current_license_content,
            });
        }

        Ok(licenses)
    }
}

#[must_use]
pub fn concat_licenses<S: ::std::hash::BuildHasher + Default>(
    packages: &HashMap<String, Vec<PackageInfo>, S>,
) -> Vec<License> {
    let mut licenses_to_attribute: Vec<License> = Vec::new();

    // Iterate through all packages
    for pkg_list in packages.values() {
        for package_info in pkg_list {
            // Skip if no license path
            if package_info.license_path.as_os_str().is_empty() {
                continue;
            }

            // Read licenses from the file
            if let Ok(licenses) = License::from_file(&package_info.license_path) {
                licenses_to_attribute.extend(licenses);
            }
        }
    }

    licenses_to_attribute
}
#[must_use]
pub fn dedup_licenses(licenses: Vec<License>) -> Vec<License> {
    let original_count = licenses.len();

    let deduped_licenses: Vec<License> = licenses
        .into_iter()
        .unique_by(|item| item.name.to_ascii_lowercase())
        .collect();

    let deduplicated_count = deduped_licenses.len();
    let removed_count = original_count - deduplicated_count;

    tracing::info!(
        "Deduplicated {} licenses to {} unique ({} duplicates removed)",
        original_count,
        deduplicated_count,
        removed_count
    );

    deduped_licenses
}

pub fn extract_licenses(
    sbom_path: &Path,
    prefer_concluded: bool,
) -> Result<HashMap<String, Vec<PackageInfo>>> {
    let file = File::open(sbom_path)
        .with_context(|| format!("Failed to open SBOM file: {}", sbom_path.display()))?;
    let reader = BufReader::new(file);
    let doc: SpdxDocument = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse SBOM JSON: {}", sbom_path.display()))?;

    let mut licenses_to_packages: HashMap<String, Vec<PackageInfo>> = HashMap::new();

    for package in doc.packages {
        let license_expr = if prefer_concluded && package.license_concluded != "NOASSERTION" {
            package.license_concluded.clone()
        } else if package.license_declared != "NOASSERTION" {
            package.license_declared.clone()
        } else {
            package.license_concluded.clone()
        };

        if should_include_license(&license_expr) {
            let package_info: PackageInfo = package.into();
            licenses_to_packages
                .entry(license_expr)
                .or_default()
                .push(package_info);
        }
    }

    tracing::info!(
        "Extracted {} unique license types from SBOM",
        licenses_to_packages.len()
    );

    // Sort packages within each license group
    for packages in licenses_to_packages.values_mut() {
        packages.sort_by(|a, b| a.name.cmp(&b.name));
    }

    Ok(licenses_to_packages)
}

pub fn write_attribution_file(licenses_to_attribute: &[License], output_path: &Path) -> Result<()> {
    let mut file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

    for license in licenses_to_attribute {
        writeln!(file, "LICENSE: {}", license.name)?;
        writeln!(file, "{}", "=".repeat(80))?;
        for line in &license.content {
            writeln!(file, "{line}")?;
        }
        writeln!(file)?;
    }
    Ok(())
}

pub fn generate_attribution(
    sbom_path: &Path,
    output_path: &Path,
    prefer_concluded: bool,
) -> Result<()> {
    tracing::info!("Generating attribution file from {}", sbom_path.display());

    // Extract licenses from SBOM to get package info with license paths
    let licenses_to_packages = extract_licenses(sbom_path, prefer_concluded)?;

    // Read actual license texts from copyright files
    let licenses_to_attribute = concat_licenses(&licenses_to_packages);

    if licenses_to_attribute.is_empty() {
        tracing::warn!("No licenses found in copyright files");
        tracing::warn!("Make sure the sourceInfo field contains valid copyright file paths");
        return Ok(());
    }

    // Deduplicate licenses with same name
    let deduplicated_licenses = dedup_licenses(licenses_to_attribute);

    // Write full attribution with deduplicated license texts
    write_attribution_file(&deduplicated_licenses, output_path)?;

    tracing::info!("Generated attribution file at: {}", output_path.display());
    Ok(())
}
