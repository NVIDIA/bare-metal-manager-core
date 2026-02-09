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
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Base packages provided by the 'cc' distroless container or satisfied by busybox
/// The files from these packages are excluded from `copy_files`
pub const DISTROLESS_BASE_PACKAGES: &[&str] = &[
    // Actually in distroless base
    "base-files",
    "ca-certificates",
    "gcc-12-base",
    "libc6",
    "libgcc-s1",
    "libgomp1",
    "libssl3",
    "libstdc++6",
    "netbase",
    "openssl",
    "tzdata",
    // Busybox provides these utilities
    "bash",
    "bzip2",
    "coreutils",
    "cpio",
    "dash",
    "diffutils",
    "findutils",
    "gawk",
    "grep",
    "gzip",
    "hostname",
    "kmod",
    "less",
    "login",
    "mawk",
    "mount",
    "net-tools",
    "patch",
    "procps",
    "sed",
    "tar",
    "traceroute",
    "util-linux",
    "wget",
    "xz-utils",
    // Package management (not needed in distroless)
    "apt",
    "debconf",
    "dpkg",
    "gpgv",
    "ucf",
    // User/auth management (distroless has fixed users)
    "adduser",
    "libpam-modules",
    "libpam-modules-bin",
    "libpam-runtime",
    "passwd",
    // Init/system (not needed in containers)
    "init-system-helpers",
    "libsystemd0",
    "sysvinit-utils",
    "systemd",
    "udev",
    // Other common deps not needed
    "install-info",
    "libaudit-common",
    "libaudit1",
    "libcap2-bin",
    "libdebconfclient0",
    "libdebian-installer4",
    "libselinux1",
    "lldpad",
    "sensible-utils",
];

pub fn is_base_package(package_name: &str) -> bool {
    DISTROLESS_BASE_PACKAGES.contains(&package_name)
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, Hash)]
pub struct License {
    pub name: String,
    pub content: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PackageConfig {
    // Runtime dependencies (libraries and tools needed in final container)
    #[serde(default, alias = "debian_archives")]
    pub runtime_dependencies: Vec<String>,

    // Packages to exclude from base distroless container (kept for backwards compatibility)
    #[serde(default)]
    pub exclude_packages_from_runtime: Vec<String>,
}

impl PackageConfig {
    /// Get runtime dependencies
    pub fn packages(&self) -> Vec<String> {
        self.runtime_dependencies.clone()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    #[serde(default)]
    pub packages: Vec<SpdxPackage>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    pub name: String,
    #[serde(default)]
    pub version_info: String,
    #[serde(default)]
    pub license_declared: String,
    #[serde(default)]
    pub license_concluded: String,
    #[serde(default)]
    pub download_location: String,
    #[serde(default)]
    pub source_info: String,
    #[serde(default)]
    pub supplier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub license_declared: String,
    pub license_concluded: String,
    pub download_location: String,
    pub source_info: String,
    pub supplier: String,
    pub license_path: PathBuf,
}

impl From<SpdxPackage> for PackageInfo {
    fn from(pkg: SpdxPackage) -> Self {
        // Extract license/copyright path from source_info
        // Format: "acquired package info from DPKG DB: <status_path>, <copyright_path>"
        let license_path = if let Some(comma_pos) = pkg.source_info.rfind(',') {
            // Get everything after the last comma and trim whitespace
            let path_str = pkg.source_info[comma_pos + 1..].trim();
            PathBuf::from(path_str)
        } else {
            PathBuf::new()
        };

        Self {
            name: pkg.name,
            version: pkg.version_info,
            license_declared: pkg.license_declared,
            license_concluded: pkg.license_concluded,
            download_location: pkg.download_location,
            source_info: pkg.source_info,
            supplier: pkg.supplier,
            license_path,
        }
    }
}
