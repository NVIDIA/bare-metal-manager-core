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
pub mod files;
pub mod license;
pub mod packages;
pub mod staging;
pub mod types;

// Re-export commonly used types
// Re-export main functions
pub use files::copy_files;
pub use license::{extract_licenses, generate_attribution, write_attribution_file};
pub use packages::debian::package::install_packages;
pub use packages::debian::sources::{download_sources, download_sources_from_config};
pub use staging::assemble_staging_directory;
pub use types::{
    DISTROLESS_BASE_PACKAGES, License, PackageConfig, PackageInfo, SpdxDocument, SpdxPackage,
    is_base_package,
};
