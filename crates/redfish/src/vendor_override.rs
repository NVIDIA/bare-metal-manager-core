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

use async_trait::async_trait;
use libredfish::model::service_root::RedfishVendor;

/// Resolves the operator pinned Redfish vendor for a BMC.
/// Injected so this crate need not reach the database, and keyed by host.
#[async_trait]
pub trait BmcVendorOverrideResolver: Send + Sync + 'static {
    /// The pinned vendor for the BMC at `host`, or `None` when it has no pin.
    /// `host` is the real BMC host, never the site wide BMC proxy in its place.
    async fn vendor_override(
        &self,
        host: &str,
    ) -> Result<Option<RedfishVendor>, VendorOverrideError>;
}

/// A pin lookup that failed.
/// Advisory, so the pool warns and falls back to detection.
#[derive(Debug, thiserror::Error)]
#[error("failed to resolve bmc_vendor_override for {host}: {source}")]
pub struct VendorOverrideError {
    pub host: String,
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

impl VendorOverrideError {
    pub fn new(
        host: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            host: host.into(),
            source: source.into(),
        }
    }
}

/// A resolver that never pins anything.
/// Named rather than absent so having no pins is visible at the call site.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBmcVendorOverrides;

#[async_trait]
impl BmcVendorOverrideResolver for NoBmcVendorOverrides {
    async fn vendor_override(
        &self,
        _host: &str,
    ) -> Result<Option<RedfishVendor>, VendorOverrideError> {
        Ok(None)
    }
}
