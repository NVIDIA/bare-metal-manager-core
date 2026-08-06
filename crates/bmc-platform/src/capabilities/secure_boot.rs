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
pub use nv_redfish::schema::secure_boot::{SecureBoot as SecureBootStatus, SecureBootUpdate};
use serde::{Deserialize, Serialize};

use crate::{DriverOutcome, OpCx, PlatformError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootDatabase {
    PlatformKey,
    KeyExchangeKey,
    AllowedSignatures,
    ForbiddenSignatures,
}

/// Secure Boot status, enablement, and certificate operations.
#[async_trait]
pub trait SecureBoot: Send + Sync {
    async fn status(&self, cx: &OpCx<'_>) -> Result<SecureBootStatus, PlatformError>;

    async fn set(
        &self,
        cx: &OpCx<'_>,
        update: &SecureBootUpdate,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn has_certificates(
        &self,
        cx: &OpCx<'_>,
        database: SecureBootDatabase,
    ) -> Result<bool, PlatformError>;

    async fn add_certificate(
        &self,
        cx: &OpCx<'_>,
        database: SecureBootDatabase,
        pem: &str,
    ) -> Result<DriverOutcome, PlatformError>;
}
