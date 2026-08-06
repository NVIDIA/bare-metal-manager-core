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
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{DriverOutcome, OpCx, PlatformError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootMode {
    Setup,
    User,
    Audit,
    Deployed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootCurrentBoot {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootDesiredState {
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecureBootStatus {
    pub secure_boot_enable: Option<bool>,
    pub secure_boot_current_boot: Option<SecureBootCurrentBoot>,
    pub secure_boot_mode: Option<SecureBootMode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecureBootCertificateInfo {
    pub certificate_string: String,
    pub certificate_type: String,
    pub issuer: Map<String, Value>,
    pub valid_not_before: String,
    pub valid_not_after: String,
}

/// Secure Boot status, enablement, and certificate operations.
#[async_trait]
pub trait SecureBoot: Send + Sync {
    async fn status(&self, cx: &OpCx<'_>) -> Result<SecureBootStatus, PlatformError>;

    async fn set(
        &self,
        cx: &OpCx<'_>,
        state: SecureBootDesiredState,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn list_certificates(
        &self,
        cx: &OpCx<'_>,
        database: &str,
    ) -> Result<Vec<String>, PlatformError>;

    async fn get_certificate(
        &self,
        cx: &OpCx<'_>,
        database: &str,
        certificate_id: &str,
    ) -> Result<SecureBootCertificateInfo, PlatformError>;

    async fn add_certificate(
        &self,
        cx: &OpCx<'_>,
        database: &str,
        pem: &str,
    ) -> Result<DriverOutcome, PlatformError>;
}
