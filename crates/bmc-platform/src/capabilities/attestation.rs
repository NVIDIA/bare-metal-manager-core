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

use crate::{DriverOutcome, FirmwareInventory, OpCx, PlatformError, RedfishUri};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComponentIntegritySummary {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub component_type: String,
    pub component_type_version: String,
    pub target_component_uri: Option<RedfishUri>,
    pub protected_component_uris: Vec<RedfishUri>,
    pub certificate_link: Option<RedfishUri>,
    pub measurement_action_target: Option<RedfishUri>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaCertificate {
    pub certificate_string: String,
    pub certificate_type: String,
    pub certificate_usage_types: Vec<String>,
    pub id: String,
    pub name: String,
    pub slot_id: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub hashing_algorithm: String,
    pub signed_measurements: String,
    pub signing_algorithm: String,
    pub version: String,
}

/// Collection of hardware attestation evidence.
#[async_trait]
pub trait Attestation: Send + Sync {
    async fn components(
        &self,
        cx: &OpCx<'_>,
    ) -> Result<Vec<ComponentIntegritySummary>, PlatformError>;

    async fn firmware_for_component(
        &self,
        cx: &OpCx<'_>,
        component_id: &str,
    ) -> Result<FirmwareInventory, PlatformError>;

    async fn ca_certificate(
        &self,
        cx: &OpCx<'_>,
        uri: &RedfishUri,
    ) -> Result<CaCertificate, PlatformError>;

    async fn trigger_evidence(
        &self,
        cx: &OpCx<'_>,
        uri: &RedfishUri,
        nonce_hex: &str,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn evidence(
        &self,
        cx: &OpCx<'_>,
        uri: &RedfishUri,
    ) -> Result<AttestationEvidence, PlatformError>;

    async fn clear_tpm(&self, cx: &OpCx<'_>) -> Result<DriverOutcome, PlatformError>;
}
