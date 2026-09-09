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

use std::time::Duration;

use async_trait::async_trait;
use carbide_secrets::credentials::CredentialKey;
use carbide_uuid::rack::RackId;
use model::rack_type::{RackHardwareType, RackProfile};

/// RMS wildcard hardware-type value for requests not tied to one rack profile.
pub const ANY_RACK_HARDWARE_TYPE: &str = "any";

/// RMS wire value used when firmware artifacts do not require authentication.
pub const RMS_NOAUTH_ACCESS_TOKEN: &str = "NOAUTH";

/// Firmware objects contain metadata, not firmware binaries. This limit bounds
/// memory use if a configured source returns an unexpected response.
const MAX_FIRMWARE_OBJECT_BYTES: usize = 16 * 1024 * 1024;

/// Loads a complete SOT firmware-object document without interpreting it.
#[async_trait]
pub trait FirmwareObjectFetcher: std::fmt::Debug + Send + Sync {
    /// Fetches the body from `url` within `timeout`.
    ///
    /// The returned text is forwarded unchanged. RMS owns JSON interpretation
    /// and firmware inventory comparison.
    async fn fetch(&self, url: &str, timeout: Duration) -> Result<String, String>;
}

#[async_trait]
impl FirmwareObjectFetcher for reqwest::Client {
    async fn fetch(&self, url: &str, timeout: Duration) -> Result<String, String> {
        let mut response = self
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| {
                format!(
                    "failed to fetch configured SOT firmware object: {}",
                    error.without_url()
                )
            })?
            .error_for_status()
            .map_err(|error| {
                format!(
                    "configured SOT firmware object returned an unsuccessful HTTP status: {}",
                    error.without_url()
                )
            })?;

        if response
            .content_length()
            .is_some_and(|length| length > MAX_FIRMWARE_OBJECT_BYTES as u64)
        {
            return Err(format!(
                "configured SOT firmware object exceeds the {MAX_FIRMWARE_OBJECT_BYTES}-byte size limit"
            ));
        }

        let mut body = Vec::new();

        while let Some(chunk) = response.chunk().await.map_err(|error| {
            format!(
                "failed to read configured SOT firmware object: {}",
                error.without_url()
            )
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_FIRMWARE_OBJECT_BYTES {
                return Err(format!(
                    "configured SOT firmware object exceeds the {MAX_FIRMWARE_OBJECT_BYTES}-byte size limit"
                ));
            }

            body.extend_from_slice(&chunk);
        }

        String::from_utf8(body).map_err(|error| {
            format!("configured SOT firmware object body is not valid UTF-8: {error}")
        })
    }
}

/// Converts an optional rack hardware type to the RMS wire representation.
pub fn hardware_type_wire_value(value: Option<&RackHardwareType>) -> String {
    value.map(|value| value.0.clone()).unwrap_or_default()
}

/// Returns the rack profile's hardware type in the RMS wire representation.
pub fn profile_hardware_type_wire_value(profile: &RackProfile) -> String {
    hardware_type_wire_value(profile.rack_hardware_type.as_ref())
}

/// Returns an artifact access token or the RMS no-auth sentinel.
///
/// Empty and whitespace-only tokens select no-auth. Any token containing a
/// non-whitespace character is preserved byte-for-byte.
pub fn rms_access_token_or_noauth(access_token: Option<&str>) -> String {
    access_token
        .filter(|token| !token.trim().is_empty())
        .unwrap_or(RMS_NOAUTH_ACCESS_TOKEN)
        .to_string()
}

/// Returns the credential key used by the rack maintenance workflow.
pub fn rack_maintenance_access_token_key(rack_id: &RackId) -> CredentialKey {
    CredentialKey::RackMaintenanceAccessToken {
        rack_id: rack_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_rack_hardware_type_serializes_empty() {
        assert_eq!(hardware_type_wire_value(None), "");
    }

    #[test]
    fn rms_access_token_defaults_to_noauth() {
        assert_eq!(rms_access_token_or_noauth(None), RMS_NOAUTH_ACCESS_TOKEN);
        assert_eq!(
            rms_access_token_or_noauth(Some("")),
            RMS_NOAUTH_ACCESS_TOKEN
        );

        assert_eq!(
            rms_access_token_or_noauth(Some(" \n\t")),
            RMS_NOAUTH_ACCESS_TOKEN
        );

        assert_eq!(rms_access_token_or_noauth(Some(" token\n")), " token\n");
    }
}
