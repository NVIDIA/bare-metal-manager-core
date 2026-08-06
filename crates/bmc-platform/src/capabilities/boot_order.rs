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

use crate::{DriverOutcome, OpCx, PlatformError};

/// A boot source NICo actively requests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BootTarget {
    Pxe,
    HardDisk,
    UefiHttp { uri: Option<String> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootFirmwareMode {
    Uefi,
    Legacy,
}

/// A valid Redfish boot override request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BootOverride {
    Disabled,
    Once {
        target: BootTarget,
        firmware_mode: Option<BootFirmwareMode>,
    },
    Continuous {
        target: BootTarget,
        firmware_mode: Option<BootFirmwareMode>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum BootInterfaceSelector {
    Mac(String),
    InterfaceId(String),
    Pair {
        mac_address: String,
        interface_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootOption {
    pub id: String,
    pub reference: String,
    pub display_name: String,
    pub description: Option<String>,
    pub uefi_device_path: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootOrderStatus {
    pub order: Vec<String>,
}

/// One-time boot override and persistent boot-order operations.
#[async_trait]
pub trait BootOrder: Send + Sync {
    async fn status(&self, cx: &OpCx<'_>) -> Result<BootOrderStatus, PlatformError>;

    async fn options(&self, cx: &OpCx<'_>) -> Result<Vec<BootOption>, PlatformError>;

    /// Reports whether the selected host boot interface is first.
    ///
    /// The interface may be a DPU, a DPU in NIC mode, or a conventional NIC.
    async fn is_boot_interface_first(
        &self,
        cx: &OpCx<'_>,
        interface: &BootInterfaceSelector,
    ) -> Result<bool, PlatformError>;

    async fn set_override(
        &self,
        cx: &OpCx<'_>,
        override_setting: &BootOverride,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn set_order(
        &self,
        cx: &OpCx<'_>,
        order: &[String],
    ) -> Result<DriverOutcome, PlatformError>;

    /// Moves the selected host boot interface to the first boot position.
    async fn set_boot_interface_first(
        &self,
        cx: &OpCx<'_>,
        interface: &BootInterfaceSelector,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn infinite_boot_enabled(&self, cx: &OpCx<'_>) -> Result<Option<bool>, PlatformError>;

    async fn enable_infinite_boot(&self, cx: &OpCx<'_>) -> Result<DriverOutcome, PlatformError>;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn boot_override_representation_prevents_unrelated_target_fields() {
        let cases = [
            (BootOverride::Disabled, json!({"mode": "disabled"})),
            (
                BootOverride::Once {
                    target: BootTarget::Pxe,
                    firmware_mode: Some(BootFirmwareMode::Uefi),
                },
                json!({
                    "mode": "once",
                    "target": {"type": "pxe"},
                    "firmware_mode": "uefi"
                }),
            ),
            (
                BootOverride::Continuous {
                    target: BootTarget::UefiHttp {
                        uri: Some("https://boot.example/image".to_string()),
                    },
                    firmware_mode: Some(BootFirmwareMode::Uefi),
                },
                json!({
                    "mode": "continuous",
                    "target": {
                        "type": "uefi_http",
                        "uri": "https://boot.example/image"
                    },
                    "firmware_mode": "uefi"
                }),
            ),
        ];

        for (request, expected) in cases {
            assert_eq!(
                serde_json::to_value(&request).expect("boot override serializes"),
                expected
            );
            assert_eq!(
                serde_json::from_value::<BootOverride>(expected)
                    .expect("boot override deserializes"),
                request
            );
        }
    }
}
