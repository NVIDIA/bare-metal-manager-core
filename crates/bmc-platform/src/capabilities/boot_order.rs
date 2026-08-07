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
use mac_address::MacAddress;
use nv_redfish::computer_system::BootOptionReference;
use nv_redfish::schema::boot_option::BootOption;
use nv_redfish::schema::computer_system::BootUpdate;
use serde::{Deserialize, Serialize};

use crate::{DriverOutcome, OpCx, PlatformError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum BootInterfaceSelector {
    Mac(MacAddress),
    InterfaceId(String),
    Pair {
        mac_address: MacAddress,
        interface_id: String,
    },
}

/// One-time boot override and persistent boot-order operations.
#[async_trait]
pub trait BootOrder: Send + Sync {
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
        override_setting: &BootUpdate,
    ) -> Result<DriverOutcome, PlatformError>;

    async fn set_order(
        &self,
        cx: &OpCx<'_>,
        order: &[BootOptionReference<String>],
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
