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

use chrono::{DateTime, Utc};
use mac_address::MacAddress;

/// A subsystem that may suppress handling of a BMC MAC address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum BmcSuppressionSubsystem {
    SiteExplorer,
    Dhcp,
}

/// An active suppression request for one BMC MAC address and subsystem.
#[derive(Clone, Debug, Eq, PartialEq, sqlx::FromRow)]
pub struct BmcSuppression {
    pub bmc_mac_address: MacAddress,
    pub subsystem: BmcSuppressionSubsystem,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// A new suppression request for one BMC MAC address and subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewBmcSuppression {
    pub bmc_mac_address: MacAddress,
    pub subsystem: BmcSuppressionSubsystem,
    pub reason: String,
}
