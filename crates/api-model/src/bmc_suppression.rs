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

/// Code path that requested a BMC MAC suppression.
///
/// Each source owns its own `(bmc_mac_address, subsystem, source)` row so
/// independent workflows can suppress and clear without fighting over a shared
/// row. A subsystem treats a MAC as suppressed while any source still has a
/// matching row.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum BmcSuppressionSource {
    Decommissioning,
}

/// An active suppression request for one BMC MAC address, subsystem, and source.
#[derive(Clone, Debug, Eq, PartialEq, sqlx::FromRow)]
pub struct BmcSuppression {
    pub bmc_mac_address: MacAddress,
    pub subsystem: BmcSuppressionSubsystem,
    pub source: BmcSuppressionSource,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// A new suppression request for one BMC MAC address, subsystem, and source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewBmcSuppression {
    pub bmc_mac_address: MacAddress,
    pub subsystem: BmcSuppressionSubsystem,
    pub source: BmcSuppressionSource,
    pub reason: String,
}
