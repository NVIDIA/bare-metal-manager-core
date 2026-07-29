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
use sqlx::FromRow;

/// A row from the `ignored_bmc_macs` table.
///
/// Tracks per-MAC suppression state for Site Explorer and DHCP during
/// decommissioning. The two suppressed-at timestamps are written exclusively
/// by Site Explorer and the DHCP server respectively, and serve as
/// acknowledgements that the decommissioning workflow waits on before
/// advancing to hardware cleanup or the `Decommissioned` terminal state.
#[derive(Debug, Clone, FromRow)]
pub struct IgnoredBmcMac {
    pub bmc_mac_address: MacAddress,
    pub reason: String,
    pub suppress_site_explorer: bool,
    pub site_explorer_suppressed_at: Option<DateTime<Utc>>,
    pub suppress_dhcp: bool,
    pub dhcp_discover_suppressed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
