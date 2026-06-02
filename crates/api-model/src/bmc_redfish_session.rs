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

use mac_address::MacAddress;
use sqlx::types::chrono::{DateTime, Utc};

/// A row in the `bmc_redfish_sessions` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredSession {
    pub spiffe_service_id: String,
    pub bmc_mac_address: MacAddress,
    pub session_odata_id: String,
    pub issued_at: DateTime<Utc>,
}
