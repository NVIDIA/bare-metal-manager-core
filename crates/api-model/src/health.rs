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
use serde::{Deserialize, Serialize};

/// History of health for a single Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthHistoryRecord {
    /// The observed health of the Object
    pub health: health_report::HealthReport,

    /// The time when the health was observed
    pub time: DateTime<Utc>,
}

impl From<HealthHistoryRecord> for rpc::forge::HealthHistoryRecord {
    fn from(record: HealthHistoryRecord) -> rpc::forge::HealthHistoryRecord {
        rpc::forge::HealthHistoryRecord {
            health: Some(record.health.into()),
            time: Some(record.time.into()),
        }
    }
}
