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

use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};

/// History of Switch states for a single Switch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateHistoryRecord {
    /// The state that was entered
    pub state: String,
    // The version number associated with the state change
    pub state_version: ConfigVersion,
}

impl From<StateHistoryRecord> for ::rpc::forge::StateHistoryRecord {
    fn from(value: StateHistoryRecord) -> ::rpc::forge::StateHistoryRecord {
        ::rpc::forge::StateHistoryRecord {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.state_version.timestamp().into()),
        }
    }
}
