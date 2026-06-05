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

use carbide_utils::config::as_std_duration;
use duration_str::deserialize_duration;
use serde::{Deserialize, Serialize};

/// Controls which machine validation tests are active.
#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MachineValidationTestSelectionMode {
    /// Only update tests in DB that are specified in the
    /// `tests` config list.
    #[default]
    Default,
    /// Enable all tests in DB, but allow per-test overrides
    /// from the `tests` config list.
    EnableAll,
    /// Disable all tests in DB, but allow per-test overrides
    /// from the `tests` config list.
    DisableAll,
}

/// Configuration for machine validation tests (memory
/// latency, SSD I/O, etc.) run after ingestion to verify
/// hardware health.
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct MachineValidationConfig {
    /// Enables machine validation testing.
    #[serde(default)]
    pub enabled: bool,

    /// Controls whether to run all tests, no tests, or use
    /// per-test configuration.
    #[serde(default)]
    pub test_selection_mode: MachineValidationTestSelectionMode,

    #[serde(
        default = "MachineValidationConfig::default_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval: std::time::Duration,

    /// Per-test enable/disable overrides.
    #[serde(default)]
    pub tests: Vec<MachineValidationTestConfig>,
}

/// Per-test override for machine validation.
///
/// Example:
/// ```toml
/// tests = [
///    { id = "MmMemLatency", enable = true },
///    { id = "FioSSD", enable = true }
/// ]
/// ```
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct MachineValidationTestConfig {
    /// Unique test identifier (e.g., "MmMemLatency").
    pub id: String,
    /// Whether this test is enabled.
    pub enable: bool,
}

impl MachineValidationConfig {
    const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}
