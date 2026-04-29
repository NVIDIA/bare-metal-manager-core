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

use duration_str::deserialize_duration;
use serde::{Deserialize, Serialize};
use utils::config::as_std_duration;

/// NvLink related configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct NvLinkConfig {
    /// Enables NvLink partitioning.
    #[serde(default)]
    pub enabled: bool,

    /// Defaults to 1 Minute if not specified.
    #[serde(
        default = "NvLinkConfig::default_monitor_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub monitor_run_interval: std::time::Duration,

    /// Timeout for pending NMX-M operations. Defaults to 10 seconds if not specified.
    #[serde(
        default = "NvLinkConfig::default_nmx_m_operation_timeout",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub nmx_m_operation_timeout: std::time::Duration,

    /// NMX-M endpoint (name or IP address) used to create client connections,
    /// include port number as well if required eg. https://127.0.0.1:4010
    #[serde(default = "default_nmx_m_endpoint")]
    pub nmx_m_endpoint: String,
    /// Set to true if NMX-M doesn't adhere to security requirements. Defaults to false
    pub allow_insecure: bool,
}

fn default_nmx_m_endpoint() -> String {
    "localhost".to_string()
}

impl Default for NvLinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            monitor_run_interval: Self::default_monitor_run_interval(),
            nmx_m_operation_timeout: Self::default_nmx_m_operation_timeout(),
            nmx_m_endpoint: "localhost".to_string(),
            allow_insecure: false,
        }
    }
}

impl NvLinkConfig {
    pub const fn default_monitor_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
    pub const fn default_nmx_m_operation_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(10)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deserialize_serialize_nvlink_config() {
        let value_json = r#"{"enabled": true, "allow_insecure": true, "monitor_run_interval": "33", "nmx_m_operation_timeout": "21", "nmx_m_endpoint": "localhost"}"#;

        let nvlink_config: NvLinkConfig = serde_json::from_str(value_json).unwrap();
        assert_eq!(
            nvlink_config,
            NvLinkConfig {
                enabled: true,
                monitor_run_interval: std::time::Duration::from_secs(33),
                nmx_m_operation_timeout: std::time::Duration::from_secs(21),
                nmx_m_endpoint: "localhost".to_string(),
                allow_insecure: true,
            }
        );
    }
}
