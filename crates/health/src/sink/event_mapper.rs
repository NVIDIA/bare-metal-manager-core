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

use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[allow(dead_code)] // used by OtlpSink in the next commit
pub trait RedfishEventMapper: Send + Sync {
    fn queue_key(&self, bmc_id: &str, attributes: &[(Cow<'static, str>, String)]) -> String;
}

#[allow(dead_code)] // used by OtlpSink in the next commit
pub struct OpenBmcEventMapper;

#[allow(dead_code)]
impl OpenBmcEventMapper {
    fn find_attr<'a>(attributes: &'a [(Cow<'static, str>, String)], key: &str) -> Option<&'a str> {
        attributes
            .iter()
            .find(|(k, _)| k.as_ref() == key)
            .map(|(_, v)| v.as_str())
    }

    fn first_message_arg(attributes: &[(Cow<'static, str>, String)]) -> String {
        Self::find_attr(attributes, "message_args")
            .and_then(|json| serde_json::from_str::<Vec<String>>(json).ok())
            .and_then(|args| args.into_iter().next())
            .unwrap_or_default()
    }

    fn hash_string(s: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }
}

impl RedfishEventMapper for OpenBmcEventMapper {
    fn queue_key(&self, bmc_id: &str, attributes: &[(Cow<'static, str>, String)]) -> String {
        let message_id = Self::find_attr(attributes, "message_id").unwrap_or("");

        if message_id.is_empty() {
            let body = Self::find_attr(attributes, "body").unwrap_or("");
            return format!("{bmc_id}|raw|{}", Self::hash_string(body));
        }

        let resource = Self::first_message_arg(attributes);

        if message_id.contains("SensorThreshold") {
            return format!("{bmc_id}|SensorThreshold|{resource}");
        }

        if message_id.starts_with("ResourceEvent.") && message_id.contains("ResourceStatusChanged")
        {
            return format!("{bmc_id}|ResourceStatusChanged|{resource}");
        }

        format!("{bmc_id}|{message_id}|{resource}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> Vec<(Cow<'static, str>, String)> {
        pairs
            .iter()
            .map(|(k, v)| (Cow::Owned(k.to_string()), v.to_string()))
            .collect()
    }

    #[test]
    fn sensor_threshold_normalizes_direction() {
        let mapper = OpenBmcEventMapper;
        let key_high = mapper.queue_key(
            "10.85.14.144",
            &attrs(&[
                (
                    "message_id",
                    "OpenBMC.0.1.SensorThresholdWarningLowGoingHigh",
                ),
                ("message_args", r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#),
            ]),
        );
        let key_low = mapper.queue_key(
            "10.85.14.144",
            &attrs(&[
                (
                    "message_id",
                    "OpenBMC.0.1.SensorThresholdWarningHighGoingLow",
                ),
                ("message_args", r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#),
            ]),
        );
        assert_eq!(key_high, key_low);
        assert!(key_high.contains("SensorThreshold"));
        assert!(key_high.contains("HGX_GPU_0_Temp_1"));
    }

    #[test]
    fn health_status_normalizes_severity() {
        let mapper = OpenBmcEventMapper;
        let key_critical = mapper.queue_key(
            "10.85.14.144",
            &attrs(&[
                (
                    "message_id",
                    "ResourceEvent.1.0.ResourceStatusChangedCritical",
                ),
                ("message_args", r#"["leakage1"]"#),
            ]),
        );
        let key_ok = mapper.queue_key(
            "10.85.14.144",
            &attrs(&[
                ("message_id", "ResourceEvent.1.0.ResourceStatusChangedOK"),
                ("message_args", r#"["leakage1"]"#),
            ]),
        );
        assert_eq!(key_critical, key_ok);
        assert!(key_critical.contains("ResourceStatusChanged"));
        assert!(key_critical.contains("leakage1"));
    }

    #[test]
    fn different_devices_are_different_keys() {
        let mapper = OpenBmcEventMapper;
        let key_gpu0 = mapper.queue_key(
            "10.85.14.144",
            &attrs(&[
                ("message_id", "ResourceEvent.1.0.ResourceErrorsDetected"),
                (
                    "message_args",
                    r#"["GPU_0 NVLink_9","NVLink Training Error"]"#,
                ),
            ]),
        );
        let key_gpu1 = mapper.queue_key(
            "10.85.14.144",
            &attrs(&[
                ("message_id", "ResourceEvent.1.0.ResourceErrorsDetected"),
                (
                    "message_args",
                    r#"["GPU_1 NVLink_9","NVLink Training Error"]"#,
                ),
            ]),
        );
        assert_ne!(key_gpu0, key_gpu1);
    }

    #[test]
    fn legacy_entry_without_message_id_uses_message_hash() {
        let mapper = OpenBmcEventMapper;
        let key = mapper.queue_key("10.85.14.144", &attrs(&[("message_id", "")]));
        assert!(key.contains("raw|"));
    }
}
