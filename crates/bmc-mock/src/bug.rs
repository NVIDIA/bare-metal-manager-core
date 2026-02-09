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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use duration_str::deserialize_option_duration;
use serde::{Deserialize, Serialize};

use crate::redfish;

#[derive(Clone, Default)]
pub struct InjectedBugs {
    all_dpu_lost_on_host: Arc<AtomicBool>,
    long_response: Arc<ArcSwap<Option<LongResponse>>>,
}

#[derive(Deserialize, Serialize)]
struct Args {
    all_dpu_lost_on_host: Option<bool>,
    long_response: Option<LongResponse>,
}

#[derive(Clone, Deserialize, Serialize)]
struct LongResponse {
    path: Option<String>,
    #[serde(deserialize_with = "deserialize_option_duration")]
    timeout: Option<Duration>,
}

impl InjectedBugs {
    pub fn get(&self) -> serde_json::Value {
        let long_response = self.long_response.load();
        serde_json::json!(Args {
            all_dpu_lost_on_host: Some(self.all_dpu_lost_on_host().is_some()),
            long_response: long_response.as_ref().clone()
        })
    }

    pub fn update(&self, v: serde_json::Value) -> Result<(), serde_json::Error> {
        let args = serde_json::from_value::<Args>(v)?;

        self.all_dpu_lost_on_host.store(
            args.all_dpu_lost_on_host.unwrap_or(false),
            Ordering::Relaxed,
        );

        self.long_response.store(args.long_response.into());
        Ok(())
    }

    pub fn all_dpu_lost_on_host(&self) -> Option<AllDpuLostOnHost> {
        self.all_dpu_lost_on_host
            .load(Ordering::Relaxed)
            .then_some(AllDpuLostOnHost {})
    }

    pub fn long_response(&self, path: &str) -> Option<Duration> {
        self.long_response.load().as_ref().as_ref().and_then(|v| {
            if v.path.as_ref().is_none_or(|v| v == path) {
                v.timeout
            } else {
                None
            }
        })
    }
}

pub struct AllDpuLostOnHost {}

impl AllDpuLostOnHost {
    // This is Network adapter as it was reproduced in FORGE-7578.
    pub fn network_adapter(&self, chassis_id: &str, network_adapter_id: &str) -> serde_json::Value {
        let resource = redfish::network_adapter::chassis_resource(chassis_id, network_adapter_id);
        redfish::network_adapter::builder(&resource)
            .status(redfish::resource::Status::Ok)
            .model("")
            .serial_number("")
            .manufacturer("")
            .part_number("")
            .sku("")
            .network_device_functions(
                &redfish::network_device_function::chassis_collection(
                    chassis_id,
                    network_adapter_id,
                ),
                vec![],
            )
            .build()
            .to_json()
    }
}
