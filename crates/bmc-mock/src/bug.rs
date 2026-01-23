/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use duration_str::deserialize_option_duration;
use serde::{Deserialize, Serialize};

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
        serde_json::json!({
            "Id": network_adapter_id,
            "Name": "Network Adpapter",
            "Status": {
                "State": "Enabled",
                "Health": "OK"
            },
            "@odata.id": format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}"),
            "@odata.context": "/redfish/v1/$metadata#NetworkAdapter.NetworkAdapter",
            "SKU": "",
            "Model": "",
            "Description": "A NetworkAdapter represents the physical network adapter capable of connecting to a computer network.",
            "@odata.type": "#NetworkAdapter.v1_9_0.NetworkAdapter",
            "SerialNumber": "",
            "PartNumber": "",
            "Manufacturer": "",
            "NetworkDeviceFunctions": {
                "@odata.id": format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions")
            },
        })
    }
}
