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

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct InjectedBugs {
    all_dpu_lost_on_host: Arc<AtomicBool>,
}

#[derive(Deserialize, Serialize)]
struct Args {
    all_dpu_lost_on_host: Option<bool>,
}

impl InjectedBugs {
    pub fn get(&self) -> serde_json::Value {
        serde_json::json!(Args {
            all_dpu_lost_on_host: Some(self.all_dpu_lost_on_host().is_some()),
        })
    }

    pub fn update(&self, v: serde_json::Value) {
        let Ok(args) = serde_json::from_value::<Args>(v) else {
            return;
        };

        self.all_dpu_lost_on_host.store(
            args.all_dpu_lost_on_host.unwrap_or(false),
            Ordering::Relaxed,
        );
    }

    pub fn all_dpu_lost_on_host(&self) -> Option<AllDpuLostOnHost> {
        self.all_dpu_lost_on_host
            .load(Ordering::Relaxed)
            .then_some(AllDpuLostOnHost {})
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
