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

use serde_json::json;

use crate::DpuMachineInfo;

pub fn dpu_dell_nic_info(function_id: &str, machine_info: &DpuMachineInfo) -> serde_json::Value {
    json!({
        "Dell": {
            "@odata.type": "#DellOem.v1_3_0.DellOemResources",
            "DellNIC": {
                "Id": function_id,
                "SerialNumber": machine_info.serial,
                // TODO: We need more precise model of the
                // hardware. Slot / port must be part of machine_info
                // in future.
                "DeviceDescription": "NIC in Slot 5 Port 1"
            }
        }
    })
}
