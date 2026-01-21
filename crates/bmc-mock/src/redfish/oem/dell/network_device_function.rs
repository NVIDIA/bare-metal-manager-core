/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
