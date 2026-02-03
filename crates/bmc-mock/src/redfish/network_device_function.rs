/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::borrow::Cow;

use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;

pub fn chassis_collection(
    chassis_id: &str,
    network_adapter_id: &str,
) -> redfish::Collection<'static> {
    let odata_id = format!(
        "/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions"
    );
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed(
            "#NetworkDeviceFunctionCollection.NetworkDeviceFunctionCollection",
        ),
        name: Cow::Borrowed("Network Device Function Collection"),
    }
}

pub fn chassis_resource<'a>(
    chassis_id: &'a str,
    network_adapter_id: &'a str,
    function_id: &'a str,
) -> redfish::Resource<'a> {
    let odata_id = format!(
        "/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{function_id}"
    );
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#NetworkDeviceFunction.v1_7_0.NetworkDeviceFunction"),
        id: Cow::Borrowed(function_id),
        name: Cow::Borrowed("NetworkDeviceFunction"),
    }
}

/// Get builder of the network device function.
pub fn builder(resource: &redfish::Resource) -> NetworkDeviceFunctionBuilder {
    NetworkDeviceFunctionBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub struct NetworkDeviceFunction {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl NetworkDeviceFunction {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub struct NetworkDeviceFunctionBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl NetworkDeviceFunctionBuilder {
    pub fn ethernet(self, v: serde_json::Value) -> Self {
        self.apply_patch(json!({ "Ethernet": v }))
    }

    pub fn oem(self, v: serde_json::Value) -> Self {
        self.apply_patch(json!({ "Oem": v }))
    }

    pub fn build(self) -> NetworkDeviceFunction {
        NetworkDeviceFunction {
            id: self.id,
            value: self.value,
        }
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}
