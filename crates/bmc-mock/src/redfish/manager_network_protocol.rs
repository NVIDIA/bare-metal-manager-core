/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use crate::redfish::Builder;

pub fn manager_resource<'a>(manager_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Managers/{manager_id}/NetworkProtocol");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#ManagerNetworkProtocol.v1_5_0.ManagerNetworkProtocol"),
        id: Cow::Borrowed("NetworkProtocol"),
        name: Cow::Borrowed("Manager Network Protocol"),
    }
}

/// Get builder of the network adapter.
pub fn builder(resource: &redfish::Resource) -> ManagerNetworkProtocolBuilder {
    ManagerNetworkProtocolBuilder {
        value: resource.json_patch(),
    }
}

pub struct ManagerNetworkProtocolBuilder {
    value: serde_json::Value,
}

impl Builder for ManagerNetworkProtocolBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl ManagerNetworkProtocolBuilder {
    pub fn ipmi_enabled(self, value: bool) -> Self {
        self.apply_patch(json!({"IPMI": { "ProtocolEnabled": value }}))
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }
}
