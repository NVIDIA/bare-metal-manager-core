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

use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn resource<'a>(chassis_id: &str, supply_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!(
        "{}/PowerSubsystem/PowerSupplies/{supply_id}",
        redfish::chassis::resource(chassis_id).odata_id
    );
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#PowerSupply.v1_5_0.PowerSupply"),
        id: Cow::Borrowed(supply_id),
        name: Cow::Borrowed("Power Supply"),
    }
}

pub fn collection(chassis_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!(
        "{}/PowerSubsystem/PowerSupplies",
        redfish::chassis::resource(chassis_id).odata_id
    );
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#PowerSupplyCollection.PowerSupplyCollection"),
        name: Cow::Borrowed("Power Supply"),
    }
}

pub struct PowerSupply {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl PowerSupply {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub fn builder(resource: &redfish::Resource) -> PowerSupplyBuilder {
    PowerSupplyBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub struct PowerSupplyBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for PowerSupplyBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}

impl PowerSupplyBuilder {
    pub fn oem_liteon_power_state(self, v: bool) -> Self {
        self.apply_patch(json!({"PowerState": v}))
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        self.apply_patch(json!({
            "Status": status.into_json()
        }))
    }

    pub fn build(self) -> PowerSupply {
        PowerSupply {
            id: self.id,
            value: self.value,
        }
    }
}
