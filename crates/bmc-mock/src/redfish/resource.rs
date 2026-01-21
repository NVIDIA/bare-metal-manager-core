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

use std::borrow::Cow;

use serde_json::json;

use crate::json::JsonPatch;

/// Defines minimal set of Redfish resource attributes.
pub struct Resource<'a> {
    pub odata_id: Cow<'a, str>,
    pub odata_type: Cow<'a, str>,
    pub id: Cow<'a, str>,
    pub name: Cow<'a, str>,
}

impl<'a> Resource<'a> {
    pub fn entity_ref(&self) -> serde_json::Value {
        json!({
            "@odata.id": self.odata_id
        })
    }
    pub fn nav_property(&self, name: &str) -> serde_json::Value {
        json!({
            name: {
                "@odata.id": self.odata_id
            }
        })
    }
    pub fn with_name(mut self, name: &'a str) -> Self {
        self.name = Cow::Borrowed(name);
        self
    }
}

impl JsonPatch for Resource<'_> {
    fn json_patch(&self) -> serde_json::Value {
        json!({
            "@odata.id": self.odata_id,
            "@odata.type": self.odata_type,
            "Id": self.id,
            "Name": self.name,
        })
    }
}

pub enum Status {
    Ok,
}

impl Status {
    pub fn into_json(self) -> serde_json::Value {
        json!({
            "State": "Enabled",
            "Health": "OK",
        })
    }
}
