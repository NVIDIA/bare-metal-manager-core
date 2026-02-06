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
