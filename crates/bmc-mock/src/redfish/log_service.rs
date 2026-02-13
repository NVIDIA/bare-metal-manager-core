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

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn manager_collection(manager_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Managers/{manager_id}/LogServices");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#LogServiceCollection.LogServiceCollection"),
        name: Cow::Borrowed("Log Service Collection"),
    }
}

pub fn system_collection(system_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/LogServices");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#LogServiceCollection.LogServiceCollection"),
        name: Cow::Borrowed("Log Service Collection"),
    }
}

pub fn system_resource<'a>(system_id: &str, service_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/LogServices/{service_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#LogService.v1_2_0.LogService"),
        name: Cow::Borrowed("Log Service"),
        id: Cow::Borrowed(service_id),
    }
}

pub fn system_entries_collection<'a>(
    system_id: &str,
    service_id: &'a str,
) -> redfish::Collection<'a> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/LogServices/{service_id}/Entries");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#LogEntryCollection.LogEntryCollection"),
        name: Cow::Borrowed("Log Entries"),
    }
}

pub fn builder(resource: &redfish::Resource<'_>) -> LogServiceBuilder {
    LogServiceBuilder {
        value: resource.json_patch(),
    }
}

pub fn event_entry(collection: &redfish::Collection<'_>, id: &str) -> EntryBuilder {
    let odata_id = format!("{}/{}", collection.odata_id, id);
    EntryBuilder {
        value: redfish::Resource {
            odata_id: Cow::Owned(odata_id),
            odata_type: Cow::Borrowed("#LogEntry.v1_15_0.LogEntry"),
            name: Cow::Borrowed("Log Entry"),
            id: Cow::Borrowed(id),
        }
        .json_patch(),
    }
    .entry_type("Event")
}

pub struct LogServiceBuilder {
    value: serde_json::Value,
}

impl Builder for LogServiceBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl LogServiceBuilder {
    pub fn entries(self, v: &redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("Entries"))
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }
}

pub struct EntryBuilder {
    value: serde_json::Value,
}

impl Builder for EntryBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl EntryBuilder {
    pub fn entry_type(self, v: &str) -> Self {
        self.add_str_field("EntryType", v)
    }

    pub fn message(self, v: &str) -> Self {
        self.add_str_field("Message", v)
    }

    pub fn severity(self, v: &str) -> Self {
        self.add_str_field("Severity", v)
    }

    pub fn created(self, v: &str) -> Self {
        self.add_str_field("Created", v)
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }
}
