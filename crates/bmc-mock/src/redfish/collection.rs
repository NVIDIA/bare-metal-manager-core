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

use crate::json::{JsonExt, JsonPatch};

/// Defines minimal set of Redfish resource attributes.
pub struct Collection<'a> {
    pub odata_id: Cow<'a, str>,
    pub odata_type: Cow<'a, str>,
    pub name: Cow<'a, str>,
}

impl Collection<'_> {
    pub fn nav_property(&self, name: &str) -> serde_json::Value {
        json!({
            name: {
                "@odata.id": self.odata_id
            }
        })
    }

    pub fn with_members(&self, members: &[impl serde::Serialize]) -> serde_json::Value {
        let count = members.len();
        self.json_patch().patch(json!({
            "Members": members,
            "Members@odata.count": count,
        }))
    }
}

impl JsonPatch for Collection<'_> {
    fn json_patch(&self) -> serde_json::Value {
        json!({
            "@odata.id": self.odata_id,
            "@odata.type": self.odata_type,
            "Name": self.name,
        })
    }
}
