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

use std::hash::{DefaultHasher, Hash, Hasher};

use crate::client::NvueClientError;

#[derive(Clone, Debug, Hash, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct NvueConfig {
    // FIXME: Replace this with a more strongly typed inner representation
    config_json: serde_json::Value,
}

impl NvueConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn remove_rev_id(&mut self) {
        if let serde_json::Value::Object(config_root) = &mut self.config_json
            && let Some(header_value) = config_root.get_mut("header")
            && let serde_json::Value::Object(header_object) = header_value
        {
            let _ = header_object.remove("rev-id");
        }
    }

    /// Extract the value under the `set` key from the top-level list structure
    /// produced by the NVUE startup templates (i.e. `[{header: ...}, {set: ...}]`).
    ///
    /// Returns:
    /// - `Ok(Some(_))` if the config was a template-wrapped array and a `set`
    ///   entry was found.
    /// - `Ok(None)` if the config is not an array, i.e. it is already a plain
    ///   object and can be used as-is.
    /// - `Err(SchemaMismatch)` if the config *is* a top-level array but
    ///   contains no `set` entry — this is an unexpected shape that would
    ///   produce a hard-to-debug REST API rejection if sent as-is.
    pub fn extract_set_payload(&self) -> Result<Option<Self>, NvueClientError> {
        if let serde_json::Value::Array(arr) = &self.config_json {
            for item in arr {
                if let serde_json::Value::Object(map) = item
                    && let Some(set_value) = map.get("set")
                {
                    return Ok(Some(Self {
                        config_json: set_value.clone(),
                    }));
                }
            }
            Err(NvueClientError::SchemaMismatch(
                "config is a top-level array but contains no \"set\" entry",
            ))
        } else {
            Ok(None)
        }
    }

    pub fn u64_hash(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        h.finish()
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct NvueRevision {
    // FIXME: Replace this with a more strongly typed inner representation
    revision_json: serde_json::Value,
}

impl NvueRevision {
    pub fn get_revision_id(&self) -> Option<String> {
        dbg!(self);
        if let serde_json::Value::Object(map) = &self.revision_json
            && map.len() == 1
        {
            map.keys().nth(0).cloned()
        } else {
            None
        }
    }
}
