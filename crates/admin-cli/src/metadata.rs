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
use rpc::Metadata;

pub(crate) fn get_nice_labels_from_rpc_metadata(metadata: Option<&Metadata>) -> Vec<String> {
    metadata
        .map(|m| {
            m.labels
                .iter()
                .map(|label| {
                    let key = &label.key;
                    let value = label.value.as_deref().unwrap_or_default();
                    format!("\"{key}:{value}\"")
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_rpc_labels(labels: Vec<String>) -> Vec<rpc::forge::Label> {
    labels
        .into_iter()
        .map(|label| match label.split_once(':') {
            Some((k, v)) => rpc::forge::Label {
                key: k.trim().to_string(),
                value: Some(v.trim().to_string()),
            },
            None => rpc::forge::Label {
                key: if label.contains(char::is_whitespace) {
                    label.trim().to_string()
                } else {
                    // avoid allocations on the happy path
                    label
                },
                value: None,
            },
        })
        .collect()
}
