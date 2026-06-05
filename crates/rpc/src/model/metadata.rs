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

use model::metadata::{LabelFilter, Metadata};

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl From<Metadata> for rpc::Metadata {
    fn from(metadata: Metadata) -> Self {
        rpc::Metadata {
            name: metadata.name,
            description: metadata.description,
            labels: metadata
                .labels
                .iter()
                .map(|(key, value)| rpc::forge::Label {
                    key: key.clone(),
                    value: if value.is_empty() {
                        None
                    } else {
                        Some(value.clone())
                    },
                })
                .collect(),
        }
    }
}

impl TryFrom<rpc::Metadata> for Metadata {
    type Error = RpcDataConversionError;

    fn try_from(metadata: rpc::Metadata) -> Result<Self, Self::Error> {
        let mut labels = std::collections::HashMap::new();

        for label in metadata.labels {
            let key = label.key.clone();
            let value = label.value.clone().unwrap_or_default();

            if labels.contains_key(&key) {
                return Err(RpcDataConversionError::InvalidLabel(format!(
                    "Duplicate key found: {key}"
                )));
            }

            labels.insert(key, value);
        }

        Ok(Metadata {
            name: metadata.name,
            description: metadata.description,
            labels,
        })
    }
}

impl From<rpc::forge::Label> for LabelFilter {
    fn from(label: rpc::forge::Label) -> Self {
        LabelFilter {
            key: label.key,
            value: label.value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_filter_from_rpc_with_value() {
        let rpc_label = rpc::forge::Label {
            key: "env".to_string(),
            value: Some("prod".to_string()),
        };
        let filter = LabelFilter::from(rpc_label);
        assert_eq!(filter.key, "env");
        assert_eq!(filter.value, Some("prod".to_string()));
    }

    #[test]
    fn label_filter_from_rpc_without_value() {
        let rpc_label = rpc::forge::Label {
            key: "env".to_string(),
            value: None,
        };
        let filter = LabelFilter::from(rpc_label);
        assert_eq!(filter.key, "env");
        assert_eq!(filter.value, None);
    }

    #[test]
    fn label_filter_from_rpc_empty_key() {
        let rpc_label = rpc::forge::Label {
            key: String::new(),
            value: Some("prod".to_string()),
        };
        let filter = LabelFilter::from(rpc_label);
        assert!(filter.key.is_empty());
        assert_eq!(filter.value, Some("prod".to_string()));
    }
}
