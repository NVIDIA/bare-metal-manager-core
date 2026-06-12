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
    use std::collections::HashMap;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    // `LabelFilter::from` is a total conversion: project to (key, value) — the two
    // fields the originals asserted.
    #[test]
    fn label_filter_from_rpc() {
        check_values(
            [
                Check {
                    scenario: "with value",
                    input: rpc::forge::Label {
                        key: "env".to_string(),
                        value: Some("prod".to_string()),
                    },
                    expect: ("env".to_string(), Some("prod".to_string())),
                },
                Check {
                    scenario: "without value",
                    input: rpc::forge::Label {
                        key: "env".to_string(),
                        value: None,
                    },
                    expect: ("env".to_string(), None),
                },
                Check {
                    scenario: "empty key",
                    input: rpc::forge::Label {
                        key: String::new(),
                        value: Some("prod".to_string()),
                    },
                    expect: (String::new(), Some("prod".to_string())),
                },
            ],
            |label| {
                let filter = LabelFilter::from(label);
                (filter.key, filter.value)
            },
        );
    }

    // `Metadata -> rpc::Metadata` is a total conversion. Project the result to
    // (name, description, sorted labels) so the row-by-row expects are
    // order-independent (labels come out of a `HashMap`). An empty label value
    // collapses to `None`; a non-empty one is wrapped in `Some`.
    #[test]
    fn metadata_into_rpc() {
        type Projected = (String, String, Vec<(String, Option<String>)>);

        check_values(
            [
                Check {
                    scenario: "name and description pass through, no labels",
                    input: Metadata {
                        name: "web".to_string(),
                        description: "front end".to_string(),
                        labels: HashMap::new(),
                    },
                    expect: ("web".to_string(), "front end".to_string(), vec![]),
                },
                Check {
                    scenario: "empty fields pass through",
                    input: Metadata::default(),
                    expect: (String::new(), String::new(), vec![]),
                },
                Check {
                    scenario: "non-empty label value becomes Some",
                    input: Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: HashMap::from([("env".to_string(), "prod".to_string())]),
                    },
                    expect: (
                        "n".to_string(),
                        "d".to_string(),
                        vec![("env".to_string(), Some("prod".to_string()))],
                    ),
                },
                Check {
                    scenario: "empty label value collapses to None",
                    input: Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: HashMap::from([("env".to_string(), String::new())]),
                    },
                    expect: (
                        "n".to_string(),
                        "d".to_string(),
                        vec![("env".to_string(), None)],
                    ),
                },
                Check {
                    scenario: "mixed empty and non-empty label values",
                    input: Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: HashMap::from([
                            ("a".to_string(), "1".to_string()),
                            ("b".to_string(), String::new()),
                        ]),
                    },
                    expect: (
                        "n".to_string(),
                        "d".to_string(),
                        vec![
                            ("a".to_string(), Some("1".to_string())),
                            ("b".to_string(), None),
                        ],
                    ),
                },
            ],
            |metadata| -> Projected {
                let proto = rpc::Metadata::from(metadata);
                let mut labels: Vec<(String, Option<String>)> = proto
                    .labels
                    .into_iter()
                    .map(|label| (label.key, label.value))
                    .collect();
                labels.sort();
                (proto.name, proto.description, labels)
            },
        );
    }

    // `rpc::Metadata -> Metadata` is fallible: a duplicate label key is the one
    // error arm. The error type carries non-PartialEq `#[from]` variants, so the
    // failing rows use `Fails`. Project the Ok result to (name, description,
    // sorted labels) for order-independent comparison.
    #[test]
    fn metadata_try_from_rpc() {
        type Projected = (String, String, Vec<(String, String)>);

        fn label(key: &str, value: Option<&str>) -> rpc::forge::Label {
            rpc::forge::Label {
                key: key.to_string(),
                value: value.map(str::to_string),
            }
        }

        check_cases(
            [
                Case {
                    scenario: "no labels",
                    input: rpc::Metadata {
                        name: "web".to_string(),
                        description: "front end".to_string(),
                        labels: vec![],
                    },
                    expect: Yields(("web".to_string(), "front end".to_string(), vec![])),
                },
                Case {
                    scenario: "empty fields",
                    input: rpc::Metadata {
                        name: String::new(),
                        description: String::new(),
                        labels: vec![],
                    },
                    expect: Yields((String::new(), String::new(), vec![])),
                },
                Case {
                    scenario: "label with value",
                    input: rpc::Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: vec![label("env", Some("prod"))],
                    },
                    expect: Yields((
                        "n".to_string(),
                        "d".to_string(),
                        vec![("env".to_string(), "prod".to_string())],
                    )),
                },
                Case {
                    scenario: "absent label value defaults to empty string",
                    input: rpc::Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: vec![label("env", None)],
                    },
                    expect: Yields((
                        "n".to_string(),
                        "d".to_string(),
                        vec![("env".to_string(), String::new())],
                    )),
                },
                Case {
                    scenario: "multiple distinct keys",
                    input: rpc::Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: vec![label("a", Some("1")), label("b", Some("2"))],
                    },
                    expect: Yields((
                        "n".to_string(),
                        "d".to_string(),
                        vec![
                            ("a".to_string(), "1".to_string()),
                            ("b".to_string(), "2".to_string()),
                        ],
                    )),
                },
                Case {
                    scenario: "duplicate key fails",
                    input: rpc::Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: vec![label("env", Some("a")), label("env", Some("b"))],
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "duplicate key with differing present/absent values fails",
                    input: rpc::Metadata {
                        name: "n".to_string(),
                        description: "d".to_string(),
                        labels: vec![label("env", Some("a")), label("env", None)],
                    },
                    expect: Fails,
                },
            ],
            |proto| -> Result<Projected, ()> {
                let metadata = Metadata::try_from(proto).map_err(drop)?;
                let mut labels: Vec<(String, String)> = metadata.labels.into_iter().collect();
                labels.sort();
                Ok((metadata.name, metadata.description, labels))
            },
        );
    }
}
