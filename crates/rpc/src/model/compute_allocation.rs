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

use model::compute_allocation::ComputeAllocation;

use crate::errors::RpcDataConversionError;
use crate::forge as rpc;

impl TryFrom<ComputeAllocation> for rpc::ComputeAllocation {
    type Error = RpcDataConversionError;

    fn try_from(compute_alloc: ComputeAllocation) -> Result<Self, Self::Error> {
        let attributes = rpc::ComputeAllocationAttributes {
            instance_type_id: compute_alloc.instance_type_id.to_string(),
            count: compute_alloc.count,
        };

        Ok(rpc::ComputeAllocation {
            id: Some(compute_alloc.id),
            tenant_organization_id: compute_alloc.tenant_organization_id.to_string(),
            version: compute_alloc.version.to_string(),
            attributes: Some(attributes),
            created_at: Some(compute_alloc.created.to_string()),
            created_by: compute_alloc.created_by,
            updated_by: compute_alloc.updated_by,
            metadata: Some(rpc::Metadata {
                name: compute_alloc.metadata.name,
                description: compute_alloc.metadata.description,
                labels: compute_alloc
                    .metadata
                    .labels
                    .iter()
                    .map(|(key, value)| rpc::Label {
                        key: key.to_owned(),
                        value: if value.is_empty() {
                            None
                        } else {
                            Some(value.to_owned())
                        },
                    })
                    .collect(),
            }),
        })
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use config_version::ConfigVersion;
    use model::metadata::Metadata;

    use super::*;
    use crate::forge as rpc;

    // A fixed, deterministic version so the domain and proto builders agree
    // byte-for-byte; the real `initial()` constructor stamps the current time.
    fn fixed_version() -> ConfigVersion {
        use std::str::FromStr;
        ConfigVersion::from_str("V1-T1700000000000000").unwrap()
    }

    /// Build a domain `ComputeAllocation` whose every conversion-relevant field is
    /// overridable, so a table row can vary one variant at a time. Anything not
    /// passed gets a fixed, well-formed default.
    fn domain_alloc(
        count: u32,
        name: &str,
        description: &str,
        labels: HashMap<String, String>,
        created_by: Option<&str>,
        updated_by: Option<&str>,
    ) -> ComputeAllocation {
        ComputeAllocation {
            id: "dbe71f32-1bdc-11f1-8101-3b10d91c938c".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: fixed_version(),
            metadata: Metadata {
                name: name.to_string(),
                description: description.to_string(),
                labels,
            },
            tenant_organization_id: "theorg".parse().unwrap(),
            instance_type_id: "12345".parse().unwrap(),
            count,
            created_by: created_by.map(str::to_string),
            updated_by: updated_by.map(str::to_string),
        }
    }

    /// The matching proto value for [`domain_alloc`]'s fixed defaults; callers
    /// override the fields their row exercises.
    fn rpc_alloc(
        count: u32,
        name: &str,
        description: &str,
        labels: Vec<rpc::Label>,
        created_by: Option<&str>,
        updated_by: Option<&str>,
    ) -> rpc::ComputeAllocation {
        rpc::ComputeAllocation {
            id: Some("dbe71f32-1bdc-11f1-8101-3b10d91c938c".parse().unwrap()),
            version: fixed_version().to_string(),
            metadata: Some(rpc::Metadata {
                name: name.to_string(),
                description: description.to_string(),
                labels,
            }),
            tenant_organization_id: "theorg".to_string(),
            attributes: Some(rpc::ComputeAllocationAttributes {
                instance_type_id: "12345".to_string(),
                count,
            }),
            created_at: Some("2023-01-01 00:00:00 UTC".to_string()),
            created_by: created_by.map(str::to_string),
            updated_by: updated_by.map(str::to_string),
        }
    }

    /// Whole-message round trips for every scalar / optional-field variant. Labels
    /// here are at most a single entry, so the proto `Vec<Label>` ordering is
    /// deterministic and the full message can be compared directly.
    #[test]
    fn converts_each_field_variant() {
        check_cases(
            [
                Case {
                    scenario: "both audit fields present, no labels",
                    input: domain_alloc(10, "fancy name", "", HashMap::new(), Some("u1"), Some("u2")),
                    expect: Yields(rpc_alloc(10, "fancy name", "", vec![], Some("u1"), Some("u2"))),
                },
                Case {
                    scenario: "created_by present, updated_by absent",
                    input: domain_alloc(10, "n", "", HashMap::new(), Some("u1"), None),
                    expect: Yields(rpc_alloc(10, "n", "", vec![], Some("u1"), None)),
                },
                Case {
                    scenario: "created_by absent, updated_by present",
                    input: domain_alloc(10, "n", "", HashMap::new(), None, Some("u2")),
                    expect: Yields(rpc_alloc(10, "n", "", vec![], None, Some("u2"))),
                },
                Case {
                    scenario: "both audit fields absent",
                    input: domain_alloc(10, "n", "", HashMap::new(), None, None),
                    expect: Yields(rpc_alloc(10, "n", "", vec![], None, None)),
                },
                Case {
                    scenario: "zero count",
                    input: domain_alloc(0, "n", "", HashMap::new(), None, None),
                    expect: Yields(rpc_alloc(0, "n", "", vec![], None, None)),
                },
                Case {
                    scenario: "large count",
                    input: domain_alloc(100_000, "n", "", HashMap::new(), None, None),
                    expect: Yields(rpc_alloc(100_000, "n", "", vec![], None, None)),
                },
                Case {
                    scenario: "non-empty description carried through",
                    input: domain_alloc(1, "n", "a useful note", HashMap::new(), None, None),
                    expect: Yields(rpc_alloc(1, "n", "a useful note", vec![], None, None)),
                },
                Case {
                    scenario: "empty name carried through",
                    input: domain_alloc(1, "", "", HashMap::new(), None, None),
                    expect: Yields(rpc_alloc(1, "", "", vec![], None, None)),
                },
                Case {
                    scenario: "single label with non-empty value keeps the value",
                    input: domain_alloc(
                        1,
                        "n",
                        "",
                        HashMap::from([("k".to_string(), "v".to_string())]),
                        None,
                        None,
                    ),
                    expect: Yields(rpc_alloc(
                        1,
                        "n",
                        "",
                        vec![rpc::Label {
                            key: "k".to_string(),
                            value: Some("v".to_string()),
                        }],
                        None,
                        None,
                    )),
                },
                Case {
                    scenario: "single label with empty value maps to None",
                    input: domain_alloc(
                        1,
                        "n",
                        "",
                        HashMap::from([("k".to_string(), "".to_string())]),
                        None,
                        None,
                    ),
                    expect: Yields(rpc_alloc(
                        1,
                        "n",
                        "",
                        vec![rpc::Label {
                            key: "k".to_string(),
                            value: None,
                        }],
                        None,
                        None,
                    )),
                },
            ],
            |alloc| rpc::ComputeAllocation::try_from(alloc).map_err(drop),
        );
    }

    /// Label-set shapes whose proto `Vec<Label>` ordering is not deterministic
    /// (more than one entry): convert, then assert on order-independent
    /// projections of the resulting label list.
    #[test]
    fn maps_multi_label_sets() {
        let convert = |labels: HashMap<String, String>| -> Vec<rpc::Label> {
            let mut out = rpc::ComputeAllocation::try_from(domain_alloc(
                1,
                "n",
                "",
                labels,
                None,
                None,
            ))
            .unwrap()
            .metadata
            .unwrap()
            .labels;
            out.sort_by(|a, b| a.key.cmp(&b.key));
            out
        };

        check_values(
            [
                Check {
                    scenario: "empty label map yields no labels",
                    input: HashMap::new(),
                    expect: vec![],
                },
                Check {
                    scenario: "two labels, both values preserved (sorted by key)",
                    input: HashMap::from([
                        ("a".to_string(), "1".to_string()),
                        ("b".to_string(), "2".to_string()),
                    ]),
                    expect: vec![
                        rpc::Label {
                            key: "a".to_string(),
                            value: Some("1".to_string()),
                        },
                        rpc::Label {
                            key: "b".to_string(),
                            value: Some("2".to_string()),
                        },
                    ],
                },
                Check {
                    scenario: "mixed empty and non-empty values across labels",
                    input: HashMap::from([
                        ("a".to_string(), "".to_string()),
                        ("b".to_string(), "2".to_string()),
                    ]),
                    expect: vec![
                        rpc::Label {
                            key: "a".to_string(),
                            value: None,
                        },
                        rpc::Label {
                            key: "b".to_string(),
                            value: Some("2".to_string()),
                        },
                    ],
                },
            ],
            convert,
        );
    }
}
