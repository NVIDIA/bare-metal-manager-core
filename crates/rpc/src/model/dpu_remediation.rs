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

use model::dpu_remediation::{
    AppliedRemediation, ApproveRemediation, DisableRemediation, EnableRemediation, NewRemediation,
    Remediation, RemediationApplicationStatus, RevokeRemediation,
};
use model::metadata::Metadata;

use crate as rpc;
use crate::errors::RpcDataConversionError;
use crate::forge::{
    ApproveRemediationRequest, CreateRemediationRequest, DisableRemediationRequest,
    EnableRemediationRequest, RevokeRemediationRequest,
};
use crate::model::RpcTryFrom;

impl TryFrom<rpc::forge::RemediationApplicationStatus> for RemediationApplicationStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: rpc::forge::RemediationApplicationStatus) -> Result<Self, Self::Error> {
        let metadata = status.metadata.map(Metadata::try_from).transpose()?;
        Ok(RemediationApplicationStatus {
            succeeded: status.succeeded,
            metadata,
        })
    }
}

// about 16KB file size, long enough for any reasonable script but small enough to make it
// almost impossible to stuff a binary in the DB, which is the point of the limit.
const MAXIMUM_SCRIPT_LENGTH: usize = 2 << 13;

impl RpcTryFrom<(CreateRemediationRequest, String)> for NewRemediation {
    type Error = RpcDataConversionError;

    fn rpc_try_from(value: (CreateRemediationRequest, String)) -> Result<Self, Self::Error> {
        let rpc_request = value.0;
        let author = value.1.into();

        let metadata = if let Some(metadata) = rpc_request.metadata {
            Some(Metadata::try_from(metadata)?)
        } else {
            None
        };
        let retries = if rpc_request.retries < 0 {
            return Err(RpcDataConversionError::InvalidArgument(String::from(
                "retries must be a positive integer or 0",
            )));
        } else {
            rpc_request.retries
        };

        let script = rpc_request.script.to_string();
        if script.len() > MAXIMUM_SCRIPT_LENGTH {
            return Err(RpcDataConversionError::InvalidArgument(format!(
                "script must not exceed length: {MAXIMUM_SCRIPT_LENGTH}"
            )));
        } else if script.is_empty() {
            return Err(RpcDataConversionError::InvalidArgument(
                "script cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            script,
            metadata,
            retries,
            author,
        })
    }
}

impl From<Remediation> for rpc::forge::Remediation {
    fn from(value: Remediation) -> Self {
        Self {
            id: value.id.into(),
            metadata: value.metadata.map(|m| m.into()),
            creation_time: Some(value.creation_time.into()),
            script_author: value.author.to_string(),
            script_reviewed_by: value.reviewer.map(|r| r.to_string()),
            script: value.script,
            enabled: value.enabled,
            retries: value.retries,
        }
    }
}

impl From<Remediation> for rpc::forge::CreateRemediationResponse {
    fn from(value: Remediation) -> Self {
        rpc::forge::CreateRemediationResponse {
            remediation_id: value.id.into(),
        }
    }
}

impl From<AppliedRemediation> for rpc::forge::AppliedRemediation {
    fn from(value: AppliedRemediation) -> Self {
        let metadata = Metadata {
            labels: value.status,
            description: String::new(),
            name: String::new(),
        };
        Self {
            dpu_machine_id: Some(value.dpu_machine_id),
            remediation_id: Some(value.id),
            attempt: value.attempt,
            metadata: Some(metadata.into()),
            succeeded: value.succeeded,
            applied_time: Some(value.applied_time.into()),
        }
    }
}

impl RpcTryFrom<(ApproveRemediationRequest, String)> for ApproveRemediation {
    type Error = RpcDataConversionError;

    fn rpc_try_from(value: (ApproveRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value
            .0
            .remediation_id
            .ok_or(RpcDataConversionError::MissingArgument(
                "Request must contain a remediation id.",
            ))?;
        let reviewer = value.1.into();

        Ok(Self { id, reviewer })
    }
}

impl RpcTryFrom<(RevokeRemediationRequest, String)> for RevokeRemediation {
    type Error = RpcDataConversionError;

    fn rpc_try_from(value: (RevokeRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value
            .0
            .remediation_id
            .ok_or(RpcDataConversionError::MissingArgument(
                "Request must contain a remediation id.",
            ))?;
        let revoked_by = value.1;
        tracing::info!("Remediation: '{}' revoked by: '{}'", id, revoked_by);

        Ok(Self { id })
    }
}

impl RpcTryFrom<(EnableRemediationRequest, String)> for EnableRemediation {
    type Error = RpcDataConversionError;

    fn rpc_try_from(value: (EnableRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value
            .0
            .remediation_id
            .ok_or(RpcDataConversionError::MissingArgument(
                "Request must contain a remediation id.",
            ))?;
        let enabled_by = value.1;
        tracing::info!("Remediation: '{}' enabled by: '{}'", id, enabled_by);

        Ok(Self { id })
    }
}

impl RpcTryFrom<(DisableRemediationRequest, String)> for DisableRemediation {
    type Error = RpcDataConversionError;

    fn rpc_try_from(value: (DisableRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value
            .0
            .remediation_id
            .ok_or(RpcDataConversionError::MissingArgument(
                "Request must contain a remediation id.",
            ))?;
        let disabled_by = value.1;
        tracing::info!("Remediation: '{}' disabled by: '{}'", id, disabled_by);

        Ok(Self { id })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use carbide_uuid::dpu_remediations::RemediationId;
    use carbide_uuid::machine::MachineId;
    use std::str::FromStr;
    use chrono::{TimeZone, Utc};

    use super::*;

    fn label(key: &str, value: Option<&str>) -> rpc::forge::Label {
        rpc::forge::Label {
            key: key.to_string(),
            value: value.map(str::to_string),
        }
    }

    fn metadata(name: &str, description: &str, labels: Vec<rpc::forge::Label>) -> rpc::Metadata {
        rpc::Metadata {
            name: name.to_string(),
            description: description.to_string(),
            labels,
        }
    }

    // `rpc::forge::RemediationApplicationStatus -> RemediationApplicationStatus` is
    // fallible only through its inner `Metadata` conversion. Project the Ok result
    // to (succeeded, name, sorted labels); a duplicate label key is the one error
    // arm and the conversion error is not `PartialEq`, so it uses `Fails`.
    #[test]
    fn remediation_application_status_try_from_rpc() {
        type Projected = (bool, Option<(String, Vec<(String, String)>)>);

        check_cases(
            [
                Case {
                    scenario: "succeeded, no metadata",
                    input: rpc::forge::RemediationApplicationStatus {
                        succeeded: true,
                        metadata: None,
                    },
                    expect: Yields((true, None)),
                },
                Case {
                    scenario: "failed, no metadata",
                    input: rpc::forge::RemediationApplicationStatus {
                        succeeded: false,
                        metadata: None,
                    },
                    expect: Yields((false, None)),
                },
                Case {
                    scenario: "failed, metadata with one label",
                    input: rpc::forge::RemediationApplicationStatus {
                        succeeded: false,
                        metadata: Some(metadata(
                            "test",
                            "desc",
                            vec![label("status", Some("failed"))],
                        )),
                    },
                    expect: Yields((
                        false,
                        Some((
                            "test".to_string(),
                            vec![("status".to_string(), "failed".to_string())],
                        )),
                    )),
                },
                Case {
                    scenario: "succeeded, metadata with no labels",
                    input: rpc::forge::RemediationApplicationStatus {
                        succeeded: true,
                        metadata: Some(metadata("n", "d", vec![])),
                    },
                    expect: Yields((true, Some(("n".to_string(), vec![])))),
                },
                Case {
                    scenario: "absent label value defaults to empty string",
                    input: rpc::forge::RemediationApplicationStatus {
                        succeeded: true,
                        metadata: Some(metadata("n", "d", vec![label("k", None)])),
                    },
                    expect: Yields((
                        true,
                        Some(("n".to_string(), vec![("k".to_string(), String::new())])),
                    )),
                },
                Case {
                    scenario: "duplicate label key fails",
                    input: rpc::forge::RemediationApplicationStatus {
                        succeeded: true,
                        metadata: Some(metadata(
                            "n",
                            "d",
                            vec![label("k", Some("a")), label("k", Some("b"))],
                        )),
                    },
                    expect: Fails,
                },
            ],
            |status| -> Result<Projected, ()> {
                let domain = RemediationApplicationStatus::try_from(status).map_err(drop)?;
                let metadata = domain.metadata.map(|m| {
                    let mut labels: Vec<(String, String)> = m.labels.into_iter().collect();
                    labels.sort();
                    (m.name, labels)
                });
                Ok((domain.succeeded, metadata))
            },
        );
    }

    // `(CreateRemediationRequest, author) -> NewRemediation` is fallible: a negative
    // retry count, an empty script, and an oversized script are the three explicit
    // error arms; an inner duplicate-label `Metadata` conversion is a fourth. Project
    // the Ok result to (script, retries, author, has-metadata) — the fields the
    // conversion sets.
    #[test]
    fn new_remediation_rpc_try_from() {
        type Projected = (String, i32, String, bool);

        let oversized = "x".repeat(MAXIMUM_SCRIPT_LENGTH + 1);

        check_cases(
            [
                Case {
                    scenario: "minimal script, no metadata, zero retries",
                    input: (
                        CreateRemediationRequest {
                            script: "echo hi".to_string(),
                            metadata: None,
                            retries: 0,
                        },
                        "alice".to_string(),
                    ),
                    expect: Yields(("echo hi".to_string(), 0, "alice".to_string(), false)),
                },
                Case {
                    scenario: "positive retries pass through",
                    input: (
                        CreateRemediationRequest {
                            script: "echo hi".to_string(),
                            metadata: None,
                            retries: 5,
                        },
                        "bob".to_string(),
                    ),
                    expect: Yields(("echo hi".to_string(), 5, "bob".to_string(), false)),
                },
                Case {
                    scenario: "metadata present is carried",
                    input: (
                        CreateRemediationRequest {
                            script: "echo hi".to_string(),
                            metadata: Some(metadata("n", "d", vec![label("k", Some("v"))])),
                            retries: 1,
                        },
                        "carol".to_string(),
                    ),
                    expect: Yields(("echo hi".to_string(), 1, "carol".to_string(), true)),
                },
                Case {
                    scenario: "script at maximum length is accepted",
                    input: (
                        CreateRemediationRequest {
                            script: "y".repeat(MAXIMUM_SCRIPT_LENGTH),
                            metadata: None,
                            retries: 0,
                        },
                        "dave".to_string(),
                    ),
                    expect: Yields((
                        "y".repeat(MAXIMUM_SCRIPT_LENGTH),
                        0,
                        "dave".to_string(),
                        false,
                    )),
                },
                Case {
                    scenario: "negative retries fail",
                    input: (
                        CreateRemediationRequest {
                            script: "echo hi".to_string(),
                            metadata: None,
                            retries: -1,
                        },
                        "alice".to_string(),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "empty script fails",
                    input: (
                        CreateRemediationRequest {
                            script: String::new(),
                            metadata: None,
                            retries: 0,
                        },
                        "alice".to_string(),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "oversized script fails",
                    input: (
                        CreateRemediationRequest {
                            script: oversized,
                            metadata: None,
                            retries: 0,
                        },
                        "alice".to_string(),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "duplicate metadata label fails",
                    input: (
                        CreateRemediationRequest {
                            script: "echo hi".to_string(),
                            metadata: Some(metadata(
                                "n",
                                "d",
                                vec![label("k", Some("a")), label("k", Some("b"))],
                            )),
                            retries: 0,
                        },
                        "alice".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |(request, author)| -> Result<Projected, ()> {
                let new = NewRemediation::rpc_try_from((request, author)).map_err(drop)?;
                Ok((
                    new.script,
                    new.retries,
                    new.author.to_string(),
                    new.metadata.is_some(),
                ))
            },
        );
    }

    // `Remediation -> rpc::forge::Remediation` is a total conversion. Project the
    // result to its scalar fields plus (reviewer, has-metadata) so each row pins the
    // present/absent optional arms and the bool/int pass-throughs.
    #[test]
    fn remediation_into_rpc() {
        type Projected = (String, String, Option<String>, bool, i32, bool);

        fn remediation(
            reviewer: Option<&str>,
            metadata: Option<Metadata>,
            enabled: bool,
            retries: i32,
        ) -> Remediation {
            Remediation {
                id: RemediationId::default(),
                script: "echo".to_string(),
                metadata,
                reviewer: reviewer.map(|r| r.to_string().into()),
                author: "alice".to_string().into(),
                retries,
                enabled,
                creation_time: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            }
        }

        check_values(
            [
                Check {
                    scenario: "no reviewer, no metadata, disabled",
                    input: remediation(None, None, false, 0),
                    expect: (
                        "echo".to_string(),
                        "alice".to_string(),
                        None,
                        false,
                        0,
                        false,
                    ),
                },
                Check {
                    scenario: "reviewer present, enabled, retries",
                    input: remediation(Some("bob"), None, true, 3),
                    expect: (
                        "echo".to_string(),
                        "alice".to_string(),
                        Some("bob".to_string()),
                        true,
                        3,
                        false,
                    ),
                },
                Check {
                    scenario: "metadata present",
                    input: remediation(None, Some(Metadata::default()), false, 0),
                    expect: (
                        "echo".to_string(),
                        "alice".to_string(),
                        None,
                        false,
                        0,
                        true,
                    ),
                },
            ],
            |remediation| -> Projected {
                let proto = rpc::forge::Remediation::from(remediation);
                (
                    proto.script,
                    proto.script_author,
                    proto.script_reviewed_by,
                    proto.enabled,
                    proto.retries,
                    proto.metadata.is_some(),
                )
            },
        );
    }

    // `Remediation -> rpc::forge::CreateRemediationResponse` projects to just the id.
    #[test]
    fn remediation_into_create_response() {
        let id = RemediationId::default();

        Check {
            scenario: "id passes through",
            input: Remediation {
                id,
                script: "echo".to_string(),
                metadata: None,
                reviewer: None,
                author: "alice".to_string().into(),
                retries: 0,
                enabled: false,
                creation_time: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            },
            expect: id.into(),
        }
        .check(|remediation| rpc::forge::CreateRemediationResponse::from(remediation).remediation_id);
    }

    // `AppliedRemediation -> rpc::forge::AppliedRemediation` is total. Project to
    // (dpu_machine_id, remediation_id, attempt, succeeded, sorted status labels) —
    // the `status` map travels through `metadata.labels`.
    #[test]
    fn applied_remediation_into_rpc() {
        type Projected = (
            Option<MachineId>,
            Option<RemediationId>,
            i32,
            bool,
            Vec<(String, String)>,
        );

        let machine =
            MachineId::from_str("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g")
                .unwrap();
        let remediation = RemediationId::default();

        fn applied(
            machine: MachineId,
            remediation: RemediationId,
            attempt: i32,
            succeeded: bool,
            status: HashMap<String, String>,
        ) -> AppliedRemediation {
            AppliedRemediation {
                id: remediation,
                dpu_machine_id: machine,
                attempt,
                succeeded,
                status,
                applied_time: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            }
        }

        check_values(
            [
                Check {
                    scenario: "succeeded, empty status",
                    input: applied(machine, remediation, 1, true, HashMap::new()),
                    expect: (Some(machine), Some(remediation), 1, true, vec![]),
                },
                Check {
                    scenario: "failed, status labels carried",
                    input: applied(
                        machine,
                        remediation,
                        2,
                        false,
                        HashMap::from([("err".to_string(), "boom".to_string())]),
                    ),
                    expect: (
                        Some(machine),
                        Some(remediation),
                        2,
                        false,
                        vec![("err".to_string(), "boom".to_string())],
                    ),
                },
            ],
            |applied| -> Projected {
                let proto = rpc::forge::AppliedRemediation::from(applied);
                let mut labels: Vec<(String, String)> = proto
                    .metadata
                    .map(|m| {
                        m.labels
                            .into_iter()
                            .map(|l| (l.key, l.value.unwrap_or_default()))
                            .collect()
                    })
                    .unwrap_or_default();
                labels.sort();
                (
                    proto.dpu_machine_id,
                    proto.remediation_id,
                    proto.attempt,
                    proto.succeeded,
                    labels,
                )
            },
        );
    }

    // `(ApproveRemediationRequest, reviewer) -> ApproveRemediation` is fallible: a
    // missing remediation id is the one error arm. The error type is not `PartialEq`,
    // so it uses `Fails`. Project the Ok result to (id, reviewer).
    #[test]
    fn approve_remediation_rpc_try_from() {
        let id = RemediationId::default();

        check_cases(
            [
                Case {
                    scenario: "id present",
                    input: (
                        ApproveRemediationRequest {
                            remediation_id: Some(id),
                        },
                        "bob".to_string(),
                    ),
                    expect: Yields((id, "bob".to_string())),
                },
                Case {
                    scenario: "missing id fails",
                    input: (
                        ApproveRemediationRequest {
                            remediation_id: None,
                        },
                        "bob".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |(request, reviewer)| -> Result<(RemediationId, String), ()> {
                let approve = ApproveRemediation::rpc_try_from((request, reviewer)).map_err(drop)?;
                Ok((approve.id, approve.reviewer.to_string()))
            },
        );
    }

    // `(RevokeRemediationRequest, actor) -> RevokeRemediation` is fallible: a missing
    // id is the one error arm; the actor is logged, not stored. Project to the id.
    #[test]
    fn revoke_remediation_rpc_try_from() {
        let id = RemediationId::default();

        check_cases(
            [
                Case {
                    scenario: "id present",
                    input: (
                        RevokeRemediationRequest {
                            remediation_id: Some(id),
                        },
                        "bob".to_string(),
                    ),
                    expect: Yields(id),
                },
                Case {
                    scenario: "missing id fails",
                    input: (
                        RevokeRemediationRequest {
                            remediation_id: None,
                        },
                        "bob".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |(request, actor)| -> Result<RemediationId, ()> {
                Ok(RevokeRemediation::rpc_try_from((request, actor))
                    .map_err(drop)?
                    .id)
            },
        );
    }

    // `(EnableRemediationRequest, actor) -> EnableRemediation` is fallible on a
    // missing id; the actor is logged, not stored. Project to the id.
    #[test]
    fn enable_remediation_rpc_try_from() {
        let id = RemediationId::default();

        check_cases(
            [
                Case {
                    scenario: "id present",
                    input: (
                        EnableRemediationRequest {
                            remediation_id: Some(id),
                        },
                        "bob".to_string(),
                    ),
                    expect: Yields(id),
                },
                Case {
                    scenario: "missing id fails",
                    input: (
                        EnableRemediationRequest {
                            remediation_id: None,
                        },
                        "bob".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |(request, actor)| -> Result<RemediationId, ()> {
                Ok(EnableRemediation::rpc_try_from((request, actor))
                    .map_err(drop)?
                    .id)
            },
        );
    }

    // `(DisableRemediationRequest, actor) -> DisableRemediation` is fallible on a
    // missing id; the actor is logged, not stored. Project to the id.
    #[test]
    fn disable_remediation_rpc_try_from() {
        let id = RemediationId::default();

        check_cases(
            [
                Case {
                    scenario: "id present",
                    input: (
                        DisableRemediationRequest {
                            remediation_id: Some(id),
                        },
                        "bob".to_string(),
                    ),
                    expect: Yields(id),
                },
                Case {
                    scenario: "missing id fails",
                    input: (
                        DisableRemediationRequest {
                            remediation_id: None,
                        },
                        "bob".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |(request, actor)| -> Result<RemediationId, ()> {
                Ok(DisableRemediation::rpc_try_from((request, actor))
                    .map_err(drop)?
                    .id)
            },
        );
    }
}
