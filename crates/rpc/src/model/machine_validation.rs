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
use std::str::FromStr;

use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use model::machine_validation::{
    MachineValidation, MachineValidationExternalConfig, MachineValidationResult,
    MachineValidationState, MachineValidationTest, MachineValidationTestAddRequest,
    MachineValidationTestUpdatePayload, MachineValidationTestUpdateRequest,
    MachineValidationTestsGetRequest,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl From<rpc::forge::MachineValidationTestAddRequest> for MachineValidationTestAddRequest {
    fn from(req: rpc::forge::MachineValidationTestAddRequest) -> Self {
        MachineValidationTestAddRequest {
            name: req.name,
            description: req.description,
            contexts: req.contexts,
            img_name: req.img_name,
            execute_in_host: req.execute_in_host,
            container_arg: req.container_arg,
            command: req.command,
            args: req.args,
            extra_err_file: req.extra_err_file,
            external_config_file: req.external_config_file,
            pre_condition: req.pre_condition,
            timeout: req.timeout,
            extra_output_file: req.extra_output_file,
            supported_platforms: req.supported_platforms,
            read_only: req.read_only,
            custom_tags: req.custom_tags,
            components: req.components,
            is_enabled: req.is_enabled,
        }
    }
}

impl From<rpc::forge::machine_validation_test_update_request::Payload>
    for MachineValidationTestUpdatePayload
{
    fn from(p: rpc::forge::machine_validation_test_update_request::Payload) -> Self {
        MachineValidationTestUpdatePayload {
            name: p.name,
            description: p.description,
            contexts: p.contexts,
            img_name: p.img_name,
            execute_in_host: p.execute_in_host,
            container_arg: p.container_arg,
            command: p.command,
            args: p.args,
            extra_err_file: p.extra_err_file,
            external_config_file: p.external_config_file,
            pre_condition: p.pre_condition,
            timeout: p.timeout,
            extra_output_file: p.extra_output_file,
            supported_platforms: p.supported_platforms,
            verified: p.verified,
            custom_tags: p.custom_tags,
            components: p.components,
            is_enabled: p.is_enabled,
        }
    }
}

impl From<rpc::forge::MachineValidationTestUpdateRequest> for MachineValidationTestUpdateRequest {
    fn from(req: rpc::forge::MachineValidationTestUpdateRequest) -> Self {
        MachineValidationTestUpdateRequest {
            test_id: req.test_id,
            version: req.version,
            payload: req.payload.map(MachineValidationTestUpdatePayload::from),
        }
    }
}

impl From<rpc::forge::MachineValidationTestsGetRequest> for MachineValidationTestsGetRequest {
    fn from(req: rpc::forge::MachineValidationTestsGetRequest) -> Self {
        MachineValidationTestsGetRequest {
            supported_platforms: req.supported_platforms,
            contexts: req.contexts,
            test_id: req.test_id,
            read_only: req.read_only,
            custom_tags: req.custom_tags,
            version: req.version,
            is_enabled: req.is_enabled,
            verified: req.verified,
        }
    }
}

pub fn machine_validation_from_state(
    state: MachineValidationState,
) -> rpc::forge::machine_validation_status::MachineValidationState {
    match state {
        MachineValidationState::Started => {
            rpc::forge::machine_validation_status::MachineValidationState::Started(
                rpc::forge::machine_validation_status::MachineValidationStarted::Started.into(),
            )
        }
        MachineValidationState::InProgress => {
            rpc::forge::machine_validation_status::MachineValidationState::InProgress(
                rpc::forge::machine_validation_status::MachineValidationInProgress::InProgress
                    .into(),
            )
        }
        MachineValidationState::Success => {
            rpc::forge::machine_validation_status::MachineValidationState::Completed(
                rpc::forge::machine_validation_status::MachineValidationCompleted::Success.into(),
            )
        }
        MachineValidationState::Skipped => {
            rpc::forge::machine_validation_status::MachineValidationState::Completed(
                rpc::forge::machine_validation_status::MachineValidationCompleted::Skipped.into(),
            )
        }
        MachineValidationState::Failed => {
            rpc::forge::machine_validation_status::MachineValidationState::Completed(
                rpc::forge::machine_validation_status::MachineValidationCompleted::Failed.into(),
            )
        }
    }
}

impl From<MachineValidation> for rpc::forge::MachineValidationRun {
    fn from(value: MachineValidation) -> Self {
        let mut end_time = None;
        if value.end_time.is_some() {
            end_time = Some(value.end_time.unwrap_or_default().into());
        }
        let status = value.status.unwrap_or_default();
        let start_time = Some(value.start_time.unwrap_or_default().into());
        rpc::forge::MachineValidationRun {
            validation_id: Some(value.id),
            name: value.name,
            start_time,
            end_time,
            context: value.context,
            machine_id: Some(value.machine_id),
            status: Some(rpc::forge::MachineValidationStatus {
                machine_validation_state: machine_validation_from_state(status.state).into(),
                total: status.total.try_into().unwrap_or(0),
                completed_tests: status.completed.try_into().unwrap_or(0),
            }),
            duration_to_complete: Some(rpc::Duration::from(std::time::Duration::from_secs(
                value.duration_to_complete.try_into().unwrap_or(0),
            ))),
        }
    }
}

impl From<MachineValidationExternalConfig> for rpc::forge::MachineValidationExternalConfig {
    fn from(value: MachineValidationExternalConfig) -> Self {
        rpc::forge::MachineValidationExternalConfig {
            name: value.name,
            config: value.config,
            description: Some(value.description),
            version: value.version.version_nr().to_string(),
            timestamp: Some(value.version.timestamp().into()),
        }
    }
}

impl TryFrom<rpc::forge::MachineValidationExternalConfig> for MachineValidationExternalConfig {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::MachineValidationExternalConfig) -> Result<Self, Self::Error> {
        Ok(MachineValidationExternalConfig {
            name: value.name,
            description: value.description.unwrap_or_default(),
            config: value.config,
            version: ConfigVersion::from_str(&value.version)
                .map_err(|_| RpcDataConversionError::InvalidConfigVersion(value.version))?,
        })
    }
}

impl From<MachineValidationTest> for rpc::forge::MachineValidationTest {
    fn from(value: MachineValidationTest) -> Self {
        rpc::forge::MachineValidationTest {
            test_id: value.test_id,
            name: value.name,
            description: value.description,
            contexts: value.contexts,
            img_name: value.img_name,
            execute_in_host: value.execute_in_host,
            container_arg: value.container_arg,
            command: value.command,
            args: value.args,
            extra_output_file: value.extra_output_file,
            extra_err_file: value.extra_err_file,
            external_config_file: value.external_config_file,
            pre_condition: value.pre_condition,
            timeout: value.timeout,
            version: value.version.version_string(),
            supported_platforms: value.supported_platforms,
            modified_by: value.modified_by,
            verified: value.verified,
            read_only: value.read_only,
            custom_tags: value.custom_tags.unwrap_or_default(),
            components: value.components,
            last_modified_at: value.last_modified_at.to_string(),
            is_enabled: value.is_enabled,
        }
    }
}

impl TryFrom<rpc::forge::MachineValidationTest> for MachineValidationTest {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::MachineValidationTest) -> Result<Self, Self::Error> {
        Ok(MachineValidationTest {
            test_id: value.test_id,
            name: value.name,
            description: value.description,
            contexts: value.contexts,
            img_name: value.img_name,
            execute_in_host: value.execute_in_host,
            container_arg: value.container_arg,
            command: value.command,
            args: value.args,
            extra_output_file: value.extra_output_file,
            extra_err_file: value.extra_err_file,
            external_config_file: value.external_config_file,
            pre_condition: value.pre_condition,
            timeout: value.timeout,
            version: ConfigVersion::from_str(&value.version)
                .map_err(|_| RpcDataConversionError::InvalidConfigVersion(value.version))?,
            supported_platforms: value.supported_platforms,
            modified_by: value.modified_by,
            verified: value.verified,
            read_only: value.read_only,
            custom_tags: if value.custom_tags.is_empty() {
                None
            } else {
                Some(value.custom_tags)
            },
            components: value.components,
            last_modified_at: Utc::now(),
            is_enabled: value.is_enabled,
        })
    }
}

impl From<MachineValidationResult> for rpc::forge::MachineValidationResult {
    fn from(value: MachineValidationResult) -> Self {
        rpc::forge::MachineValidationResult {
            validation_id: Some(value.validation_id),
            command: value.command,
            args: value.args,
            std_out: value.stdout,
            std_err: value.stderr,
            name: value.name,
            description: value.description,
            context: value.context,
            exit_code: value.exit_code,
            start_time: Some(value.start_time.into()),
            end_time: Some(value.end_time.into()),
            test_id: value.test_id,
        }
    }
}

impl TryFrom<rpc::forge::MachineValidationResult> for MachineValidationResult {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::MachineValidationResult) -> Result<Self, Self::Error> {
        let val_id = value
            .validation_id
            .ok_or(RpcDataConversionError::MissingArgument("validation_id"))?;
        let start_time = match value.start_time {
            Some(time) => {
                DateTime::from_timestamp(time.seconds, time.nanos.try_into().unwrap()).unwrap()
            }
            None => Utc::now(),
        };
        let end_time = match value.end_time {
            Some(time) => {
                DateTime::from_timestamp(time.seconds, time.nanos.try_into().unwrap()).unwrap()
            }
            None => Utc::now(),
        };
        Ok(MachineValidationResult {
            validation_id: val_id,
            command: value.command,
            name: value.name,
            description: value.description,
            args: value.args,
            context: value.context,
            stdout: value.std_out,
            stderr: value.std_err,
            exit_code: value.exit_code,
            start_time,
            end_time,
            test_id: value.test_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    // ---- machine_validation_from_state: every domain state arm maps to the
    // matching proto oneof variant. The function is total, so check_values.
    #[test]
    fn validation_state_maps_each_arm() {
        use rpc::forge::machine_validation_status::{
            MachineValidationCompleted, MachineValidationInProgress, MachineValidationStarted,
            MachineValidationState as ProtoState,
        };
        check_values(
            [
                Check {
                    scenario: "started",
                    input: MachineValidationState::Started,
                    expect: ProtoState::Started(MachineValidationStarted::Started.into()),
                },
                Check {
                    scenario: "in progress",
                    input: MachineValidationState::InProgress,
                    expect: ProtoState::InProgress(MachineValidationInProgress::InProgress.into()),
                },
                Check {
                    scenario: "success -> completed/success",
                    input: MachineValidationState::Success,
                    expect: ProtoState::Completed(MachineValidationCompleted::Success.into()),
                },
                Check {
                    scenario: "skipped -> completed/skipped",
                    input: MachineValidationState::Skipped,
                    expect: ProtoState::Completed(MachineValidationCompleted::Skipped.into()),
                },
                Check {
                    scenario: "failed -> completed/failed",
                    input: MachineValidationState::Failed,
                    expect: ProtoState::Completed(MachineValidationCompleted::Failed.into()),
                },
            ],
            machine_validation_from_state,
        );
    }

    // ---- MachineValidationTestAddRequest::from: a direct field-for-field map.
    // Confirm each scalar/optional/repeated field is carried straight through.
    #[test]
    fn add_request_carries_every_field() {
        check_values(
            [
                Check {
                    scenario: "name carried",
                    input: rpc::forge::MachineValidationTestAddRequest {
                        name: "t".to_string(),
                        ..Default::default()
                    },
                    expect: "t".to_string(),
                },
                Check {
                    scenario: "empty name default",
                    input: rpc::forge::MachineValidationTestAddRequest::default(),
                    expect: String::new(),
                },
            ],
            |r| MachineValidationTestAddRequest::from(r).name,
        );
        check_values(
            [
                Check {
                    scenario: "is_enabled present true",
                    input: rpc::forge::MachineValidationTestAddRequest {
                        is_enabled: Some(true),
                        ..Default::default()
                    },
                    expect: Some(true),
                },
                Check {
                    scenario: "is_enabled present false",
                    input: rpc::forge::MachineValidationTestAddRequest {
                        is_enabled: Some(false),
                        ..Default::default()
                    },
                    expect: Some(false),
                },
                Check {
                    scenario: "is_enabled absent",
                    input: rpc::forge::MachineValidationTestAddRequest::default(),
                    expect: None,
                },
            ],
            |r| MachineValidationTestAddRequest::from(r).is_enabled,
        );
        check_values(
            [
                Check {
                    scenario: "repeated contexts + read_only + execute_in_host carried",
                    input: rpc::forge::MachineValidationTestAddRequest {
                        contexts: vec!["a".to_string(), "b".to_string()],
                        read_only: Some(true),
                        execute_in_host: Some(false),
                        supported_platforms: vec!["x86_64".to_string()],
                        ..Default::default()
                    },
                    expect: true,
                },
                Check {
                    scenario: "empty repeated + absent optionals",
                    input: rpc::forge::MachineValidationTestAddRequest::default(),
                    expect: true,
                },
            ],
            |r| {
                let want_contexts = r.contexts.clone();
                let want_platforms = r.supported_platforms.clone();
                let want_read_only = r.read_only;
                let want_execute = r.execute_in_host;
                let d = MachineValidationTestAddRequest::from(r);
                d.contexts == want_contexts
                    && d.supported_platforms == want_platforms
                    && d.read_only == want_read_only
                    && d.execute_in_host == want_execute
            },
        );
    }

    // ---- Payload -> MachineValidationTestUpdatePayload: same field-for-field map,
    // exercising the verified flag (present true/false/absent) and a scalar.
    #[test]
    fn update_payload_carries_verified_and_fields() {
        check_values(
            [
                Check {
                    scenario: "verified true",
                    input: rpc::forge::machine_validation_test_update_request::Payload {
                        verified: Some(true),
                        ..Default::default()
                    },
                    expect: Some(true),
                },
                Check {
                    scenario: "verified false",
                    input: rpc::forge::machine_validation_test_update_request::Payload {
                        verified: Some(false),
                        ..Default::default()
                    },
                    expect: Some(false),
                },
                Check {
                    scenario: "verified absent",
                    input: rpc::forge::machine_validation_test_update_request::Payload::default(),
                    expect: None,
                },
            ],
            |p| MachineValidationTestUpdatePayload::from(p).verified,
        );
        check_values(
            [
                Check {
                    scenario: "name present",
                    input: rpc::forge::machine_validation_test_update_request::Payload {
                        name: Some("n".to_string()),
                        ..Default::default()
                    },
                    expect: Some("n".to_string()),
                },
                Check {
                    scenario: "name absent",
                    input: rpc::forge::machine_validation_test_update_request::Payload::default(),
                    expect: None,
                },
            ],
            |p| MachineValidationTestUpdatePayload::from(p).name,
        );
    }

    // ---- MachineValidationTestUpdateRequest::from: payload present vs absent, and
    // the scalar test_id / version carried straight through.
    #[test]
    fn update_request_maps_payload_presence() {
        check_values(
            [
                Check {
                    scenario: "payload present",
                    input: rpc::forge::MachineValidationTestUpdateRequest {
                        test_id: "id".to_string(),
                        version: "1".to_string(),
                        payload: Some(
                            rpc::forge::machine_validation_test_update_request::Payload::default(),
                        ),
                    },
                    expect: true,
                },
                Check {
                    scenario: "payload absent",
                    input: rpc::forge::MachineValidationTestUpdateRequest {
                        test_id: "id".to_string(),
                        version: "1".to_string(),
                        payload: None,
                    },
                    expect: false,
                },
            ],
            |r| MachineValidationTestUpdateRequest::from(r).payload.is_some(),
        );
        check_values(
            [Check {
                scenario: "test_id + version carried",
                input: rpc::forge::MachineValidationTestUpdateRequest {
                    test_id: "forge_x".to_string(),
                    version: "7".to_string(),
                    payload: None,
                },
                expect: true,
            }],
            |r| {
                let d = MachineValidationTestUpdateRequest::from(r);
                d.test_id == "forge_x" && d.version == "7"
            },
        );
    }

    // ---- MachineValidationTestsGetRequest::from: optional filters present/absent.
    #[test]
    fn tests_get_request_maps_optionals() {
        check_values(
            [
                Check {
                    scenario: "all key optionals present",
                    input: rpc::forge::MachineValidationTestsGetRequest {
                        test_id: Some("t".to_string()),
                        read_only: Some(true),
                        version: Some("1".to_string()),
                        is_enabled: Some(false),
                        verified: Some(true),
                        contexts: vec!["c".to_string()],
                        custom_tags: vec!["k".to_string()],
                        supported_platforms: vec!["x86_64".to_string()],
                    },
                    expect: true,
                },
                Check {
                    scenario: "all optionals absent (default)",
                    input: rpc::forge::MachineValidationTestsGetRequest::default(),
                    expect: false,
                },
            ],
            |r| {
                let d = MachineValidationTestsGetRequest::from(r);
                d.test_id.is_some()
                    && d.read_only.is_some()
                    && d.version.is_some()
                    && d.is_enabled.is_some()
                    && d.verified.is_some()
            },
        );
        check_values(
            [
                Check {
                    scenario: "repeated contexts/custom_tags/platforms carried",
                    input: rpc::forge::MachineValidationTestsGetRequest {
                        contexts: vec!["c".to_string()],
                        custom_tags: vec!["k".to_string(), "j".to_string()],
                        supported_platforms: vec!["x86_64".to_string()],
                        ..Default::default()
                    },
                    expect: true,
                },
                Check {
                    scenario: "empty repeated default",
                    input: rpc::forge::MachineValidationTestsGetRequest::default(),
                    expect: true,
                },
            ],
            |r| {
                let want = (
                    r.contexts.clone(),
                    r.custom_tags.clone(),
                    r.supported_platforms.clone(),
                );
                let d = MachineValidationTestsGetRequest::from(r);
                (d.contexts, d.custom_tags, d.supported_platforms) == want
            },
        );
    }

    // ---- MachineValidationExternalConfig::try_from (proto -> domain): fallible on
    // the version string. RpcDataConversionError has no PartialEq, so use Fails.
    #[test]
    fn external_config_try_from_parses_version() {
        check_cases(
            [
                Case {
                    scenario: "valid V-T version parses",
                    input: rpc::forge::MachineValidationExternalConfig {
                        name: "cfg".to_string(),
                        description: Some("d".to_string()),
                        config: vec![1, 2, 3],
                        version: "V1-T0".to_string(),
                        timestamp: None,
                    },
                    expect: Yields(true),
                },
                Case {
                    scenario: "absent description defaults to empty",
                    input: rpc::forge::MachineValidationExternalConfig {
                        name: "cfg".to_string(),
                        description: None,
                        config: vec![],
                        version: "V2-T0".to_string(),
                        timestamp: None,
                    },
                    expect: Yields(true),
                },
                Case {
                    scenario: "bare number is not a valid version",
                    input: rpc::forge::MachineValidationExternalConfig {
                        name: "cfg".to_string(),
                        description: None,
                        config: vec![],
                        version: "1".to_string(),
                        timestamp: None,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty version string fails",
                    input: rpc::forge::MachineValidationExternalConfig {
                        name: "cfg".to_string(),
                        description: None,
                        config: vec![],
                        version: String::new(),
                        timestamp: None,
                    },
                    expect: Fails,
                },
            ],
            |proto| {
                let want_desc = proto.description.clone().unwrap_or_default();
                let want_name = proto.name.clone();
                let want_config = proto.config.clone();
                MachineValidationExternalConfig::try_from(proto)
                    .map(|d| {
                        d.description == want_desc
                            && d.name == want_name
                            && d.config == want_config
                    })
                    .map_err(drop)
            },
        );
    }

    // ---- MachineValidationExternalConfig::from (domain -> proto): total. version
    // becomes the bare number string; description is wrapped Some.
    #[test]
    fn external_config_to_proto_serializes_version_number() {
        check_values(
            [
                Check {
                    scenario: "version number rendered, description wrapped",
                    input: MachineValidationExternalConfig {
                        name: "cfg".to_string(),
                        description: "d".to_string(),
                        config: vec![9],
                        version: ConfigVersion::new(5),
                    },
                    expect: true,
                },
                Check {
                    scenario: "empty description still wrapped Some",
                    input: MachineValidationExternalConfig {
                        name: "cfg".to_string(),
                        description: String::new(),
                        config: vec![],
                        version: ConfigVersion::new(1),
                    },
                    expect: true,
                },
            ],
            |d| {
                let want_version = d.version.version_nr().to_string();
                let want_desc = d.description.clone();
                let p = rpc::forge::MachineValidationExternalConfig::from(d);
                p.version == want_version
                    && p.description == Some(want_desc)
                    && p.timestamp.is_some()
            },
        );
    }

    // ---- MachineValidationTest::try_from (proto -> domain): version parse Ok/Err,
    // and the empty-custom_tags -> None / non-empty -> Some mapping.
    #[test]
    fn test_try_from_parses_version_and_folds_custom_tags() {
        check_cases(
            [
                Case {
                    scenario: "valid version, empty custom_tags -> None",
                    input: rpc::forge::MachineValidationTest {
                        version: "V1-T0".to_string(),
                        custom_tags: vec![],
                        ..Default::default()
                    },
                    expect: Yields(true),
                },
                Case {
                    scenario: "valid version, populated custom_tags -> Some",
                    input: rpc::forge::MachineValidationTest {
                        version: "V3-T0".to_string(),
                        custom_tags: vec!["k".to_string()],
                        ..Default::default()
                    },
                    expect: Yields(false),
                },
                Case {
                    scenario: "invalid version fails",
                    input: rpc::forge::MachineValidationTest {
                        version: "nope".to_string(),
                        ..Default::default()
                    },
                    expect: Fails,
                },
            ],
            |proto| {
                MachineValidationTest::try_from(proto)
                    .map(|d| d.custom_tags.is_none())
                    .map_err(drop)
            },
        );
        // Scalar/optional fields carried straight through on the Ok path.
        check_cases(
            [Case {
                scenario: "fields carried through",
                input: rpc::forge::MachineValidationTest {
                    test_id: "id".to_string(),
                    name: "n".to_string(),
                    command: "cmd".to_string(),
                    args: "a".to_string(),
                    timeout: Some(30),
                    verified: true,
                    read_only: true,
                    is_enabled: true,
                    contexts: vec!["c".to_string()],
                    version: "V1-T0".to_string(),
                    ..Default::default()
                },
                expect: Yields(true),
            }],
            |proto| {
                MachineValidationTest::try_from(proto)
                    .map(|d| {
                        d.test_id == "id"
                            && d.name == "n"
                            && d.command == "cmd"
                            && d.timeout == Some(30)
                            && d.verified
                            && d.read_only
                            && d.is_enabled
                            && d.contexts == vec!["c".to_string()]
                    })
                    .map_err(drop)
            },
        );
    }

    // ---- MachineValidationTest::from (domain -> proto): total. version becomes the
    // V-T string; absent custom_tags become an empty vec.
    #[test]
    fn test_to_proto_renders_version_and_unwraps_custom_tags() {
        check_values(
            [
                Check {
                    scenario: "None custom_tags -> empty vec, version string rendered",
                    input: sample_test(None),
                    expect: true,
                },
                Check {
                    scenario: "Some custom_tags carried",
                    input: sample_test(Some(vec!["k".to_string()])),
                    expect: true,
                },
            ],
            |d| {
                let want_version = d.version.version_string();
                let want_tags = d.custom_tags.clone().unwrap_or_default();
                let p = rpc::forge::MachineValidationTest::from(d);
                p.version == want_version && p.custom_tags == want_tags
            },
        );
    }

    fn sample_test(custom_tags: Option<Vec<String>>) -> MachineValidationTest {
        MachineValidationTest {
            test_id: "id".to_string(),
            name: "n".to_string(),
            description: None,
            contexts: vec![],
            img_name: None,
            execute_in_host: None,
            container_arg: None,
            command: "cmd".to_string(),
            args: "a".to_string(),
            extra_output_file: None,
            extra_err_file: None,
            external_config_file: None,
            pre_condition: None,
            timeout: None,
            version: ConfigVersion::new(2),
            supported_platforms: vec![],
            modified_by: "me".to_string(),
            verified: false,
            read_only: false,
            custom_tags,
            components: vec![],
            last_modified_at: Utc::now(),
            is_enabled: true,
        }
    }

    #[test]
    fn tests_get_request_from_rpc() {
        let rpc_req = rpc::forge::MachineValidationTestsGetRequest {
            test_id: Some("forge_mytest".to_string()),
            is_enabled: Some(true),
            verified: Some(false),
            ..Default::default()
        };
        let req = MachineValidationTestsGetRequest::from(rpc_req);
        assert_eq!(req.test_id, Some("forge_mytest".to_string()));
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.verified, Some(false));
        assert!(req.version.is_none());
    }

    #[test]
    fn test_add_request_from_rpc() {
        let rpc_req = rpc::forge::MachineValidationTestAddRequest {
            name: "my_test".to_string(),
            command: "/bin/test".to_string(),
            args: "--verbose".to_string(),
            supported_platforms: vec!["x86_64".to_string()],
            ..Default::default()
        };
        let req = MachineValidationTestAddRequest::from(rpc_req);
        assert_eq!(req.name, "my_test");
        assert_eq!(req.command, "/bin/test");
        assert_eq!(req.supported_platforms, vec!["x86_64"]);
    }

    #[test]
    fn test_update_request_from_rpc_with_payload() {
        let rpc_req = rpc::forge::MachineValidationTestUpdateRequest {
            test_id: "forge_mytest".to_string(),
            version: "1".to_string(),
            payload: Some(
                rpc::forge::machine_validation_test_update_request::Payload {
                    verified: Some(true),
                    is_enabled: Some(false),
                    ..Default::default()
                },
            ),
        };
        let req = MachineValidationTestUpdateRequest::from(rpc_req);
        assert_eq!(req.test_id, "forge_mytest");
        assert_eq!(req.version, "1");
        let payload = req.payload.unwrap();
        assert_eq!(payload.verified, Some(true));
        assert_eq!(payload.is_enabled, Some(false));
        assert!(payload.name.is_none());
    }
}
