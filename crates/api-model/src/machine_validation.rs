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
use std::fmt::{Debug, Display};
use std::str::FromStr;

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::machine::MachineValidationFilter;

#[derive(Debug, Clone, PartialEq, Eq, Default, strum_macros::EnumString)]
pub enum MachineValidationState {
    #[default]
    Started,
    InProgress,
    Success,
    Skipped,
    Failed,
}

impl Display for MachineValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// represent machine validation over all test status
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MachineValidationStatus {
    pub state: MachineValidationState,
    pub total: i32,
    pub completed: i32,
}

#[derive(Debug, Clone)]
pub struct MachineValidation {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub name: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub filter: Option<MachineValidationFilter>,
    pub context: Option<String>,
    pub status: Option<MachineValidationStatus>,
    pub duration_to_complete: i64,
    // Columns for these exist, but are unused in rust code
    // pub description: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for MachineValidation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let filter: Option<sqlx::types::Json<MachineValidationFilter>> = row.try_get("filter")?;
        let status = MachineValidationStatus {
            state: match MachineValidationState::from_str(row.try_get("state")?) {
                Ok(status) => status,
                Err(_) => MachineValidationState::Success,
            },
            total: row.try_get("total")?,
            completed: row.try_get("completed")?,
        };

        Ok(MachineValidation {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            name: row.try_get("name")?,
            start_time: row.try_get("start_time")?,
            end_time: row.try_get("end_time")?,
            context: row.try_get("context")?,
            filter: filter.map(|x| x.0),
            status: Some(status),
            duration_to_complete: row.try_get("duration_to_complete")?,
            // description: row.try_get("description")?, // unused
        })
    }
}

impl MachineValidation {
    pub fn from_state(
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
                    rpc::forge::machine_validation_status::MachineValidationCompleted::Success
                        .into(),
                )
            }
            MachineValidationState::Skipped => {
                rpc::forge::machine_validation_status::MachineValidationState::Completed(
                    rpc::forge::machine_validation_status::MachineValidationCompleted::Skipped
                        .into(),
                )
            }
            MachineValidationState::Failed => {
                rpc::forge::machine_validation_status::MachineValidationState::Completed(
                    rpc::forge::machine_validation_status::MachineValidationCompleted::Failed
                        .into(),
                )
            }
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
            validation_id: Some(value.id.into()),
            name: value.name,
            start_time,
            end_time,
            context: value.context,
            machine_id: Some(value.machine_id),
            status: Some(rpc::forge::MachineValidationStatus {
                machine_validation_state: MachineValidation::from_state(status.state).into(),
                total: status.total.try_into().unwrap_or(0),
                completed_tests: status.completed.try_into().unwrap_or(0),
            }),
            duration_to_complete: Some(rpc::Duration::from(std::time::Duration::from_secs(
                value.duration_to_complete.try_into().unwrap_or(0),
            ))),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct MachineValidationExternalConfig {
    pub name: String,
    pub description: String,
    pub config: Vec<u8>,
    pub version: ConfigVersion,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationExternalConfig {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineValidationExternalConfig {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            config: row.try_get("config")?,
            version: row.try_get("version")?,
        })
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

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct MachineValidationTest {
    pub test_id: String,
    pub name: String,
    pub description: Option<String>,
    pub contexts: Vec<String>,
    pub img_name: Option<String>,
    pub execute_in_host: Option<bool>,
    pub container_arg: Option<String>,
    pub command: String,
    pub args: String,
    pub extra_output_file: Option<String>,
    pub extra_err_file: Option<String>,
    pub external_config_file: Option<String>,
    pub pre_condition: Option<String>,
    pub timeout: Option<i64>,
    pub version: ConfigVersion,
    pub supported_platforms: Vec<String>,
    pub modified_by: String,
    pub verified: bool,
    pub read_only: bool,
    pub custom_tags: Option<Vec<String>>,
    pub components: Vec<String>,
    pub last_modified_at: DateTime<Utc>,
    pub is_enabled: bool,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationTest {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineValidationTest {
            test_id: row.try_get("test_id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            img_name: row.try_get("img_name")?,
            execute_in_host: row.try_get("execute_in_host")?,
            container_arg: row.try_get("container_arg")?,
            command: row.try_get("command")?,
            args: row.try_get("args")?,
            extra_output_file: row.try_get("extra_output_file")?,
            extra_err_file: row.try_get("extra_err_file")?,
            external_config_file: row.try_get("external_config_file")?,
            contexts: row.try_get("contexts")?,
            pre_condition: row.try_get("pre_condition")?,
            timeout: row.try_get("timeout")?,
            version: row.try_get("version")?,
            supported_platforms: row.try_get("supported_platforms")?,
            modified_by: row.try_get("modified_by")?,
            verified: row.try_get("verified")?,
            read_only: row.try_get("read_only")?,
            custom_tags: row.try_get("custom_tags")?,
            components: row.try_get("components")?,
            last_modified_at: row.try_get("last_modified_at")?,
            is_enabled: row.try_get("is_enabled")?,
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
            validation_id: Some(value.validation_id.into()),
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

#[derive(Debug, Clone)]
pub struct MachineValidationResult {
    pub validation_id: Uuid,
    pub name: String,
    pub description: String,
    pub stdout: String,
    pub stderr: String,
    pub command: String,
    pub args: String,
    pub context: String,
    pub exit_code: i32,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub test_id: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationResult {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineValidationResult {
            validation_id: row.try_get("machine_validation_id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            command: row.try_get("command")?,
            args: row.try_get("args")?,
            context: row.try_get("context")?,
            stdout: row.try_get("stdout")?,
            stderr: row.try_get("stderr")?,
            exit_code: row.try_get("exit_code")?,
            start_time: row.try_get("start_time")?,
            end_time: row.try_get("end_time")?,
            test_id: row.try_get("test_id")?,
        })
    }
}

impl TryFrom<rpc::forge::MachineValidationResult> for MachineValidationResult {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::MachineValidationResult) -> Result<Self, Self::Error> {
        let val_id = Uuid::try_from(value.validation_id.unwrap_or_default())
            .map_err(|_| RpcDataConversionError::MissingArgument("validation_id"))?;
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
