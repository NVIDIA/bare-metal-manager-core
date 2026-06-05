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
use carbide_uuid::machine_validation::MachineValidationId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::machine::MachineValidationFilter;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MachineValidationTestAddRequest {
    pub name: String,
    pub description: Option<String>,
    pub contexts: Vec<String>,
    pub img_name: Option<String>,
    pub execute_in_host: Option<bool>,
    pub container_arg: Option<String>,
    pub command: String,
    pub args: String,
    pub extra_err_file: Option<String>,
    pub external_config_file: Option<String>,
    pub pre_condition: Option<String>,
    pub timeout: Option<i64>,
    pub extra_output_file: Option<String>,
    pub supported_platforms: Vec<String>,
    pub read_only: Option<bool>,
    pub custom_tags: Vec<String>,
    pub components: Vec<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MachineValidationTestUpdatePayload {
    pub name: Option<String>,
    pub description: Option<String>,
    pub contexts: Vec<String>,
    pub img_name: Option<String>,
    pub execute_in_host: Option<bool>,
    pub container_arg: Option<String>,
    pub command: Option<String>,
    pub args: Option<String>,
    pub extra_err_file: Option<String>,
    pub external_config_file: Option<String>,
    pub pre_condition: Option<String>,
    pub timeout: Option<i64>,
    pub extra_output_file: Option<String>,
    pub supported_platforms: Vec<String>,
    pub verified: Option<bool>,
    pub custom_tags: Vec<String>,
    pub components: Vec<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct MachineValidationTestUpdateRequest {
    pub test_id: String,
    pub version: String,
    pub payload: Option<MachineValidationTestUpdatePayload>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MachineValidationTestsGetRequest {
    pub supported_platforms: Vec<String>,
    pub contexts: Vec<String>,
    pub test_id: Option<String>,
    pub read_only: Option<bool>,
    pub custom_tags: Vec<String>,
    pub version: Option<String>,
    pub is_enabled: Option<bool>,
    pub verified: Option<bool>,
}

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
    pub id: MachineValidationId,
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

#[derive(Debug, Clone)]
pub struct MachineValidationResult {
    pub validation_id: MachineValidationId,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_get_request_default_serializes_to_all_null_optionals() {
        let req = MachineValidationTestsGetRequest::default();
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        // Optional fields should be null, vec fields should be empty arrays
        assert!(obj["test_id"].is_null());
        assert!(obj["is_enabled"].is_null());
        assert_eq!(obj["supported_platforms"], serde_json::json!([]));
    }
}
