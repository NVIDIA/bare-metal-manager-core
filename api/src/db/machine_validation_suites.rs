/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{ops::DerefMut, str::FromStr};

use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::{CarbideError, CarbideResult};
use serde::{Deserialize, Serialize};

use super::DatabaseError;

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
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineValidationTest) -> CarbideResult<Self> {
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
            version: ConfigVersion::from_str(&value.version)?,
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

impl MachineValidationTest {
    /// Method to generate an SQL update query based on the fields that are `Some`
    fn build_update_query(
        req: rpc::forge::machine_validation_test_update_request::Payload,
        table: &str,
        version: String,
        test_id: &str,
        modified_by: &str,
    ) -> CarbideResult<String> {
        let json_value = match serde_json::to_value(req.clone()) {
            Ok(json_value) => json_value,
            Err(e) => return Err(CarbideError::InvalidArgument(e.to_string())),
        };
        let json_object = match json_value {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(CarbideError::InvalidArgument(
                    "Invalid argument".to_string(),
                ))
            }
        };
        let mut updates = vec![];

        for (key, value) in json_object {
            if !value.is_null() {
                match value {
                    serde_json::Value::String(s) => updates.push(format!("{} = '{}'", key, s)),
                    serde_json::Value::Number(n) => updates.push(format!("{} = {}", key, n)),
                    serde_json::Value::Bool(b) => updates.push(format!("{} = {}", key, b)),
                    serde_json::Value::Array(v) => {
                        let mut vector = match serde_json::to_string(&v) {
                            Ok(msg) => msg,
                            Err(_) => "[]".to_string(),
                        };
                        if vector != "[]" {
                            vector = vector.replace("\"", "\'");
                            updates.push(format!("{} = ARRAY{}", key, vector));
                        }
                    }
                    _ => {}
                }
            }
        }
        if updates.is_empty() {
            return Err(CarbideError::InvalidArgument(
                "Nothing to update".to_string(),
            ));
        }
        // If the verified is not set then any
        // update would require re-verify the test
        if req.verified.is_none() {
            updates.push(format!("verified = '{}'", false));
        }
        // updates.push(format!("version = '{}'", version));
        updates.push(format!("modified_by = '{}'", modified_by));
        let mut query: String = format!("UPDATE {} SET ", table);
        query.push_str(&updates.join(", "));
        query.push_str(&format!(
            " WHERE test_id = '{}' AND version = '{}' RETURNING test_id",
            test_id, version
        ));

        Ok(query)
    }

    fn build_insert_query(
        req: rpc::forge::MachineValidationTestAddRequest,
        table: &str,
        version: String,
        test_id: &str,
        modified_by: &str,
    ) -> CarbideResult<String> {
        let json_value = match serde_json::to_value(req) {
            Ok(json_value) => json_value,
            Err(e) => return Err(CarbideError::InvalidArgument(e.to_string())),
        };
        let json_object = match json_value {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(CarbideError::InvalidArgument(
                    "Invalid argument".to_string(),
                ))
            }
        };

        let mut columns = vec![];
        let mut values = vec![];

        for (key, value) in json_object {
            if !value.is_null() {
                columns.push(key.clone());
                match value {
                    serde_json::Value::String(s) => values.push(format!("'{}'", s)), // wrap strings in quotes
                    serde_json::Value::Number(n) => values.push(format!("{}", n)),
                    serde_json::Value::Bool(b) => values.push(format!("{}", b)),
                    serde_json::Value::Array(v) => {
                        let mut vector = match serde_json::to_string(&v) {
                            Ok(msg) => msg,
                            Err(_) => "[]".to_string(),
                        };
                        if vector == "[]" {
                            // Remove the key
                            columns.pop();
                        } else {
                            vector = vector.replace("\"", "\'");
                            values.push(format!("ARRAY{}", vector));
                        }
                    }
                    _ => {}
                }
            }
        }
        if columns.is_empty() || values.is_empty() {
            return Err(CarbideError::InvalidArgument(
                "Nothing to insert".to_string(),
            ));
        }
        columns.push("version".to_string());
        values.push(format!("'{}'", version));

        columns.push("test_id".to_string());
        values.push(format!("'{}'", test_id));

        columns.push("modified_by".to_string());
        values.push(format!("'{}'", modified_by));

        // Build the final query
        let query = format!(
            "INSERT INTO {} ({}) VALUES ({}) RETURNING test_id",
            table,
            columns.join(", "),
            values.join(", ")
        );

        Ok(query)
    }
    fn build_select_query(
        req: rpc::forge::MachineValidationTestsGetRequest,
        table: &str,
        // version: ConfigVersion,
    ) -> CarbideResult<String> {
        let json_value = match serde_json::to_value(req) {
            Ok(json_value) => json_value,
            Err(e) => return Err(CarbideError::InvalidArgument(e.to_string())),
        };
        let json_object = match json_value {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(CarbideError::InvalidArgument(
                    "Invalid argument".to_string(),
                ))
            }
        };
        let mut wheres = vec![];
        wheres.push(format!("{}={}", "1", "1"));
        for (key, value) in json_object {
            if !value.is_null() {
                match value {
                    serde_json::Value::String(s) => wheres.push(format!("{}='{}'", key, s)),
                    serde_json::Value::Number(n) => wheres.push(format!("{}={}", key, n)),
                    serde_json::Value::Bool(b) => wheres.push(format!("{}={}", key, b)),
                    serde_json::Value::Array(v) => {
                        let mut vector = match serde_json::to_string(&v) {
                            Ok(msg) => msg,
                            Err(_) => "[]".to_string(),
                        };
                        if vector == "[]" {
                            continue;
                        } else {
                            vector = vector.replace("\"", "\'");
                            wheres.push(format!("{}&&ARRAY{}", key, vector));
                        }
                    }
                    _ => {}
                }
            }
        }
        // Build the final query
        let query = format!(
            "SELECT * FROM {} WHERE {} ORDER BY version DESC, name ASC",
            table,
            wheres.join(" AND ")
        );

        Ok(query)
    }

    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        req: rpc::forge::MachineValidationTestsGetRequest,
    ) -> CarbideResult<Vec<Self>> {
        let query = Self::build_select_query(req, "machine_validation_tests")?;
        let ret = sqlx::query_as(&query)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), &query, e)))?;
        Ok(ret)
    }
    pub fn generate_test_id(name: &str) -> String {
        format!("forge_{}", name)
    }
    pub async fn save(
        txn: &mut Transaction<'_, Postgres>,
        req: rpc::forge::MachineValidationTestAddRequest,
        version: ConfigVersion,
    ) -> CarbideResult<String> {
        let test_id = Self::generate_test_id(&req.name);

        let query = Self::build_insert_query(
            req,
            "machine_validation_tests",
            version.version_string(),
            &test_id,
            "User",
        )?;
        sqlx::query_as(&query)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), &query, e)))?;
        Ok(test_id)
    }

    pub async fn update(
        txn: &mut Transaction<'_, Postgres>,
        req: rpc::forge::MachineValidationTestUpdateRequest,
    ) -> CarbideResult<String> {
        let Some(payload) = req.payload else {
            return Err(CarbideError::InvalidArgument(
                "Payload is missing".to_owned(),
            ));
        };
        let query = Self::build_update_query(
            payload,
            "machine_validation_tests",
            req.version,
            &req.test_id,
            "User",
        )?;

        sqlx::query_as(&query)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), &query, e)))?;
        Ok(req.test_id)
    }

    pub async fn clone(
        txn: &mut Transaction<'_, Postgres>,
        test: &MachineValidationTest,
    ) -> CarbideResult<(String, ConfigVersion)> {
        let add_req = rpc::forge::MachineValidationTestAddRequest {
            name: test.name.clone(),
            description: test.description.clone(),
            contexts: test.contexts.clone(),
            img_name: test.img_name.clone(),
            execute_in_host: test.execute_in_host,
            container_arg: test.container_arg.clone(),
            command: test.command.clone(),
            args: test.args.clone(),
            extra_err_file: test.extra_err_file.clone(),
            external_config_file: test.external_config_file.clone(),
            pre_condition: test.pre_condition.clone(),
            timeout: test.timeout,
            extra_output_file: test.extra_output_file.clone(),
            supported_platforms: test.supported_platforms.clone(),
            read_only: None,
            custom_tags: test.custom_tags.clone().unwrap_or_default(),
            components: test.components.clone(),
            is_enabled: Some(test.is_enabled),
        };
        let next_version = test.version.increment();
        let test_id = Self::save(txn, add_req, next_version).await?;
        Ok((test_id, next_version))
    }

    pub async fn mark_verified(
        txn: &mut Transaction<'_, Postgres>,
        test_id: String,
        version: ConfigVersion,
    ) -> CarbideResult<String> {
        let req = rpc::forge::MachineValidationTestUpdateRequest {
            test_id,
            version: version.version_string(),
            payload: Some(
                rpc::forge::machine_validation_test_update_request::Payload {
                    verified: Some(true),
                    ..Default::default()
                },
            ),
        };
        Self::update(txn, req).await
    }

    pub async fn enabled_diable(
        txn: &mut Transaction<'_, Postgres>,
        test_id: String,
        version: ConfigVersion,
        is_enabled: bool,
    ) -> CarbideResult<String> {
        let req = rpc::forge::MachineValidationTestUpdateRequest {
            test_id,
            version: version.version_string(),
            payload: Some(
                rpc::forge::machine_validation_test_update_request::Payload {
                    is_enabled: Some(is_enabled),
                    ..Default::default()
                },
            ),
        };
        Self::update(txn, req).await
    }
}
#[cfg(test)]
mod test {}
