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

use config_version::ConfigVersion;
use model::machine_validation::MachineValidationTest;
use regex::Regex;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

/// Method to generate an SQL update query based on the fields that are `Some`
fn build_update_query(
    req: rpc::forge::machine_validation_test_update_request::Payload,
    table: &str,
    version: String,
    test_id: &str,
    modified_by: &str,
) -> DatabaseResult<String> {
    let json_value = match serde_json::to_value(req.clone()) {
        Ok(json_value) => json_value,
        Err(e) => return Err(DatabaseError::InvalidArgument(e.to_string())),
    };
    let json_object = match json_value {
        serde_json::Value::Object(map) => map,
        _ => {
            return Err(DatabaseError::InvalidArgument(
                "Invalid argument".to_string(),
            ));
        }
    };
    let mut updates = vec![];

    for (key, value) in json_object {
        if !value.is_null() {
            match value {
                serde_json::Value::String(s) => updates.push(format!("{key} = '{s}'")),
                serde_json::Value::Number(n) => updates.push(format!("{key} = {n}")),
                serde_json::Value::Bool(b) => updates.push(format!("{key} = {b}")),
                serde_json::Value::Array(v) => {
                    let mut vector = match serde_json::to_string(&v) {
                        Ok(msg) => msg,
                        Err(_) => "[]".to_string(),
                    };
                    if vector != "[]" {
                        vector = vector.replace("\"", "\'");
                        updates.push(format!("{key} = ARRAY{vector}"));
                    }
                }
                _ => {}
            }
        }
    }
    if updates.is_empty() {
        return Err(DatabaseError::InvalidArgument(
            "Nothing to update".to_string(),
        ));
    }
    // If the verified is not set then any
    // update would require re-verify the test
    if req.verified.is_none() {
        updates.push(format!("verified = '{}'", false));
    }
    // updates.push(format!("version = '{}'", version));
    updates.push(format!("modified_by = '{modified_by}'"));
    let mut query: String = format!("UPDATE {table} SET ");
    query.push_str(&updates.join(", "));
    query.push_str(&format!(
        " WHERE test_id = '{test_id}' AND version = '{version}' RETURNING test_id"
    ));

    Ok(query)
}

fn build_insert_query(
    req: rpc::forge::MachineValidationTestAddRequest,
    table: &str,
    version: String,
    test_id: &str,
    modified_by: &str,
) -> DatabaseResult<String> {
    let json_value = match serde_json::to_value(req) {
        Ok(json_value) => json_value,
        Err(e) => return Err(DatabaseError::InvalidArgument(e.to_string())),
    };
    let json_object = match json_value {
        serde_json::Value::Object(map) => map,
        _ => {
            return Err(DatabaseError::InvalidArgument(
                "Invalid argument".to_string(),
            ));
        }
    };

    let mut columns = vec![];
    let mut values = vec![];

    for (key, value) in json_object {
        if !value.is_null() {
            columns.push(key.clone());
            match value {
                serde_json::Value::String(s) => values.push(format!("'{s}'")), // wrap strings in quotes
                serde_json::Value::Number(n) => values.push(format!("{n}")),
                serde_json::Value::Bool(b) => values.push(format!("{b}")),
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
                        values.push(format!("ARRAY{vector}"));
                    }
                }
                _ => {}
            }
        }
    }
    if columns.is_empty() || values.is_empty() {
        return Err(DatabaseError::InvalidArgument(
            "Nothing to insert".to_string(),
        ));
    }
    columns.push("version".to_string());
    values.push(format!("'{version}'"));

    columns.push("test_id".to_string());
    values.push(format!("'{test_id}'"));

    columns.push("modified_by".to_string());
    values.push(format!("'{modified_by}'"));

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
) -> DatabaseResult<String> {
    let json_value = match serde_json::to_value(req) {
        Ok(json_value) => json_value,
        Err(e) => return Err(DatabaseError::InvalidArgument(e.to_string())),
    };
    let json_object = match json_value {
        serde_json::Value::Object(map) => map,
        _ => {
            return Err(DatabaseError::InvalidArgument(
                "Invalid argument".to_string(),
            ));
        }
    };
    let mut wheres = vec![];
    wheres.push(format!("{}={}", "1", "1"));
    for (key, value) in json_object {
        if !value.is_null() {
            match value {
                serde_json::Value::String(s) => wheres.push(format!("{key}='{s}'")),
                serde_json::Value::Number(n) => wheres.push(format!("{key}={n}")),
                serde_json::Value::Bool(b) => wheres.push(format!("{key}={b}")),
                serde_json::Value::Array(v) => {
                    let mut vector = match serde_json::to_string(&v) {
                        Ok(msg) => msg,
                        Err(_) => "[]".to_string(),
                    };
                    if vector == "[]" {
                        continue;
                    } else {
                        vector = vector.replace("\"", "\'");
                        wheres.push(format!("{key}&&ARRAY{vector}"));
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
    txn: &mut PgConnection,
    req: rpc::forge::MachineValidationTestsGetRequest,
) -> DatabaseResult<Vec<MachineValidationTest>> {
    let query = build_select_query(req, "machine_validation_tests")?;
    let ret = sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;
    Ok(ret)
}

pub fn generate_test_id(name: &str) -> String {
    format!("forge_{name}")
}

pub async fn save(
    txn: &mut PgConnection,
    mut req: rpc::forge::MachineValidationTestAddRequest,
    version: ConfigVersion,
) -> DatabaseResult<String> {
    let test_id = generate_test_id(&req.name);

    let re = Regex::new(r"[ =;:@#\!?\-]").unwrap();
    req.supported_platforms = req
        .supported_platforms
        .iter()
        .map(|p| re.replace_all(p, "_").to_string().to_ascii_lowercase())
        .collect();

    let query = build_insert_query(
        req,
        "machine_validation_tests",
        version.version_string(),
        &test_id,
        "User",
    )?;
    let _: () = sqlx::query_as(&query)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;
    Ok(test_id)
}

pub async fn update(
    txn: &mut PgConnection,
    req: rpc::forge::MachineValidationTestUpdateRequest,
) -> DatabaseResult<String> {
    let Some(mut payload) = req.payload else {
        return Err(DatabaseError::InvalidArgument(
            "Payload is missing".to_owned(),
        ));
    };
    let re = Regex::new(r"[ =;:@#\!?\-]").unwrap();
    payload.supported_platforms = payload
        .supported_platforms
        .iter()
        .map(|p| re.replace_all(p, "_").to_string().to_ascii_lowercase())
        .collect();
    let query = build_update_query(
        payload,
        "machine_validation_tests",
        req.version,
        &req.test_id,
        "User",
    )?;

    let _: () = sqlx::query_as(&query)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;
    Ok(req.test_id)
}

pub async fn clone(
    txn: &mut PgConnection,
    test: &MachineValidationTest,
) -> DatabaseResult<(String, ConfigVersion)> {
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
    let test_id = save(txn, add_req, next_version).await?;
    Ok((test_id, next_version))
}

pub async fn mark_verified(
    txn: &mut PgConnection,
    test_id: String,
    version: ConfigVersion,
) -> DatabaseResult<String> {
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
    update(txn, req).await
}

pub async fn enable_disable(
    txn: &mut PgConnection,
    test_id: String,
    version: ConfigVersion,
    is_enabled: bool,
    is_verified: bool,
) -> DatabaseResult<String> {
    let req = rpc::forge::MachineValidationTestUpdateRequest {
        test_id,
        version: version.version_string(),
        payload: Some(
            rpc::forge::machine_validation_test_update_request::Payload {
                is_enabled: Some(is_enabled),
                verified: Some(is_verified),
                ..Default::default()
            },
        ),
    };
    update(txn, req).await
}
