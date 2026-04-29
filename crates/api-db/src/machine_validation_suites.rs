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
use model::machine_validation::{
    MachineValidationTest, MachineValidationTestAddRequest, MachineValidationTestUpdatePayload,
    MachineValidationTestUpdateRequest, MachineValidationTestsGetRequest,
};
use regex::Regex;
use sqlx::Execute;
use sqlx::PgConnection;
use sqlx::Postgres;
use sqlx::QueryBuilder;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

const MVT_TABLE: &str = "machine_validation_tests";

/// INSERT semantics match the previous serde_json-driven builder: skip `Option::None`, skip empty
/// `Vec`s for array columns, always set `version`, `test_id`, `modified_by`.
///
/// `name`, `command`, and `args` are always emitted as columns and bound values: in
/// `forge.proto` they are plain `string` fields on `MachineValidationTestAddRequest` (not
/// `optional`), the Rust model uses `String`, and the `machine_validation_tests` table defines
/// them `NOT NULL`.
fn push_insert<'a>(
    req: &'a MachineValidationTestAddRequest,
    version: &'a str,
    test_id: &'a str,
    modified_by: &'a str,
) -> QueryBuilder<'a, Postgres> {
    let mut qb = QueryBuilder::new("INSERT INTO ");
    qb.push(MVT_TABLE);
    qb.push(" (");
    let mut cols = qb.separated(", ");
    cols.push("name");
    if req.description.is_some() {
        cols.push("description");
    }
    if !req.contexts.is_empty() {
        cols.push("contexts");
    }
    if req.img_name.is_some() {
        cols.push("img_name");
    }
    if req.execute_in_host.is_some() {
        cols.push("execute_in_host");
    }
    if req.container_arg.is_some() {
        cols.push("container_arg");
    }
    cols.push("command");
    cols.push("args");
    if req.extra_err_file.is_some() {
        cols.push("extra_err_file");
    }
    if req.external_config_file.is_some() {
        cols.push("external_config_file");
    }
    if req.pre_condition.is_some() {
        cols.push("pre_condition");
    }
    if req.timeout.is_some() {
        cols.push("timeout");
    }
    if req.extra_output_file.is_some() {
        cols.push("extra_output_file");
    }
    if !req.supported_platforms.is_empty() {
        cols.push("supported_platforms");
    }
    if req.read_only.is_some() {
        cols.push("read_only");
    }
    if !req.custom_tags.is_empty() {
        cols.push("custom_tags");
    }
    if !req.components.is_empty() {
        cols.push("components");
    }
    if req.is_enabled.is_some() {
        cols.push("is_enabled");
    }
    cols.push("version");
    cols.push("test_id");
    cols.push("modified_by");

    qb.push(") VALUES (");
    let mut vals = qb.separated(", ");
    vals.push_bind(&req.name);
    if let Some(ref d) = req.description {
        vals.push_bind(d);
    }
    if !req.contexts.is_empty() {
        vals.push_bind(&req.contexts);
    }
    if let Some(ref v) = req.img_name {
        vals.push_bind(v);
    }
    if let Some(v) = req.execute_in_host {
        vals.push_bind(v);
    }
    if let Some(ref v) = req.container_arg {
        vals.push_bind(v);
    }
    vals.push_bind(&req.command);
    vals.push_bind(&req.args);
    if let Some(ref v) = req.extra_err_file {
        vals.push_bind(v);
    }
    if let Some(ref v) = req.external_config_file {
        vals.push_bind(v);
    }
    if let Some(ref v) = req.pre_condition {
        vals.push_bind(v);
    }
    if let Some(v) = req.timeout {
        vals.push_bind(v);
    }
    if let Some(ref v) = req.extra_output_file {
        vals.push_bind(v);
    }
    if !req.supported_platforms.is_empty() {
        vals.push_bind(&req.supported_platforms);
    }
    if let Some(v) = req.read_only {
        vals.push_bind(v);
    }
    if !req.custom_tags.is_empty() {
        vals.push_bind(&req.custom_tags);
    }
    if !req.components.is_empty() {
        vals.push_bind(&req.components);
    }
    if let Some(v) = req.is_enabled {
        vals.push_bind(v);
    }
    vals.push_bind(version);
    vals.push_bind(test_id);
    vals.push_bind(modified_by);
    qb.push(") RETURNING test_id");
    qb
}

/// UPDATE: at least one non-verified field or explicit `verified` must be present, or
/// `InvalidArgument("Nothing to update")`. If `verified` is omitted, it is set to `false` after
/// other columns are applied (same as the legacy JSON builder).
fn push_update<'a>(
    payload: &'a MachineValidationTestUpdatePayload,
    version: &'a str,
    test_id: &'a str,
    modified_by: &'a str,
) -> DatabaseResult<QueryBuilder<'a, Postgres>> {
    let mut qb = QueryBuilder::new("UPDATE ");
    qb.push(MVT_TABLE);
    qb.push(" SET ");
    let mut sets = qb.separated(", ");

    let mut n = 0usize;
    if let Some(ref v) = payload.name {
        sets.push("name = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.description {
        sets.push("description = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if !payload.contexts.is_empty() {
        sets.push("contexts = ");
        sets.push_bind_unseparated(&payload.contexts);
        n += 1;
    }
    if let Some(ref v) = payload.img_name {
        sets.push("img_name = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(v) = payload.execute_in_host {
        sets.push("execute_in_host = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.container_arg {
        sets.push("container_arg = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.command {
        sets.push("command = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.args {
        sets.push("args = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.extra_err_file {
        sets.push("extra_err_file = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.external_config_file {
        sets.push("external_config_file = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.pre_condition {
        sets.push("pre_condition = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(v) = payload.timeout {
        sets.push("timeout = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if let Some(ref v) = payload.extra_output_file {
        sets.push("extra_output_file = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if !payload.supported_platforms.is_empty() {
        sets.push("supported_platforms = ");
        sets.push_bind_unseparated(&payload.supported_platforms);
        n += 1;
    }
    if let Some(v) = payload.verified {
        sets.push("verified = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }
    if !payload.custom_tags.is_empty() {
        sets.push("custom_tags = ");
        sets.push_bind_unseparated(&payload.custom_tags);
        n += 1;
    }
    if !payload.components.is_empty() {
        sets.push("components = ");
        sets.push_bind_unseparated(&payload.components);
        n += 1;
    }
    if let Some(v) = payload.is_enabled {
        sets.push("is_enabled = ");
        sets.push_bind_unseparated(v);
        n += 1;
    }

    if n == 0 {
        return Err(DatabaseError::InvalidArgument(
            "Nothing to update".to_string(),
        ));
    }

    if payload.verified.is_none() {
        sets.push("verified = ");
        sets.push_bind_unseparated(false);
    }

    sets.push("modified_by = ");
    sets.push_bind_unseparated(modified_by);
    qb.push(" WHERE test_id = ")
        .push_bind(test_id)
        .push(" AND version = ")
        .push_bind(version)
        .push(" RETURNING test_id");
    Ok(qb)
}

/// Applies `MachineValidationTestsGetRequest` fields as `AND ...` filters with bound parameters.
///
/// **Maintenance:** When adding a filterable field to `MachineValidationTestsGetRequest` in
/// `forge.proto`, extend this function (and add tests) so the new field is wired through. The
/// legacy JSON-based `build_select_query` iterated serialized keys automatically; this path is
/// explicit and will not pick up new proto fields by itself.
fn push_select_filters<'a>(
    qb: &mut QueryBuilder<'a, Postgres>,
    req: &'a MachineValidationTestsGetRequest,
) {
    if let Some(ref tid) = req.test_id {
        qb.push(" AND LOWER(test_id) = LOWER(");
        qb.push_bind(tid);
        qb.push(")");
    }
    if let Some(ref v) = req.version {
        qb.push(" AND version = ");
        qb.push_bind(v);
    }
    if let Some(b) = req.is_enabled {
        qb.push(" AND is_enabled = ");
        qb.push_bind(b);
    }
    if let Some(b) = req.verified {
        qb.push(" AND verified = ");
        qb.push_bind(b);
    }
    if let Some(b) = req.read_only {
        qb.push(" AND read_only = ");
        qb.push_bind(b);
    }
    if !req.supported_platforms.is_empty() {
        qb.push(" AND supported_platforms && ");
        qb.push_bind(&req.supported_platforms);
    }
    if !req.contexts.is_empty() {
        qb.push(" AND contexts && ");
        qb.push_bind(&req.contexts);
    }
    if !req.custom_tags.is_empty() {
        qb.push(" AND custom_tags && ");
        qb.push_bind(&req.custom_tags);
    }
}

pub async fn find(
    txn: impl DbReader<'_>,
    req: MachineValidationTestsGetRequest,
) -> DatabaseResult<Vec<MachineValidationTest>> {
    let mut qb = QueryBuilder::new("SELECT * FROM ");
    qb.push(MVT_TABLE);
    qb.push(" WHERE 1=1");
    push_select_filters(&mut qb, &req);
    qb.push(" ORDER BY version DESC, name ASC");
    let q = qb.build_query_as::<MachineValidationTest>();
    let sql = q.sql();
    q.fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

pub fn generate_test_id(name: &str) -> String {
    format!("forge_{}", name.to_ascii_lowercase())
}

pub async fn save(
    txn: &mut PgConnection,
    mut req: MachineValidationTestAddRequest,
    version: ConfigVersion,
) -> DatabaseResult<String> {
    let test_id = generate_test_id(&req.name);

    let re = Regex::new(r"[ =;:@#\!?\-]").unwrap();
    req.supported_platforms = req
        .supported_platforms
        .iter()
        .map(|p| re.replace_all(p, "_").to_string().to_ascii_lowercase())
        .collect();

    let version_s = version.version_string();
    let mut qb = push_insert(&req, version_s.as_str(), &test_id, "User");
    let q = qb.build_query_scalar::<String>();
    let sql = q.sql();
    let returned = q
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    debug_assert_eq!(returned, test_id);
    Ok(test_id)
}

pub async fn update(
    txn: &mut PgConnection,
    req: MachineValidationTestUpdateRequest,
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

    let mut qb = push_update(&payload, &req.version, &req.test_id, "User")?;
    let q = qb.build_query_scalar::<String>();
    let sql = q.sql();
    q.fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(req.test_id)
}

pub async fn clone(
    txn: &mut PgConnection,
    test: &MachineValidationTest,
) -> DatabaseResult<(String, ConfigVersion)> {
    let add_req = MachineValidationTestAddRequest {
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
    let req = MachineValidationTestUpdateRequest {
        test_id,
        version: version.version_string(),
        payload: Some(MachineValidationTestUpdatePayload {
            verified: Some(true),
            ..Default::default()
        }),
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
    let req = MachineValidationTestUpdateRequest {
        test_id,
        version: version.version_string(),
        payload: Some(MachineValidationTestUpdatePayload {
            is_enabled: Some(is_enabled),
            verified: Some(is_verified),
            ..Default::default()
        }),
    };
    update(txn, req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_id_lowercases_name() {
        assert_eq!(generate_test_id("MyTest"), "forge_mytest");
        assert_eq!(generate_test_id("ALLCAPS"), "forge_allcaps");
        assert_eq!(generate_test_id("already_lower"), "forge_already_lower");
        assert_eq!(generate_test_id("MiXeD_CaSe_123"), "forge_mixed_case_123");
    }

    #[test]
    fn select_query_uses_lower_for_test_id_and_placeholders() {
        let req = MachineValidationTestsGetRequest {
            test_id: Some("Forge_MyTest".to_string()),
            ..Default::default()
        };
        let mut qb = QueryBuilder::new("SELECT * FROM ");
        qb.push(MVT_TABLE);
        qb.push(" WHERE 1=1");
        push_select_filters(&mut qb, &req);
        qb.push(" ORDER BY version DESC, name ASC");
        let sql = qb.build().sql();
        assert!(
            sql.contains("LOWER(test_id)"),
            "Expected LOWER(test_id), got: {sql}"
        );
        assert!(
            sql.contains("LOWER(") && sql.contains(')'),
            "Expected bound LOWER comparison, got: {sql}"
        );
    }

    #[test]
    fn select_query_boolean_uses_placeholder() {
        let req = MachineValidationTestsGetRequest {
            is_enabled: Some(true),
            ..Default::default()
        };
        let mut qb = QueryBuilder::new("SELECT * FROM ");
        qb.push(MVT_TABLE);
        qb.push(" WHERE 1=1");
        push_select_filters(&mut qb, &req);
        let sql = qb.build().sql();
        assert!(
            sql.contains("is_enabled = $"),
            "Expected parameterized is_enabled, got: {sql}"
        );
    }

    #[test]
    fn select_query_empty_request_is_select_all() {
        let req = MachineValidationTestsGetRequest::default();
        let mut qb = QueryBuilder::new("SELECT * FROM ");
        qb.push(MVT_TABLE);
        qb.push(" WHERE 1=1");
        push_select_filters(&mut qb, &req);
        let sql = qb.build().sql();
        assert!(
            sql.contains("WHERE 1=1"),
            "Empty request should have no extra filters, got: {sql}"
        );
        assert!(
            !sql.contains("LOWER(test_id)"),
            "Empty request should not filter test_id, got: {sql}"
        );
    }
}
