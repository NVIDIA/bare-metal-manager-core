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

use carbide_uuid::rack::RackId;
use model::rack::{MaintenanceScope, RackMaintenanceRequest, RackMaintenanceRequestStatus};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseResult};

pub async fn find_by_id(
    conn: &mut PgConnection,
    request_id: Uuid,
) -> DatabaseResult<Option<RackMaintenanceRequest>> {
    let query = "SELECT * FROM rack_maintenance_requests WHERE id = $1";
    sqlx::query_as(query)
        .bind(request_id)
        .fetch_optional(conn)
        .await
        .map_err(|error| DatabaseError::new(query, error))
}

pub async fn find_active_for_rack_for_update(
    conn: &mut PgConnection,
    rack_id: &RackId,
) -> DatabaseResult<Option<RackMaintenanceRequest>> {
    let query = "SELECT * FROM rack_maintenance_requests \
                 WHERE rack_id = $1 AND status IN ('preparing', 'ready', 'running') \
                 FOR UPDATE";
    sqlx::query_as(query)
        .bind(rack_id)
        .fetch_optional(conn)
        .await
        .map_err(|error| DatabaseError::new(query, error))
}

pub async fn insert_preparing(
    conn: &mut PgConnection,
    request_id: Uuid,
    rack_id: &RackId,
    scope: &MaintenanceScope,
    requires_access_token: bool,
) -> DatabaseResult<RackMaintenanceRequest> {
    let query = "INSERT INTO rack_maintenance_requests \
                 (id, rack_id, scope, status, requires_access_token) \
                 VALUES ($1, $2, $3, 'preparing', $4) RETURNING *";
    sqlx::query_as(query)
        .bind(request_id)
        .bind(rack_id)
        .bind(sqlx::types::Json(scope))
        .bind(requires_access_token)
        .fetch_one(conn)
        .await
        .map_err(|error| DatabaseError::new(query, error))
}

pub async fn mark_ready(conn: &mut PgConnection, request_id: Uuid) -> DatabaseResult<bool> {
    transition(
        conn,
        request_id,
        RackMaintenanceRequestStatus::Preparing,
        RackMaintenanceRequestStatus::Ready,
        None,
    )
    .await
}

pub async fn mark_running(conn: &mut PgConnection, request_id: Uuid) -> DatabaseResult<bool> {
    transition(
        conn,
        request_id,
        RackMaintenanceRequestStatus::Ready,
        RackMaintenanceRequestStatus::Running,
        None,
    )
    .await
}

pub async fn mark_completed(conn: &mut PgConnection, request_id: Uuid) -> DatabaseResult<bool> {
    transition(
        conn,
        request_id,
        RackMaintenanceRequestStatus::Running,
        RackMaintenanceRequestStatus::Completed,
        None,
    )
    .await
}

pub async fn mark_failed(
    conn: &mut PgConnection,
    request_id: Uuid,
    error_message: &str,
) -> DatabaseResult<bool> {
    let query = "UPDATE rack_maintenance_requests \
                 SET status = 'failed', error_message = $2, updated = now(), completed = now() \
                 WHERE id = $1 AND status IN ('preparing', 'ready', 'running')";
    sqlx::query(query)
        .bind(request_id)
        .bind(error_message)
        .execute(conn)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(|error| DatabaseError::new(query, error))
}

pub async fn mark_preparing_failed(
    conn: &mut PgConnection,
    request_id: Uuid,
    error_message: &str,
) -> DatabaseResult<bool> {
    let query = "UPDATE rack_maintenance_requests \
                 SET status = 'failed', error_message = $2, updated = now(), completed = now() \
                 WHERE id = $1 AND status = 'preparing'";
    sqlx::query(query)
        .bind(request_id)
        .bind(error_message)
        .execute(conn)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(|error| DatabaseError::new(query, error))
}

pub async fn mark_cancelled(
    conn: &mut PgConnection,
    request_id: Uuid,
    reason: &str,
) -> DatabaseResult<bool> {
    let query = "UPDATE rack_maintenance_requests \
                 SET status = 'cancelled', error_message = $2, updated = now(), completed = now() \
                 WHERE id = $1 AND status IN ('preparing', 'ready')";
    sqlx::query(query)
        .bind(request_id)
        .bind(reason)
        .execute(conn)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(|error| DatabaseError::new(query, error))
}

async fn transition(
    conn: &mut PgConnection,
    request_id: Uuid,
    expected: RackMaintenanceRequestStatus,
    next: RackMaintenanceRequestStatus,
    error_message: Option<&str>,
) -> DatabaseResult<bool> {
    let terminal = next.is_terminal();
    let query = "UPDATE rack_maintenance_requests \
                 SET status = $3, error_message = $4, updated = now(), \
                     started = CASE WHEN $3 = 'running' THEN now() ELSE started END, \
                     completed = CASE WHEN $5 THEN now() ELSE completed END \
                 WHERE id = $1 AND status = $2";
    sqlx::query(query)
        .bind(request_id)
        .bind(expected)
        .bind(next)
        .bind(error_message)
        .bind(terminal)
        .execute(conn)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(|error| DatabaseError::new(query, error))
}
