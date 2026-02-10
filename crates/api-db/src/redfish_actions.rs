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
use std::collections::{HashMap, HashSet};

use model::redfish::{ActionRequest, BMCResponse};
use sqlx::PgConnection;
use sqlx::types::Json;

use crate::DatabaseError;
use crate::db_read::DbReader;

pub async fn list_requests(
    request: rpc::forge::RedfishListActionsRequest,
    txn: impl DbReader<'_>,
) -> Result<Vec<ActionRequest>, DatabaseError> {
    let text_query = format!(
        "SELECT
        request_id,
        requester,
        approvers,
        approver_dates,
        machine_ips,
        board_serials,
        target,
        action,
        parameters,
        applied_at,
        applier,
        results
    FROM redfish_bmc_actions
    {}
    ORDER BY applied_at DESC
    ",
        if request.machine_ip.is_some() {
            "WHERE $1 <@ machine_ips"
        } else {
            ""
        }
    );
    let query = if let Some(machine_ip) = request.machine_ip {
        sqlx::query_as(&text_query).bind(vec![machine_ip])
    } else {
        sqlx::query_as(&text_query)
    };
    let result: Vec<ActionRequest> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(&text_query, e))?;
    Ok(result)
}

pub async fn fetch_request(
    request: rpc::forge::RedfishActionId,
    txn: &mut PgConnection,
) -> Result<ActionRequest, DatabaseError> {
    let query = "SELECT
        request_id,
        requester,
        approvers,
        approver_dates,
        machine_ips,
        board_serials,
        target,
        action,
        parameters,
        applied_at,
        applier,
        results
     FROM redfish_bmc_actions WHERE request_id = $1";
    let action_request: Option<ActionRequest> = sqlx::query_as(query)
        .bind(request.request_id)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    let Some(action_request) = action_request else {
        return Err(DatabaseError::NotFoundError {
            kind: "redfish_bmc_action",
            id: request.request_id.to_string(),
        });
    };
    Ok(action_request)
}

pub async fn find_serials(
    ips: &[String],
    txn: &mut PgConnection,
) -> Result<HashMap<String, String>, DatabaseError> {
    let pairs = crate::machine_topology::find_machine_bmc_pairs(&mut *txn, ips.to_vec()).await?;
    if pairs.len() != ips.len() {
        let requested_ips: HashSet<_> = ips.iter().cloned().collect();
        let found_ips: HashSet<_> = pairs.into_iter().map(|p| p.1).collect();
        return Err(DatabaseError::NotFoundError {
            kind: "machine topologies",
            id: requested_ips
                .difference(&found_ips)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        });
    }
    let topologies = crate::machine_topology::find_by_machine_ids(
        txn,
        pairs.iter().map(|p| p.0).collect::<Vec<_>>().as_slice(),
    )
    .await?;
    let mut output = HashMap::new();
    for (id, ip) in pairs {
        let (topology, remainder) = topologies
            .get(&id)
            .and_then(|v| v.split_first())
            .ok_or_else(|| DatabaseError::NotFoundError {
                kind: "machine topology",
                id: id.to_string(),
            })?;
        // See find_by_machine_ids: there should only ever be one topology.
        if !remainder.is_empty() {
            return Err(DatabaseError::internal(format!(
                "found multiple topologies for machine {id}"
            )));
        }
        let dmi_data = topology
            .topology()
            .discovery_data
            .info
            .dmi_data
            .as_ref()
            .ok_or_else(|| DatabaseError::NotFoundError {
                kind: "discovery data dmi_data",
                id: id.to_string(),
            })?;
        output.insert(ip, dmi_data.chassis_serial.clone());
    }
    Ok(output)
}

pub async fn insert_request(
    authored_by: String,
    request: rpc::forge::RedfishCreateActionRequest,
    txn: &mut PgConnection,
    machine_ips: Vec<String>,
    serials: Vec<&String>,
) -> Result<i64, DatabaseError> {
    let query = r#"INSERT INTO redfish_bmc_actions(requester, approvers, approver_dates, machine_ips, board_serials, target, action, parameters, results)
       VALUES($1, $2, '{now()}', $3, $4, $5, $6, $7, $8)
       RETURNING request_id
    "#;
    let machine_count = machine_ips.len();
    let request_id: i64 = sqlx::query_scalar(query)
        .bind(authored_by.clone())
        .bind(vec![authored_by])
        .bind(machine_ips)
        .bind(serials)
        .bind(request.target)
        .bind(request.action)
        .bind(request.parameters)
        .bind(vec![None::<Json<BMCResponse>>; machine_count])
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    Ok(request_id)
}

pub async fn approve_request(
    approver: String,
    request: rpc::forge::RedfishActionId,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let query = r#"UPDATE redfish_bmc_actions
    SET approvers = array_prepend($1, approvers), approver_dates = array_prepend(now(), approver_dates)
    WHERE request_id = $2 AND NOT approvers @> ARRAY[$1]"#;
    let is_approved = sqlx::query(query)
        .bind(approver)
        .bind(request.request_id)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?
        .rows_affected()
        == 1;
    Ok(is_approved)
}

pub async fn update_response(
    request: rpc::forge::RedfishActionId,
    txn: &mut PgConnection,
    response: BMCResponse,
    bmc_index: usize,
) -> Result<(), DatabaseError> {
    let query = r#"UPDATE redfish_bmc_actions SET results[$1] = $2 WHERE request_id = $3"#;
    sqlx::query(query)
        .bind(bmc_index as i32 + 1) // postgres is 1-indexed.
        .bind(Json(response))
        .bind(request.request_id)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    Ok(())
}

pub async fn set_applied(
    applied_by: String,
    request: rpc::forge::RedfishActionId,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let query = r#"UPDATE redfish_bmc_actions SET applied_at = now(), applier = $1 WHERE request_id = $2 AND applied_at IS NULL"#;
    let is_applied = sqlx::query(query)
        .bind(applied_by)
        .bind(request.request_id)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?
        .rows_affected()
        == 1;
    Ok(is_applied)
}

pub async fn delete_request(
    request: rpc::forge::RedfishActionId,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = r#"DELETE FROM redfish_bmc_actions WHERE request_id = $1 AND applied_at IS NULL"#;
    let result = sqlx::query(query)
        .bind(request.request_id)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "redfish_bmc_action",
            id: request.request_id.to_string(),
        });
    }
    Ok(())
}
