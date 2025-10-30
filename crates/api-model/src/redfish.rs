/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{FromRow, Row};

pub struct ActionRequest {
    pub request_id: i64,
    pub requester: String,
    pub approvers: Vec<String>,
    pub approver_dates: Vec<DateTime<Utc>>,
    pub machine_ips: Vec<String>,
    pub board_serials: Vec<String>,
    pub target: String,
    pub action: String,
    pub parameters: String,
    pub applied_at: Option<DateTime<Utc>>,
    pub applier: Option<String>,
    pub results: Vec<Option<BMCResponse>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BMCResponse {
    pub headers: HashMap<String, String>,
    pub status: String,
    pub body: String,
    pub completed_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for ActionRequest {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let request_id = row.try_get("request_id")?;
        let requester = row.try_get("requester")?;
        let approvers: Vec<_> = row.try_get("approvers")?;
        let approver_dates: Vec<_> = row.try_get("approver_dates")?;
        let machine_ips: Vec<String> = row.try_get("machine_ips")?;
        let board_serials: Vec<String> = row.try_get("board_serials")?;
        let target = row.try_get("target")?;
        let action = row.try_get("action")?;
        let parameters = row.try_get("parameters")?;
        let applied_at = row.try_get("applied_at")?;
        let applier = row.try_get("applier")?;
        let results: Option<Vec<Option<Json<BMCResponse>>>> = row.try_get("results")?;
        Ok(Self {
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
            results: results
                .unwrap_or_default()
                .into_iter()
                .map(|option| option.map(|json| json.0))
                .collect(),
        })
    }
}

impl From<ActionRequest> for rpc::forge::RedfishAction {
    fn from(value: ActionRequest) -> Self {
        Self {
            request_id: value.request_id,
            requester: value.requester,
            approvers: value.approvers,
            approver_dates: value.approver_dates.into_iter().map(|d| d.into()).collect(),
            machine_ips: value.machine_ips,
            board_serials: value.board_serials,
            target: value.target,
            action: value.action,
            parameters: value.parameters,
            applied_at: value.applied_at.map(|t| t.into()),
            applier: value.applier,
            results: value
                .results
                .into_iter()
                .map(|r| rpc::forge::OptionalRedfishActionResult {
                    result: r.map(|r| rpc::forge::RedfishActionResult {
                        headers: r.headers,
                        status: r.status,
                        body: r.body,
                        completed_at: Some(r.completed_at.into()),
                    }),
                })
                .collect(),
        }
    }
}
