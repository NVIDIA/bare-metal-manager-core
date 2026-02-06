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
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use carbide_uuid::dpu_remediations::RemediationId;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use rpc::errors::RpcDataConversionError;
use rpc::forge::{
    ApproveRemediationRequest, CreateRemediationRequest, DisableRemediationRequest,
    EnableRemediationRequest, RevokeRemediationRequest,
};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::Metadata;

// about 16KB file size, long enough for any reasonable script but small enough to make it
// almost impossible to stuff a binary in the DB, which is the point of the limit.
const MAXIMUM_SCRIPT_LENGTH: usize = 2 << 13;

pub struct NewRemediation {
    pub script: String,
    pub metadata: Option<Metadata>,
    pub retries: i32,
    pub author: Author,
}

impl TryFrom<(CreateRemediationRequest, String)> for NewRemediation {
    type Error = RpcDataConversionError;

    fn try_from(value: (CreateRemediationRequest, String)) -> Result<Self, Self::Error> {
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

#[derive(Clone, Debug)]
pub struct Author {
    name: String,
}

impl From<String> for Author {
    fn from(value: String) -> Self {
        Self { name: value }
    }
}

impl Display for Author {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Clone, Debug)]
pub struct Reviewer {
    name: String,
}

impl From<String> for Reviewer {
    fn from(value: String) -> Self {
        Self { name: value }
    }
}

impl Display for Reviewer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Debug, Clone)]
pub struct Remediation {
    pub id: RemediationId,
    pub script: String,
    pub metadata: Option<Metadata>,
    pub reviewer: Option<Reviewer>,
    pub author: Author,
    pub retries: i32,
    pub enabled: bool,
    pub creation_time: DateTime<Utc>,
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

impl<'r> FromRow<'r, PgRow> for Remediation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let metadata_labels: Option<sqlx::types::Json<HashMap<String, String>>> =
            row.try_get("metadata_labels").ok();
        let metadata_name: Option<String> = row.try_get("metadata_name").ok();
        let metadata_description: Option<String> = row.try_get("metadata_description").ok();

        let metadata = if metadata_name
            .as_ref()
            .map(|x| !x.trim().is_empty())
            .unwrap_or(false)
            || metadata_description
                .as_ref()
                .map(|x| !x.trim().is_empty())
                .unwrap_or(false)
            || metadata_labels
                .as_ref()
                .map(|x| !x.is_empty())
                .unwrap_or(false)
        {
            Some(Metadata {
                name: metadata_name.unwrap_or_default(),
                description: metadata_description.unwrap_or_default(),
                labels: metadata_labels.map(|x| x.0).unwrap_or_default(),
            })
        } else {
            None
        };

        let reviewer: Option<String> = row.try_get("script_reviewed_by").ok();
        let author: String = row.try_get("script_author")?;

        Ok(Self {
            id: row.try_get("id")?,
            script: row.try_get("script")?,
            retries: row.try_get("retries")?,
            enabled: row.try_get("enabled")?,
            reviewer: reviewer.map(Reviewer::from),
            author: Author::from(author),
            creation_time: row.try_get("creation_time")?,
            metadata,
        })
    }
}

pub struct NewAppliedRemediation {
    pub id: RemediationId,
    pub dpu_machine_id: String,
    pub attempt: i32,
    pub succeeded: bool,
    pub status: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct AppliedRemediation {
    pub id: RemediationId,
    pub dpu_machine_id: MachineId,
    pub attempt: i32,
    pub succeeded: bool,
    pub status: HashMap<String, String>,
    pub applied_time: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for AppliedRemediation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let status: Option<sqlx::types::Json<HashMap<String, String>>> = row.try_get("status").ok();
        let status = status.map(|x| x.0).unwrap_or_default();

        Ok(Self {
            id: row.try_get("id")?,
            dpu_machine_id: row.try_get("dpu_machine_id")?,
            attempt: row.try_get("attempt")?,
            succeeded: row.try_get("succeeded")?,
            applied_time: row.try_get("applied_time")?,
            status,
        })
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

#[derive(Debug, Clone)]
pub struct ApproveRemediation {
    pub id: RemediationId,
    pub reviewer: Reviewer,
}

impl TryFrom<(ApproveRemediationRequest, String)> for ApproveRemediation {
    type Error = RpcDataConversionError;

    fn try_from(value: (ApproveRemediationRequest, String)) -> Result<Self, Self::Error> {
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

#[derive(Debug, Clone)]
pub struct RevokeRemediation {
    pub id: RemediationId,
}

impl TryFrom<(RevokeRemediationRequest, String)> for RevokeRemediation {
    type Error = RpcDataConversionError;

    fn try_from(value: (RevokeRemediationRequest, String)) -> Result<Self, Self::Error> {
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

#[derive(Debug, Clone)]
pub struct EnableRemediation {
    pub id: RemediationId,
}

impl TryFrom<(EnableRemediationRequest, String)> for EnableRemediation {
    type Error = RpcDataConversionError;

    fn try_from(value: (EnableRemediationRequest, String)) -> Result<Self, Self::Error> {
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

#[derive(Debug, Clone)]
pub struct DisableRemediation {
    pub id: RemediationId,
}

impl TryFrom<(DisableRemediationRequest, String)> for DisableRemediation {
    type Error = RpcDataConversionError;

    fn try_from(value: (DisableRemediationRequest, String)) -> Result<Self, Self::Error> {
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
