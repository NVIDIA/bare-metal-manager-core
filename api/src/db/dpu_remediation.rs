use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    ops::DerefMut,
};

use chrono::{DateTime, Utc};
use forge_uuid::{dpu_remediations::RemediationId, machine::MachineId};
use rpc::forge::{
    ApproveRemediationRequest, CreateRemediationRequest, DisableRemediationRequest,
    EnableRemediationRequest, RemediationApplicationStatus, RevokeRemediationRequest,
};
use sqlx::{FromRow, Postgres, Row, postgres::PgRow};

use super::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};
use crate::{
    errors::{CarbideError, CarbideResult},
    model::metadata::Metadata,
};

// about 16KB file size, long enough for any reasonable script but small enough to make it
// almost impossible to stuff a binary in the DB, which is the point of the limit.
const MAXIMUM_SCRIPT_LENGTH: usize = 2 << 13;

pub struct NewRemediation {
    script: String,
    metadata: Option<Metadata>,
    retries: i32,
    author: Author,
}

impl NewRemediation {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Remediation> {
        let (query, intermediate_query) = if let Some(metadata) = self.metadata.as_ref() {
            let query = "INSERT INTO dpu_remediations (metadata_name, metadata_description, metadata_labels, script, retries, script_author) VALUES ($1, $2, $3, $4, $5, $6) returning *";
            (
                query,
                sqlx::query_as(query)
                    .bind(&metadata.name)
                    .bind(&metadata.description)
                    .bind(sqlx::types::Json(&metadata.labels)),
            )
        } else {
            let query = "INSERT INTO dpu_remediations (script, retries, script_author) VALUES ($1, $2, $3) returning *";
            (query, sqlx::query_as(query))
        };

        intermediate_query
            .bind(&self.script)
            .bind(self.retries)
            .bind(self.author.to_string())
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|err| CarbideError::from(DatabaseError::new(query, err)))
    }
}

impl TryFrom<(CreateRemediationRequest, String)> for NewRemediation {
    type Error = CarbideError;

    fn try_from(value: (CreateRemediationRequest, String)) -> Result<Self, Self::Error> {
        let rpc_request = value.0;
        let author = value.1.into();

        let metadata = if let Some(metadata) = rpc_request.metadata {
            Some(Metadata::try_from(metadata)?)
        } else {
            None
        };
        let retries = if rpc_request.retries < 0 {
            return Err(CarbideError::InvalidArgument(String::from(
                "retries must be a positive integer or 0",
            )));
        } else {
            rpc_request.retries
        };

        let script = rpc_request.script.to_string();
        if script.len() > MAXIMUM_SCRIPT_LENGTH {
            return Err(CarbideError::InvalidArgument(format!(
                "script must not exceed length: {MAXIMUM_SCRIPT_LENGTH}"
            )));
        } else if script.is_empty() {
            return Err(CarbideError::InvalidArgument(
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

#[derive(Clone, Copy)]
pub struct RemediationIdColumn;
impl ColumnInfo<'_> for RemediationIdColumn {
    type TableType = Remediation;
    type ColumnType = RemediationId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Clone, Copy)]
pub struct EnabledColumn;

impl ColumnInfo<'_> for EnabledColumn {
    type TableType = Remediation;
    type ColumnType = bool;

    fn column_name(&self) -> &'static str {
        "enabled"
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

impl From<Remediation> for crate::api::rpc::CreateRemediationResponse {
    fn from(value: Remediation) -> Self {
        crate::api::rpc::CreateRemediationResponse {
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

impl Remediation {
    pub async fn find_remediation_ids(
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vec<RemediationId>, CarbideError> {
        let ids = Self::find_remediations_by(txn, ObjectColumnFilter::<RemediationIdColumn>::All)
            .await?
            .into_iter()
            .map(|x| x.id)
            .collect();
        Ok(ids)
    }

    pub async fn find_remediations_by_ids(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        remediation_ids: &[RemediationId],
    ) -> Result<Vec<Remediation>, CarbideError> {
        let remediations = Self::find_remediations_by(
            txn,
            ObjectColumnFilter::List(RemediationIdColumn, remediation_ids),
        )
        .await?;
        Ok(remediations)
    }
    pub async fn find_remediations_by<'a, C: ColumnInfo<'a, TableType = Remediation>>(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C>,
    ) -> Result<Vec<Remediation>, DatabaseError> {
        let mut query =
            FilterableQueryBuilder::new("SELECT * FROM dpu_remediations").filter(&filter);
        query
            .build_query_as()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(query.sql(), e))
    }

    pub async fn find_next_remediation_for_machine(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: MachineId,
    ) -> Result<Option<Remediation>, CarbideError> {
        for remediation in
            Self::find_remediations_by(txn, ObjectColumnFilter::List(EnabledColumn, &[true]))
                .await?
                .into_iter()
        {
            let max_attempts = remediation.retries + 1;
            let remediations_applied =
                AppliedRemediation::find_remediations_by_remediation_id_and_machine(
                    txn,
                    remediation.id,
                    &machine_id,
                )
                .await?;

            let attempted_so_far = remediations_applied.len() as i32;
            if attempted_so_far < max_attempts {
                if let Some(last_attempted) = remediations_applied.first() {
                    if last_attempted.succeeded {
                        continue;
                    }
                }
                return Ok(Some(remediation));
            }
        }
        Ok(None)
    }

    pub async fn remediation_applied(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: MachineId,
        remediation_id: RemediationId,
        status: RemediationApplicationStatus,
    ) -> Result<(), CarbideError> {
        let remediations_applied_so_far =
            AppliedRemediation::find_remediations_by_remediation_id_and_machine(
                txn,
                remediation_id,
                &machine_id,
            )
            .await?;

        let attempt_for_this_remediation = match remediations_applied_so_far.first() {
            Some(last_applied_remediation) => last_applied_remediation.attempt + 1,
            None => 1,
        };
        let metadata: Metadata = status
            .metadata
            .unwrap_or_default()
            .try_into()
            .map_err(CarbideError::from)?;

        let new_applied_remediation = NewAppliedRemediation {
            dpu_machine_id: machine_id.to_string(),
            id: remediation_id,
            succeeded: status.succeeded,
            status: metadata.labels,
            attempt: attempt_for_this_remediation,
        };

        let _ = new_applied_remediation.persist(txn).await?;

        Ok(())
    }
}

pub struct NewAppliedRemediation {
    id: RemediationId,
    dpu_machine_id: String,
    attempt: i32,
    succeeded: bool,
    status: HashMap<String, String>,
}

impl NewAppliedRemediation {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<AppliedRemediation, CarbideError> {
        let query = "INSERT INTO applied_dpu_remediations (id, dpu_machine_id, attempt, succeeded, status) VALUES ($1, $2, $3, $4, $5) returning *";

        sqlx::query_as(query)
            .bind(self.id)
            .bind(&self.dpu_machine_id)
            .bind(self.attempt)
            .bind(self.succeeded)
            .bind(sqlx::types::Json(&self.status))
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|err| CarbideError::from(DatabaseError::new(query, err)))
    }
}

#[derive(Clone, Copy)]
pub struct AppliedRemediationIdColumn;
impl ColumnInfo<'_> for AppliedRemediationIdColumn {
    type TableType = AppliedRemediation;
    type ColumnType = RemediationId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Clone, Copy)]
pub struct AppliedRemediationDpuMachineIdColumn;
impl ColumnInfo<'_> for AppliedRemediationDpuMachineIdColumn {
    type TableType = AppliedRemediation;
    type ColumnType = String;

    fn column_name(&self) -> &'static str {
        "dpu_machine_id"
    }
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

pub enum AppliedRemediationIdQueryType {
    Machine(MachineId),
    RemediationId(RemediationId),
}

impl AppliedRemediation {
    pub async fn find_applied_remediation_ids(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id_query_args: AppliedRemediationIdQueryType,
    ) -> Result<(Vec<RemediationId>, Vec<MachineId>), CarbideError> {
        let ids = match id_query_args {
            AppliedRemediationIdQueryType::Machine(machine_id) => {
                let remediation_ids = Self::find_applied_remediations_by(
                    txn,
                    ObjectColumnFilter::List(
                        AppliedRemediationDpuMachineIdColumn,
                        &[machine_id.to_string()],
                    ),
                )
                .await?
                .into_iter()
                .map(|x| x.id)
                .collect();

                (remediation_ids, vec![machine_id])
            }
            AppliedRemediationIdQueryType::RemediationId(remediation_id) => {
                let machine_ids = Self::find_applied_remediations_by(
                    txn,
                    ObjectColumnFilter::List(AppliedRemediationIdColumn, &[remediation_id]),
                )
                .await?
                .into_iter()
                .map(|x| x.dpu_machine_id)
                .collect();

                (vec![remediation_id], machine_ids)
            }
        };

        Ok(ids)
    }

    pub async fn find_applied_remediations_by<
        'a,
        C: ColumnInfo<'a, TableType = AppliedRemediation>,
    >(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C>,
    ) -> Result<Vec<AppliedRemediation>, DatabaseError> {
        let mut query =
            FilterableQueryBuilder::new("SELECT * FROM applied_dpu_remediations").filter(&filter);
        query
            .build_query_as()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(query.sql(), e))
    }

    // we cannot use the generic query for this one because we can't limit it to _two_ columns, unfortunately.
    pub async fn find_remediations_by_remediation_id_and_machine(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        remediation_id: RemediationId,
        machine_id: &MachineId,
    ) -> Result<Vec<AppliedRemediation>, CarbideError> {
        let query = "SELECT * FROM applied_dpu_remediations WHERE id=$1 AND dpu_machine_id=$2 ORDER BY attempt DESC";
        sqlx::query_as(query)
            .bind(remediation_id)
            .bind(machine_id.to_string())
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(query, e))
            .map_err(CarbideError::from)
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
    type Error = CarbideError;

    fn try_from(value: (ApproveRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value.0.remediation_id.ok_or(CarbideError::MissingArgument(
            "Request must contain a remediation id.",
        ))?;
        let reviewer = value.1.into();

        Ok(Self { id, reviewer })
    }
}

impl ApproveRemediation {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), CarbideError> {
        let existing_query = "SELECT * from dpu_remediations WHERE id=$1";
        let existing_remediation: Remediation = sqlx::query_as(existing_query)
            .bind(self.id)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(existing_query, e))?
            .ok_or(CarbideError::NotFoundError {
                kind: "dpu_remediations.id",
                id: self.id.to_string(),
            })?;

        if existing_remediation.author.to_string().as_str() == self.reviewer.to_string().as_str() {
            return Err(CarbideError::InvalidArgument("Reviewer cannot be the same person as Author for remediation, must be different person.".to_string()));
        } else if let Some(reviewer) = existing_remediation.reviewer.as_ref() {
            let reviewer = reviewer.to_string();
            if !reviewer.is_empty() {
                return Err(CarbideError::InvalidArgument(format!(
                    "Reviewer is already set to '{reviewer}', cannot overwrite.  Revoke if necessary.",
                )));
            }
        }

        let update_query = "UPDATE dpu_remediations SET script_reviewed_by=$1 WHERE id=$2";
        let _ = sqlx::query(update_query)
            .bind(self.reviewer.to_string())
            .bind(self.id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(update_query, e))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RevokeRemediation {
    pub id: RemediationId,
}

impl TryFrom<(RevokeRemediationRequest, String)> for RevokeRemediation {
    type Error = CarbideError;

    fn try_from(value: (RevokeRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value.0.remediation_id.ok_or(CarbideError::MissingArgument(
            "Request must contain a remediation id.",
        ))?;
        let revoked_by = value.1;
        tracing::info!("Remediation: '{}' revoked by: '{}'", id, revoked_by);

        Ok(Self { id })
    }
}

impl RevokeRemediation {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), CarbideError> {
        let update_query =
            "UPDATE dpu_remediations SET script_reviewed_by=NULL,enabled=false WHERE id=$1";
        let _ = sqlx::query(update_query)
            .bind(self.id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(update_query, e))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EnableRemediation {
    pub id: RemediationId,
}

impl TryFrom<(EnableRemediationRequest, String)> for EnableRemediation {
    type Error = CarbideError;

    fn try_from(value: (EnableRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value.0.remediation_id.ok_or(CarbideError::MissingArgument(
            "Request must contain a remediation id.",
        ))?;
        let enabled_by = value.1;
        tracing::info!("Remediation: '{}' enabled by: '{}'", id, enabled_by);

        Ok(Self { id })
    }
}

impl EnableRemediation {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), CarbideError> {
        let existing_query = "SELECT * from dpu_remediations WHERE id=$1";
        let existing_remediation: Remediation = sqlx::query_as(existing_query)
            .bind(self.id)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(existing_query, e))?
            .ok_or(CarbideError::NotFoundError {
                kind: "dpu_remediations.id",
                id: self.id.to_string(),
            })?;

        if existing_remediation.reviewer.is_none() {
            return Err(CarbideError::InvalidArgument(
                "Cannot enable a remediation that has not been approved.".to_string(),
            ));
        }

        let update_query = "UPDATE dpu_remediations SET enabled=true WHERE id=$1";
        let _ = sqlx::query(update_query)
            .bind(self.id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(update_query, e))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DisableRemediation {
    pub id: RemediationId,
}

impl TryFrom<(DisableRemediationRequest, String)> for DisableRemediation {
    type Error = CarbideError;

    fn try_from(value: (DisableRemediationRequest, String)) -> Result<Self, Self::Error> {
        let id = value.0.remediation_id.ok_or(CarbideError::MissingArgument(
            "Request must contain a remediation id.",
        ))?;
        let disabled_by = value.1;
        tracing::info!("Remediation: '{}' disabled by: '{}'", id, disabled_by);

        Ok(Self { id })
    }
}

impl DisableRemediation {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), CarbideError> {
        let update_query = "UPDATE dpu_remediations SET enabled=false WHERE id=$1";
        let _ = sqlx::query(update_query)
            .bind(self.id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(update_query, e))?;

        Ok(())
    }
}
