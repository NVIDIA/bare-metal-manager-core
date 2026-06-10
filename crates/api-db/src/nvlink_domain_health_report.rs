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

use carbide_uuid::nvlink::NvLinkDomainId;
use health_report::{HealthReport, HealthReportApplyMode};
use model::health::HealthReportSources;
use sqlx::PgConnection;

use crate::DatabaseError;
use crate::db_read::DbReader;

const TABLE_NAME: &str = "nvlink_domain_health_reports";

/// Finds the health report sources stored for an NVLink domain.
pub async fn find(
    txn: impl DbReader<'_>,
    domain_id: &NvLinkDomainId,
) -> Result<Option<HealthReportSources>, DatabaseError> {
    let query = "SELECT health_reports FROM nvlink_domain_health_reports WHERE id = $1";
    let health_reports = sqlx::query_scalar::<_, sqlx::types::Json<HealthReportSources>>(query)
        .bind(domain_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(health_reports.map(|json| json.0))
}

/// Lists NVLink domain IDs that have stored health reports.
pub async fn list_domain_ids(txn: impl DbReader<'_>) -> Result<Vec<NvLinkDomainId>, DatabaseError> {
    let query = "SELECT id FROM nvlink_domain_health_reports ORDER BY id";
    let ids = sqlx::query_scalar::<_, NvLinkDomainId>(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(ids)
}

/// Inserts or updates one health report source for an NVLink domain.
pub async fn insert_health_report(
    txn: &mut PgConnection,
    domain_id: &NvLinkDomainId,
    mode: HealthReportApplyMode,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    ensure_row(txn, domain_id).await?;

    crate::health_report::insert_health_report(txn, TABLE_NAME, domain_id, mode, health_report)
        .await
}

/// Removes one health report source from an NVLink domain.
pub async fn remove_health_report(
    txn: &mut PgConnection,
    domain_id: &NvLinkDomainId,
    mode: HealthReportApplyMode,
    source: &str,
) -> Result<(), DatabaseError> {
    crate::health_report::remove_health_report(txn, TABLE_NAME, domain_id, mode, source).await
}

/// Creates the domain row before applying a JSON health-report update.
async fn ensure_row(
    txn: &mut PgConnection,
    domain_id: &NvLinkDomainId,
) -> Result<(), DatabaseError> {
    // Health reports can arrive before inventory creates an NVLink domain row,
    // so inserts lazily create the container row and then use the shared JSON
    // update path.
    let query =
        "INSERT INTO nvlink_domain_health_reports (id) VALUES ($1) ON CONFLICT (id) DO NOTHING";

    sqlx::query(query)
        .bind(domain_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(())
}
