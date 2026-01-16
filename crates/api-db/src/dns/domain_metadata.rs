/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use model::dns::metadata::DomainMetadata;
use sqlx::postgres::PgRow;
use sqlx::{Error, FromRow, Row};

use crate::DatabaseError;

#[derive(Debug, Clone, Default)]
pub struct DbMetadata {
    allow_axfr_from: Vec<String>,
}

impl<'r> FromRow<'r, PgRow> for DbMetadata {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        Ok(DbMetadata {
            allow_axfr_from: row.try_get("allow_axfr_from")?,
        })
    }
}

pub async fn metadata_for_domain(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domain_name: &str,
) -> Result<DbMetadata, DatabaseError> {
    let domain_name = crate::dns::normalize_domain(domain_name);

    let query = "SELECT m.* FROM domain_metadata m JOIN domains d ON m.id = d.domain_metadata_id WHERE d.name = $1";
    let metadata: DbMetadata = sqlx::query_as(query)
        .bind(domain_name)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(metadata)
}

impl From<DbMetadata> for DomainMetadata {
    fn from(metadata: DbMetadata) -> Self {
        DomainMetadata {
            allow_axfr_from: metadata.allow_axfr_from,
        }
    }
}

impl DbMetadata {
    pub async fn persist(&self, txn: &mut sqlx::PgConnection) -> Result<i32, DatabaseError> {
        let query = "INSERT INTO domain_metadata (allow_axfr_from) VALUES ($1) RETURNING id";
        let row: (i32,) = sqlx::query_as(query)
            .bind(&self.allow_axfr_from)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        Ok(row.0)
    }

    pub async fn create_default(txn: &mut sqlx::PgConnection) -> Result<i32, DatabaseError> {
        Self::default().persist(txn).await
    }
}
