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

use carbide_uuid::machine::MachineId;
use model::attestation::EkCertVerificationStatus;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

pub async fn get_by_ek_sha256(
    txn: &mut PgConnection,
    ek_sha256: &[u8],
) -> DatabaseResult<Option<EkCertVerificationStatus>> {
    let query = "SELECT * FROM ek_cert_verification_status WHERE ek_sha256 = ($1)";

    sqlx::query_as(query)
        .bind(ek_sha256)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn get_by_unmatched_ca(
    txn: &mut PgConnection,
) -> DatabaseResult<Vec<EkCertVerificationStatus>> {
    let query = "SELECT * FROM ek_cert_verification_status WHERE signing_ca_found = FALSE";

    sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn get_by_issuer(
    txn: &mut PgConnection,
    issuer: &[u8],
) -> DatabaseResult<Vec<EkCertVerificationStatus>> {
    let query = "SELECT * FROM ek_cert_verification_status WHERE issuer = ($1)";

    sqlx::query_as(query)
        .bind(issuer)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn get_by_machine_id(
    txn: impl DbReader<'_>,
    machine_id: MachineId,
) -> DatabaseResult<Option<EkCertVerificationStatus>> {
    let query = "SELECT * FROM ek_cert_verification_status WHERE machine_id = ($1)";

    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn update_ca_verification_status(
    txn: &mut PgConnection,
    ek_sha256: &[u8],
    signing_ca_found: bool,
    ca_id: Option<i32>,
) -> DatabaseResult<Vec<EkCertVerificationStatus>> {
    let query = "UPDATE ek_cert_verification_status SET signing_ca_found=$1, ca_id=$2 WHERE ek_sha256=$3 RETURNING *";
    sqlx::query_as(query)
        .bind(signing_ca_found)
        .bind(ca_id)
        .bind(ek_sha256)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn unmatch_ca_verification_status(
    txn: &mut PgConnection,
    ca_id: i32,
) -> DatabaseResult<Option<EkCertVerificationStatus>> {
    let query = "UPDATE ek_cert_verification_status SET signing_ca_found=false, ca_id=null WHERE ca_id=$1 RETURNING *";
    sqlx::query_as(query)
        .bind(ca_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete_ca_verification_status_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<Option<EkCertVerificationStatus>> {
    let query = "DELETE FROM ek_cert_verification_status WHERE machine_id=$1 RETURNING *";
    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    txn: &mut PgConnection,
    ek_sha256: &[u8],
    serial_num: &str,
    signing_ca_found: bool,
    ca_id: Option<i32>,
    issuer: &[u8],
    issuer_access_info: &str,
    machine_id: MachineId,
) -> DatabaseResult<Option<EkCertVerificationStatus>> {
    let query =
        "INSERT INTO ek_cert_verification_status VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *";

    sqlx::query_as(query)
        .bind(ek_sha256)
        .bind(serial_num)
        .bind(signing_ca_found)
        .bind(ca_id)
        .bind(issuer)
        .bind(issuer_access_info)
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
        .map(Some)
}
