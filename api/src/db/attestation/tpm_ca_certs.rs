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

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection};

use crate::{CarbideError, CarbideResult, db::DatabaseError};
use forge_uuid::machine::MachineId;

#[derive(FromRow, Debug, sqlx::Encode)]
pub struct TpmCaCert {
    pub id: i32,
    pub not_valid_before: DateTime<Utc>,
    pub not_valid_after: DateTime<Utc>,
    #[sqlx(default)]
    pub ca_cert_der: Vec<u8>,
    pub cert_subject: Vec<u8>,
}

impl TpmCaCert {
    pub async fn insert(
        txn: &mut PgConnection,
        not_valid_before: &DateTime<Utc>,
        not_valid_after: &DateTime<Utc>,
        ca_cert: &[u8],
        cert_subject: &[u8],
    ) -> CarbideResult<Option<Self>> {
        let query = "INSERT INTO tpm_ca_certs (not_valid_before, not_valid_after, ca_cert_der, cert_subject) VALUES ($1, $2, $3, $4) RETURNING *";

        let res = sqlx::query_as(query)
            .bind(not_valid_before)
            .bind(not_valid_after)
            .bind(ca_cert)
            .bind(cert_subject)
            .fetch_one(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::query(query, e)))?;

        Ok(Some(res))
    }

    pub async fn get_by_subject(
        txn: &mut PgConnection,
        cert_subject: &[u8],
    ) -> CarbideResult<Option<Self>> {
        let query = "SELECT * FROM tpm_ca_certs WHERE cert_subject = ($1)";

        sqlx::query_as(query)
            .bind(cert_subject)
            .fetch_optional(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::query(query, e)))
    }

    pub async fn get_all(txn: &mut PgConnection) -> CarbideResult<Vec<TpmCaCert>> {
        let query = "SELECT id, not_valid_before, not_valid_after, cert_subject FROM tpm_ca_certs";

        sqlx::query_as(query)
            .fetch_all(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::query(query, e)))
    }

    pub async fn delete(txn: &mut PgConnection, ca_cert_id: i32) -> CarbideResult<Option<Self>> {
        let query = "DELETE FROM tpm_ca_certs WHERE id = ($1) RETURNING *";

        sqlx::query_as(query)
            .bind(ca_cert_id)
            .fetch_optional(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::query(query, e)))
    }
}

// ------- EK Cert Verification Status -------------------

#[derive(FromRow, Debug)]
pub struct EkCertVerificationStatus {
    pub ek_sha256: Vec<u8>,
    pub serial_num: String,
    pub signing_ca_found: bool,
    pub issuer: Vec<u8>,
    pub issuer_access_info: Option<String>,
    pub machine_id: MachineId,
    // pub ca_id: Option<i32>, // currently unused
}

impl EkCertVerificationStatus {
    pub async fn get_by_ek_sha256(
        txn: &mut PgConnection,
        ek_sha256: &[u8],
    ) -> CarbideResult<Option<Self>> {
        let query = "SELECT * FROM ek_cert_verification_status WHERE ek_sha256 = ($1)";

        sqlx::query_as(query)
            .bind(ek_sha256)
            .fetch_optional(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn get_by_unmatched_ca(txn: &mut PgConnection) -> CarbideResult<Vec<Self>> {
        let query = "SELECT * FROM ek_cert_verification_status WHERE signing_ca_found = FALSE";

        sqlx::query_as(query)
            .fetch_all(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn get_by_issuer(txn: &mut PgConnection, issuer: &[u8]) -> CarbideResult<Vec<Self>> {
        let query = "SELECT * FROM ek_cert_verification_status WHERE issuer = ($1)";

        sqlx::query_as(query)
            .bind(issuer)
            .fetch_all(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn get_by_machine_id(
        txn: &mut PgConnection,
        machine_id: MachineId,
    ) -> CarbideResult<Option<Self>> {
        let query = "SELECT * FROM ek_cert_verification_status WHERE machine_id = ($1)";

        sqlx::query_as(query)
            .bind(machine_id)
            .fetch_optional(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn update_ca_verification_status(
        txn: &mut PgConnection,
        ek_sha256: &[u8],
        signing_ca_found: bool,
        ca_id: Option<i32>,
    ) -> CarbideResult<Vec<Self>> {
        let query = "UPDATE ek_cert_verification_status SET signing_ca_found=$1, ca_id=$2 WHERE ek_sha256=$3 RETURNING *";
        sqlx::query_as(query)
            .bind(signing_ca_found)
            .bind(ca_id)
            .bind(ek_sha256)
            .fetch_all(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn unmatch_ca_verification_status(
        txn: &mut PgConnection,
        ca_id: i32,
    ) -> CarbideResult<Option<Self>> {
        let query = "UPDATE ek_cert_verification_status SET signing_ca_found=false, ca_id=null WHERE ca_id=$1 RETURNING *";
        sqlx::query_as(query)
            .bind(ca_id)
            .fetch_optional(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn delete_ca_verification_status_by_machine_id(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> CarbideResult<Option<Self>> {
        let query = "DELETE FROM ek_cert_verification_status WHERE machine_id=$1 RETURNING *";
        sqlx::query_as(query)
            .bind(machine_id)
            .fetch_optional(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
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
    ) -> CarbideResult<Option<Self>> {
        let query = "INSERT INTO ek_cert_verification_status VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *";

        let res = sqlx::query_as(query)
            .bind(ek_sha256)
            .bind(serial_num)
            .bind(signing_ca_found)
            .bind(ca_id)
            .bind(issuer)
            .bind(issuer_access_info)
            .bind(machine_id)
            .fetch_one(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(Some(res))
    }
}
