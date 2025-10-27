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
use model::attestation::SecretAkPub;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

pub async fn insert(
    txn: &mut PgConnection,
    secret: &Vec<u8>,
    ak_pub: &Vec<u8>,
) -> DatabaseResult<Option<SecretAkPub>> {
    let query = "INSERT INTO attestation_secret_ak_pub VALUES ($1, $2) RETURNING *";
    let res = sqlx::query_as(query)
        .bind(secret.as_slice())
        .bind(ak_pub.as_slice())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(Some(res))
}

pub async fn delete(
    txn: &mut PgConnection,
    secret: &Vec<u8>,
) -> DatabaseResult<Option<SecretAkPub>> {
    let query = "DELETE FROM attestation_secret_ak_pub WHERE secret = ($1) RETURNING *";

    let res = sqlx::query_as(query)
        .bind(secret.as_slice())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(Some(res))
}

pub async fn get_by_secret(
    txn: &mut PgConnection,
    secret: &Vec<u8>,
) -> DatabaseResult<Option<SecretAkPub>> {
    let query = "SELECT * FROM attestation_secret_ak_pub WHERE secret = ($1)";

    sqlx::query_as(query)
        .bind(secret.as_slice())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
