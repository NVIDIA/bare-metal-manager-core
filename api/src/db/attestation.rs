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

use sqlx::{FromRow, Postgres, Transaction};

use crate::{db::DatabaseError, CarbideError, CarbideResult};

#[derive(FromRow, Debug, sqlx::Encode)]
pub struct SecretAkPub {
    pub secret: Vec<u8>,
    pub ak_pub: Vec<u8>,
}

impl SecretAkPub {
    pub async fn insert(
        txn: &mut Transaction<'_, Postgres>,
        secret: &Vec<u8>,
        ak_pub: &Vec<u8>,
    ) -> CarbideResult<Option<Self>> {
        let query = "INSERT INTO attestation_secret_ak_pub VALUES ($1, $2) RETURNING *";
        let res = sqlx::query_as(query)
            .bind(secret.as_slice())
            .bind(ak_pub.as_slice())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(Some(res))
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        secret: &Vec<u8>,
    ) -> CarbideResult<Option<Self>> {
        let query = "DELETE FROM attestation_secret_ak_pub WHERE secret = ($1) RETURNING *";

        let res = sqlx::query_as(query)
            .bind(secret.as_slice())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(Some(res))
    }

    pub async fn get_by_secret(
        txn: &mut Transaction<'_, Postgres>,
        secret: &Vec<u8>,
    ) -> CarbideResult<Option<Self>> {
        let query = "SELECT * FROM attestation_secret_ak_pub WHERE secret = ($1)";

        let res = sqlx::query_as(query)
            .bind(secret.as_slice())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(res)
    }
}
