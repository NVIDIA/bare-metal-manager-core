/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};

use super::DatabaseError;
use crate::db::ipmi::UserRoles;

#[derive(Clone, Debug)]
pub struct SshKeyValidationRequest {
    pub user: String,
    pub pubkey: String,
}

#[derive(Clone, Debug)]
struct SshPublicKeys {
    role: UserRoles,
    pubkeys: Vec<String>,
}

impl From<rpc::SshKeyValidationRequest> for SshKeyValidationRequest {
    fn from(value: rpc::SshKeyValidationRequest) -> Self {
        SshKeyValidationRequest {
            user: value.user,
            pubkey: value.pubkey,
        }
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for SshPublicKeys {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(SshPublicKeys {
            role: row.try_get("role")?,
            pubkeys: row.try_get("pubkeys")?,
        })
    }
}

impl SshKeyValidationRequest {
    pub async fn verify_user(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<rpc::SshKeyValidationResponse, DatabaseError> {
        let query = "SELECT role, pubkeys from ssh_public_keys WHERE username=$1";
        let user_info: SshPublicKeys = sqlx::query_as(query)
            .bind(&self.user)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        // the key is normally formatted like "<algorith> <key>"
        if let Some(actual_key) = self.pubkey.split_ascii_whitespace().last() {
            for pkey in user_info.pubkeys {
                let key = pkey.lines().collect::<Vec<&str>>().join("");
                if key.contains(actual_key) {
                    // Key matched
                    return Ok(rpc::SshKeyValidationResponse {
                        is_authenticated: true,
                        role: rpc::UserRoles::from(user_info.role) as i32,
                    });
                }
            }
        }

        Ok(rpc::SshKeyValidationResponse {
            is_authenticated: false,
            role: rpc::UserRoles::Noaccess as i32,
        })
    }
}
