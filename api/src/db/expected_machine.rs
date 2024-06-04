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

use itertools::Itertools;
use mac_address::MacAddress;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use super::DatabaseError;
use crate::CarbideError;
use crate::CarbideResult;

const SQL_VIOLATION_DUPLICATE_MAC: &str = "expected_machines_bmc_mac_address_key";

#[derive(Debug, Clone)]
pub struct ExpectedMachine {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub serial_number: String,
    pub bmc_password: String,
}

impl<'r> FromRow<'r, PgRow> for ExpectedMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(ExpectedMachine {
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            bmc_username: row.try_get("bmc_username")?,
            bmc_password: row.try_get("bmc_password")?,
            serial_number: row.try_get("serial_number")?,
        })
    }
}

impl ExpectedMachine {
    pub async fn find_by_bmc_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        bmc_mac_address: MacAddress,
    ) -> CarbideResult<Option<ExpectedMachine>> {
        let sql = "SELECT * FROM expected_machines WHERE bmc_mac_address=$1";
        sqlx::query_as(sql)
            .bind(bmc_mac_address)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|err: sqlx::Error| DatabaseError::new(file!(), line!(), sql, err).into())
    }

    pub async fn find_many_by_bmc_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        bmc_mac_addresses: &[MacAddress],
    ) -> CarbideResult<HashMap<MacAddress, ExpectedMachine>> {
        let sql = "SELECT * FROM expected_machines WHERE bmc_mac_address=ANY($1)";
        let v: Vec<ExpectedMachine> = sqlx::query_as(sql)
            .bind(bmc_mac_addresses)
            .fetch_all(&mut **txn)
            .await
            .map_err(|err: sqlx::Error| {
                CarbideError::from(DatabaseError::new(file!(), line!(), sql, err))
            })?;
        Ok(v.into_iter()
            .into_group_map_by(|exp| exp.bmc_mac_address)
            .drain()
            .filter(|(_, v)| v.len() == 1)
            .map(|(k, mut v)| (k, v.pop().unwrap()))
            .collect())
    }

    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<ExpectedMachine>> {
        let sql = "SELECT * FROM expected_machines";
        sqlx::query_as(sql)
            .fetch_all(&mut **txn)
            .await
            .map_err(|err: sqlx::Error| DatabaseError::new(file!(), line!(), sql, err).into())
    }

    pub async fn update_bmc_credentials(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        bmc_username: String,
        bmc_password: String,
    ) -> CarbideResult<&Self> {
        let query = "UPDATE expected_machines SET bmc_username=$1, bmc_password=$2 WHERE bmc_mac_address=$3 RETURNING bmc_mac_address";

        sqlx::query_as(query)
            .bind(&bmc_username)
            .bind(&bmc_password)
            .bind(self.bmc_mac_address)
            .fetch_one(&mut **txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::RowNotFound => CarbideError::NotFoundError {
                    kind: "expected_machine",
                    id: self.bmc_mac_address.to_string(),
                },
                _ => DatabaseError::new(file!(), line!(), query, err).into(),
            })?;

        self.bmc_username = bmc_username;
        self.bmc_password = bmc_password;

        Ok(self)
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        bmc_mac_address: MacAddress,
        bmc_username: String,
        bmc_password: String,
        serial_number: String,
    ) -> CarbideResult<Self> {
        let query = "INSERT INTO expected_machines
            (bmc_mac_address, bmc_username, bmc_password, serial_number)
            VALUES
            ($1::macaddr, $2::varchar, $3::varchar, $4::varchar) RETURNING *";

        sqlx::query_as(query)
            .bind(bmc_mac_address)
            .bind(bmc_username)
            .bind(bmc_password)
            .bind(serial_number)
            .fetch_one(&mut **txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                    CarbideError::ExpectedHostDuplicateMacAddress(bmc_mac_address)
                }
                _ => DatabaseError::new(file!(), line!(), query, err).into(),
            })
    }

    pub async fn delete(self, txn: &mut Transaction<'_, Postgres>) -> CarbideResult<()> {
        let query = "DELETE FROM expected_machines WHERE bmc_mac_address=$1";

        sqlx::query(query)
            .bind(self.bmc_mac_address)
            .execute(&mut **txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::RowNotFound => CarbideError::NotFoundError {
                    kind: "expected_machine",
                    id: self.bmc_mac_address.to_string(),
                },
                _ => DatabaseError::new(file!(), line!(), query, err).into(),
            })?;

        Ok(())
    }

    pub async fn clear(txn: &mut Transaction<'_, Postgres>) -> Result<(), DatabaseError> {
        let query = "DELETE FROM expected_machines";

        sqlx::query(query)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }
}
