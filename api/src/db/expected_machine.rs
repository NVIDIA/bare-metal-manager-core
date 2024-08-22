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
use std::ops::DerefMut;

use itertools::Itertools;
use mac_address::MacAddress;
use sqlx::{FromRow, Postgres, Transaction};

use super::machine_interface::MachineInterfaceId;
use super::DatabaseError;
use crate::CarbideError;
use crate::CarbideResult;

const SQL_VIOLATION_DUPLICATE_MAC: &str = "expected_machines_bmc_mac_address_key";

#[derive(Debug, Clone, Default, FromRow)]
pub struct ExpectedMachine {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub serial_number: String,
    pub bmc_password: String,
    pub fallback_dpu_serial_numbers: Vec<String>,
}

#[derive(FromRow)]
pub struct LinkedExpectedMachine {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_machines table
    pub interface_id: Option<MachineInterfaceId>, // from machine_interfaces table
    pub address: Option<String>,     // The explored endpoint
    pub machine_id: Option<String>,  // The machine
}

impl From<LinkedExpectedMachine> for rpc::forge::LinkedExpectedMachine {
    fn from(m: LinkedExpectedMachine) -> rpc::forge::LinkedExpectedMachine {
        rpc::forge::LinkedExpectedMachine {
            chassis_serial_number: m.serial_number,
            bmc_mac_address: m.bmc_mac_address.to_string(),
            interface_id: m.interface_id.map(|u| u.to_string()),
            explored_endpoint_address: m.address,
            machine_id: m
                .machine_id
                .map(|id| rpc::common::MachineId { id: id.to_string() }),
        }
    }
}

impl ExpectedMachine {
    pub async fn find_by_bmc_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        bmc_mac_address: MacAddress,
    ) -> Result<Option<ExpectedMachine>, DatabaseError> {
        let sql = "SELECT * FROM expected_machines WHERE bmc_mac_address=$1";
        sqlx::query_as(sql)
            .bind(bmc_mac_address)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|err: sqlx::Error| DatabaseError::new(file!(), line!(), sql, err))
    }

    pub async fn find_many_by_bmc_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        bmc_mac_addresses: &[MacAddress],
    ) -> CarbideResult<HashMap<MacAddress, ExpectedMachine>> {
        let sql = "SELECT * FROM expected_machines WHERE bmc_mac_address=ANY($1)";
        let v: Vec<ExpectedMachine> = sqlx::query_as(sql)
            .bind(bmc_mac_addresses)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|err: sqlx::Error| {
                CarbideError::from(DatabaseError::new(file!(), line!(), sql, err))
            })?;

        // expected_machines has a unique constraint on bmc_mac_address,
        // but if the constraint gets dropped and we have multiple mac addresses,
        // we want this code to generate an Err and not silently drop values
        // and/or return nothing.
        v.into_iter()
            .into_group_map_by(|exp| exp.bmc_mac_address)
            .drain()
            .map(|(k, mut v)| {
                if v.len() > 1 {
                    Err(CarbideError::AlreadyFoundError {
                        kind: "ExpectedMachine",
                        id: k.to_string(),
                    })
                } else {
                    Ok((k, v.pop().unwrap()))
                }
            })
            .collect()
    }

    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<ExpectedMachine>> {
        let sql = "SELECT * FROM expected_machines";
        sqlx::query_as(sql)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|err: sqlx::Error| DatabaseError::new(file!(), line!(), sql, err).into())
    }

    pub async fn find_all_linked(
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<LinkedExpectedMachine>> {
        let sql = r#"
 SELECT
 em.serial_number,
 em.bmc_mac_address,
 mi.id AS interface_id,
 host(ee.address) AS address,
 mt.machine_id
FROM expected_machines em
 LEFT JOIN machine_interfaces mi ON em.bmc_mac_address = mi.mac_address
 LEFT JOIN machine_interface_addresses mia ON mi.id = mia.interface_id
 LEFT JOIN explored_endpoints ee ON mia.address = ee.address
 LEFT JOIN machine_topologies mt ON host(ee.address) = mt.topology->'bmc_info'->>'ip'
 ORDER BY em.bmc_mac_address
 "#;
        sqlx::query_as(sql)
            .fetch_all(txn.deref_mut())
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
            .fetch_one(txn.deref_mut())
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
        fallback_dpu_serial_numbers: Vec<String>,
    ) -> CarbideResult<Self> {
        let query = "INSERT INTO expected_machines
            (bmc_mac_address, bmc_username, bmc_password, serial_number, fallback_dpu_serial_numbers)
            VALUES
            ($1::macaddr, $2::varchar, $3::varchar, $4::varchar, $5::text[]) RETURNING *";

        sqlx::query_as(query)
            .bind(bmc_mac_address)
            .bind(bmc_username)
            .bind(bmc_password)
            .bind(serial_number)
            .bind(fallback_dpu_serial_numbers)
            .fetch_one(txn.deref_mut())
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
            .execute(txn.deref_mut())
            .await
            .map(|_| ())
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::RowNotFound => CarbideError::NotFoundError {
                    kind: "expected_machine",
                    id: self.bmc_mac_address.to_string(),
                },
                _ => DatabaseError::new(file!(), line!(), query, err).into(),
            })
    }

    pub async fn clear(txn: &mut Transaction<'_, Postgres>) -> Result<(), DatabaseError> {
        let query = "DELETE FROM expected_machines";

        sqlx::query(query)
            .execute(txn.deref_mut())
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn update(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        bmc_username: String,
        bmc_password: String,
        serial_number: String,
        fallback_dpu_serial_numbers: Vec<String>,
    ) -> CarbideResult<&Self> {
        let query = "UPDATE expected_machines SET bmc_username=$1, bmc_password=$2, serial_number=$3, fallback_dpu_serial_numbers=$4 WHERE bmc_mac_address=$5 RETURNING bmc_mac_address";

        sqlx::query_as(query)
            .bind(&bmc_username)
            .bind(&bmc_password)
            .bind(&serial_number)
            .bind(&fallback_dpu_serial_numbers)
            .bind(self.bmc_mac_address)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::RowNotFound => CarbideError::NotFoundError {
                    kind: "expected_machine",
                    id: self.bmc_mac_address.to_string(),
                },
                _ => DatabaseError::new(file!(), line!(), query, err).into(),
            })?;

        self.serial_number = serial_number;
        self.bmc_username = bmc_username;
        self.bmc_password = bmc_password;
        self.fallback_dpu_serial_numbers = fallback_dpu_serial_numbers;
        Ok(self)
    }
}
