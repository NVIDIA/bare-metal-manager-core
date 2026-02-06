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

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use carbide_uuid::rack::RackId;
use itertools::Itertools;
use mac_address::MacAddress;
use model::expected_power_shelf::{ExpectedPowerShelf, LinkedExpectedPowerShelf};
use model::metadata::Metadata;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "expected_power_shelves_bmc_mac_address_key";

pub async fn find_by_bmc_mac_address(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<Option<ExpectedPowerShelf>> {
    let sql = "SELECT * FROM expected_power_shelves WHERE bmc_mac_address=$1";
    sqlx::query_as(sql)
        .bind(bmc_mac_address)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_many_by_bmc_mac_address(
    txn: &mut PgConnection,
    bmc_mac_addresses: &[MacAddress],
) -> DatabaseResult<HashMap<MacAddress, ExpectedPowerShelf>> {
    let sql = "SELECT * FROM expected_power_shelves WHERE bmc_mac_address=ANY($1)";
    let v: Vec<ExpectedPowerShelf> = sqlx::query_as(sql)
        .bind(bmc_mac_addresses)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))?;

    // expected_power_shelves has a unique constraint on bmc_mac_address,
    // but if the constraint gets dropped and we have multiple mac addresses,
    // we want this code to generate an Err and not silently drop values
    // and/or return nothing.
    v.into_iter()
        .into_group_map_by(|exp| exp.bmc_mac_address)
        .drain()
        .map(|(k, mut v)| {
            if v.len() > 1 {
                Err(DatabaseError::AlreadyFoundError {
                    kind: "ExpectedPowerShelf",
                    id: k.to_string(),
                })
            } else {
                Ok((k, v.pop().unwrap()))
            }
        })
        .collect()
}

pub async fn find_all(txn: &mut PgConnection) -> DatabaseResult<Vec<ExpectedPowerShelf>> {
    let sql = "SELECT * FROM expected_power_shelves";
    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_all_linked(
    txn: &mut PgConnection,
) -> DatabaseResult<Vec<LinkedExpectedPowerShelf>> {
    let sql = r#"
 SELECT
 eps.serial_number,
 eps.bmc_mac_address,
 ps.id AS power_shelf_id
FROM expected_power_shelves eps
 LEFT JOIN power_shelves ps ON eps.serial_number = ps.config->>'name'
 ORDER BY eps.bmc_mac_address
 "#;
    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
    bmc_username: String,
    bmc_password: String,
    serial_number: String,
    ip_address: Option<IpAddr>,
    metadata: Metadata,
    rack_id: Option<RackId>,
) -> DatabaseResult<ExpectedPowerShelf> {
    let query = "INSERT INTO expected_power_shelves
            (bmc_mac_address, bmc_username, bmc_password, serial_number, ip_address, metadata_name, metadata_description, metadata_labels, rack_id)
            VALUES
            ($1::macaddr, $2::varchar, $3::varchar, $4::varchar, $5::inet, $6, $7, $8::jsonb, $9) RETURNING *";

    sqlx::query_as(query)
        .bind(bmc_mac_address)
        .bind(bmc_username)
        .bind(bmc_password)
        .bind(serial_number)
        .bind(ip_address)
        .bind(metadata.name)
        .bind(metadata.description)
        .bind(sqlx::types::Json(metadata.labels))
        .bind(rack_id)
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                DatabaseError::ExpectedHostDuplicateMacAddress(bmc_mac_address)
            }
            _ => DatabaseError::query(query, err),
        })
}

pub async fn delete(bmc_mac_address: MacAddress, txn: &mut PgConnection) -> DatabaseResult<()> {
    let query = "DELETE FROM expected_power_shelves WHERE bmc_mac_address=$1";

    let result = sqlx::query(query)
        .bind(bmc_mac_address)
        .execute(txn)
        .await
        .map_err(|err| DatabaseError::query(query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_power_shelf",
            id: bmc_mac_address.to_string(),
        });
    }

    Ok(())
}

pub async fn clear(txn: &mut PgConnection) -> DatabaseResult<()> {
    let query = "DELETE FROM expected_power_shelves";

    sqlx::query(query)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|err| DatabaseError::query(query, err))
}

#[allow(clippy::too_many_arguments)]
pub async fn update<'a>(
    expected_power_shelf: &'a mut ExpectedPowerShelf,
    txn: &mut PgConnection,
    bmc_username: String,
    bmc_password: String,
    serial_number: String,
    ip_address: Option<IpAddr>,
    metadata: Metadata,
    rack_id: Option<RackId>,
) -> DatabaseResult<&'a mut ExpectedPowerShelf> {
    let query = "UPDATE expected_power_shelves SET bmc_username=$1, bmc_password=$2, serial_number=$3, ip_address=$4, metadata_name=$5, metadata_description=$6, metadata_labels=$7, rack_id=$8 WHERE bmc_mac_address=$9 RETURNING bmc_mac_address";

    let _: () = sqlx::query_as(query)
        .bind(&bmc_username)
        .bind(&bmc_password)
        .bind(&serial_number)
        .bind(ip_address)
        .bind(&metadata.name)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(rack_id)
        .bind(expected_power_shelf.bmc_mac_address)
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::RowNotFound => DatabaseError::NotFoundError {
                kind: "expected_power_shelf",
                id: expected_power_shelf.bmc_mac_address.to_string(),
            },
            _ => DatabaseError::query(query, err),
        })?;

    expected_power_shelf.serial_number = serial_number;
    expected_power_shelf.bmc_username = bmc_username;
    expected_power_shelf.bmc_password = bmc_password;
    expected_power_shelf.ip_address = ip_address;
    expected_power_shelf.metadata = metadata;
    expected_power_shelf.rack_id = rack_id;
    Ok(expected_power_shelf)
}

/// fn will insert rows that are not currently present in DB for each expected_power_shelf arg in list,
/// but will NOT overwrite existing rows matching by MAC addr.
pub async fn create_missing_from(
    txn: &mut PgConnection,
    expected_power_shelves: &[ExpectedPowerShelf],
) -> DatabaseResult<()> {
    let existing_power_shelves = find_all(txn).await?;
    let existing_map: BTreeMap<String, ExpectedPowerShelf> = existing_power_shelves
        .into_iter()
        .map(|power_shelf| (power_shelf.bmc_mac_address.to_string(), power_shelf))
        .collect();

    for expected_power_shelf in expected_power_shelves {
        if existing_map.contains_key(&expected_power_shelf.bmc_mac_address.to_string()) {
            tracing::debug!(
                "Not overwriting expected-power-shelf with mac_addr: {}",
                expected_power_shelf.bmc_mac_address.to_string()
            );
            continue;
        }

        let expected_power_shelf = expected_power_shelf.clone();
        create(
            txn,
            expected_power_shelf.bmc_mac_address,
            expected_power_shelf.bmc_username,
            expected_power_shelf.bmc_password,
            expected_power_shelf.serial_number,
            expected_power_shelf.ip_address,
            expected_power_shelf.metadata,
            expected_power_shelf.rack_id,
        )
        .await?;
    }

    Ok(())
}
