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

use carbide_uuid::rack::RackId;
use itertools::Itertools;
use mac_address::MacAddress;
use model::expected_switch::{ExpectedSwitch, LinkedExpectedSwitch};
use model::metadata::Metadata;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "expected_switches_bmc_mac_address_key";
pub async fn find_by_bmc_mac_address(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
) -> Result<Option<ExpectedSwitch>, DatabaseError> {
    let sql = "SELECT * FROM expected_switches WHERE bmc_mac_address=$1";
    sqlx::query_as(sql)
        .bind(bmc_mac_address)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_by_rack_id(
    txn: &mut PgConnection,
    rack_id: String,
) -> Result<Option<ExpectedSwitch>, DatabaseError> {
    let sql = "SELECT * FROM expected_switches WHERE rack_id=$1";
    sqlx::query_as(sql)
        .bind(rack_id)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_many_by_bmc_mac_address(
    txn: &mut PgConnection,
    bmc_mac_addresses: &[MacAddress],
) -> DatabaseResult<HashMap<MacAddress, ExpectedSwitch>> {
    let sql = "SELECT * FROM expected_switches WHERE bmc_mac_address=ANY($1)";
    let v: Vec<ExpectedSwitch> = sqlx::query_as(sql)
        .bind(bmc_mac_addresses)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))?;

    // expected_switches has a unique constraint on bmc_mac_address,
    // but if the constraint gets dropped and we have multiple mac addresses,
    // we want this code to generate an Err and not silently drop values
    // and/or return nothing.
    v.into_iter()
        .into_group_map_by(|exp| exp.bmc_mac_address)
        .drain()
        .map(|(k, mut v)| {
            if v.len() > 1 {
                Err(DatabaseError::AlreadyFoundError {
                    kind: "ExpectedSwitch",
                    id: k.to_string(),
                })
            } else {
                Ok((k, v.pop().unwrap()))
            }
        })
        .collect()
}

pub async fn find_all(txn: &mut PgConnection) -> DatabaseResult<Vec<ExpectedSwitch>> {
    let sql = "SELECT * FROM expected_switches";
    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_all_linked(txn: &mut PgConnection) -> DatabaseResult<Vec<LinkedExpectedSwitch>> {
    let sql = r#"
  SELECT
  es.serial_number,
  es.bmc_mac_address,
  s.id AS switch_id
 FROM expected_switches es
  LEFT JOIN switches s ON es.serial_number = s.config->>'name'
  ORDER BY es.bmc_mac_address
  "#;
    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_one_linked(
    txn: &mut PgConnection,
) -> DatabaseResult<Option<LinkedExpectedSwitch>> {
    let sql = r#"
  SELECT
  es.serial_number,
  es.bmc_mac_address,
  s.id AS switch_id
 FROM expected_switches es
  LEFT JOIN switches s ON es.serial_number = s.config->>'name'
  ORDER BY es.bmc_mac_address
 LIMIT 1
 "#;
    sqlx::query_as(sql)
        .fetch_optional(txn)
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
    metadata: Metadata,
    rack_id: Option<RackId>,
    nvos_username: Option<String>,
    nvos_password: Option<String>,
) -> DatabaseResult<ExpectedSwitch> {
    let query = "INSERT INTO expected_switches
             (bmc_mac_address, bmc_username, bmc_password, serial_number, metadata_name, metadata_description, rack_id, metadata_labels, nvos_username, nvos_password)
             VALUES
             ($1::macaddr, $2::varchar, $3::varchar, $4::varchar, $5::varchar, $6::varchar, $7::varchar, $8::jsonb, $9::varchar, $10::varchar) RETURNING *";

    sqlx::query_as(query)
        .bind(bmc_mac_address)
        .bind(bmc_username)
        .bind(bmc_password)
        .bind(serial_number)
        .bind(metadata.name)
        .bind(metadata.description)
        .bind(rack_id)
        .bind(sqlx::types::Json(metadata.labels))
        .bind(nvos_username)
        .bind(nvos_password)
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
    let query = "DELETE FROM expected_switches WHERE bmc_mac_address=$1";

    let result = sqlx::query(query)
        .bind(bmc_mac_address)
        .execute(txn)
        .await
        .map_err(|err| DatabaseError::query(query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_switch",
            id: bmc_mac_address.to_string(),
        });
    }

    Ok(())
}

pub async fn clear(txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "DELETE FROM expected_switches";

    sqlx::query(query)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|err| DatabaseError::query(query, err))
}

#[allow(clippy::too_many_arguments)]
pub async fn update<'a>(
    expected_switch: &'a mut ExpectedSwitch,
    txn: &mut PgConnection,
    bmc_username: String,
    bmc_password: String,
    serial_number: String,
    metadata: Metadata,
    rack_id: Option<RackId>,
    nvos_username: Option<String>,
    nvos_password: Option<String>,
) -> DatabaseResult<&'a mut ExpectedSwitch> {
    let query = "UPDATE expected_switches SET bmc_username=$1, bmc_password=$2, serial_number=$3, metadata_name=$4, metadata_description=$5, metadata_labels=$6, rack_id=$7 , nvos_username=$8, nvos_password=$9 WHERE bmc_mac_address=$10 RETURNING bmc_mac_address";

    let _: () = sqlx::query_as(query)
        .bind(&bmc_username)
        .bind(&bmc_password)
        .bind(&serial_number)
        .bind(&metadata.name)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(rack_id)
        .bind(&nvos_username)
        .bind(&nvos_password)
        .bind(expected_switch.bmc_mac_address)
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::RowNotFound => DatabaseError::NotFoundError {
                kind: "expected_switch",
                id: expected_switch.bmc_mac_address.to_string(),
            },
            _ => DatabaseError::query(query, err),
        })?;

    expected_switch.serial_number = serial_number;
    expected_switch.bmc_username = bmc_username;
    expected_switch.bmc_password = bmc_password;
    expected_switch.metadata = metadata;
    expected_switch.rack_id = rack_id;
    Ok(expected_switch)
}

/// fn will insert rows that are not currently present in DB for each expected_switch arg in list,
/// but will NOT overwrite existing rows matching by MAC addr.
pub async fn create_missing_from(
    txn: &mut PgConnection,
    expected_switches: &[ExpectedSwitch],
) -> DatabaseResult<()> {
    let existing_switches = find_all(txn).await?;
    let existing_map: BTreeMap<String, ExpectedSwitch> = existing_switches
        .into_iter()
        .map(|switch| (switch.bmc_mac_address.to_string(), switch))
        .collect();

    for expected_switch in expected_switches {
        if existing_map.contains_key(&expected_switch.bmc_mac_address.to_string()) {
            tracing::debug!(
                "Not overwriting expected-switch with mac_addr: {}",
                expected_switch.bmc_mac_address.to_string()
            );
            continue;
        }

        let expected_switch = expected_switch.clone();
        create(
            txn,
            expected_switch.bmc_mac_address,
            expected_switch.bmc_username,
            expected_switch.bmc_password,
            expected_switch.serial_number,
            expected_switch.metadata,
            expected_switch.rack_id,
            expected_switch.nvos_username,
            expected_switch.nvos_password,
        )
        .await?;
    }

    Ok(())
}
