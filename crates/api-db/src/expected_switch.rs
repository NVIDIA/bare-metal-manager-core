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
use model::expected_switch::{ExpectedSwitch, ExpectedSwitchRequest, LinkedExpectedSwitch};
use sqlx::PgConnection;
use uuid::Uuid;

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

pub async fn find_by_serial_number(
    txn: &mut PgConnection,
    serial_number: &str,
) -> Result<Option<ExpectedSwitch>, DatabaseError> {
    let sql = "SELECT * FROM expected_switches WHERE serial_number=$1";
    sqlx::query_as(sql)
        .bind(serial_number)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_by_id(
    txn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<ExpectedSwitch>, DatabaseError> {
    let sql = "SELECT * FROM expected_switches WHERE expected_switch_id=$1";
    sqlx::query_as(sql)
        .bind(id)
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

/// find_all_by_rack_id returns all expected switches for a given rack_id.
pub async fn find_all_by_rack_id(
    txn: &mut PgConnection,
    rack_id: &RackId,
) -> DatabaseResult<Vec<ExpectedSwitch>> {
    let sql = "SELECT * FROM expected_switches WHERE rack_id=$1";
    sqlx::query_as(sql)
        .bind(rack_id)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_all_linked(txn: &mut PgConnection) -> DatabaseResult<Vec<LinkedExpectedSwitch>> {
    let sql = r#"
  SELECT
  es.serial_number,
  es.bmc_mac_address,
  s.id AS switch_id,
  es.expected_switch_id,
  host(ee.address) AS address,
  es.rack_id
 FROM expected_switches es
  LEFT JOIN switches s ON es.bmc_mac_address = s.bmc_mac_address
  LEFT JOIN machine_interfaces mi ON es.bmc_mac_address = mi.mac_address
  LEFT JOIN machine_interface_addresses mia ON mi.id = mia.interface_id
  LEFT JOIN explored_endpoints ee ON mia.address = ee.address
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
  s.id AS switch_id,
  es.expected_switch_id
 FROM expected_switches es
  LEFT JOIN switches s ON es.bmc_mac_address = s.bmc_mac_address
  ORDER BY es.bmc_mac_address
 LIMIT 1
 "#;
    sqlx::query_as(sql)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

/// create inserts a new expected switch record. If the id field is None,
/// a new UUID is generated.
pub async fn create(
    txn: &mut PgConnection,
    switch: ExpectedSwitch,
) -> DatabaseResult<ExpectedSwitch> {
    let id = switch.expected_switch_id.unwrap_or_else(Uuid::new_v4);
    let query = "INSERT INTO expected_switches
             (expected_switch_id, bmc_mac_address, bmc_username, bmc_password, serial_number, bmc_ip_address, metadata_name, metadata_description, rack_id, metadata_labels, nvos_username, nvos_password, nvos_mac_addresses, bmc_retain_credentials)
             VALUES
             ($1::uuid, $2::macaddr, $3::varchar, $4::varchar, $5::varchar, $6::inet, $7::varchar, $8::varchar, $9::varchar, $10::jsonb, $11::varchar, $12::varchar, $13::macaddr[], $14) RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(switch.bmc_mac_address)
        .bind(&switch.bmc_username)
        .bind(&switch.bmc_password)
        .bind(&switch.serial_number)
        .bind(switch.bmc_ip_address)
        .bind(&switch.metadata.name)
        .bind(&switch.metadata.description)
        .bind(&switch.rack_id)
        .bind(sqlx::types::Json(&switch.metadata.labels))
        .bind(&switch.nvos_username)
        .bind(&switch.nvos_password)
        .bind(&switch.nvos_mac_addresses)
        .bind(switch.bmc_retain_credentials.unwrap_or(false))
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                DatabaseError::ExpectedHostDuplicateMacAddress(switch.bmc_mac_address)
            }
            _ => DatabaseError::query(query, err),
        })
}

/// find returns an expected switch by expected_switch_id if provided,
/// otherwise by bmc_mac_address.
pub async fn find(
    txn: &mut PgConnection,
    req: &ExpectedSwitchRequest,
) -> DatabaseResult<Option<ExpectedSwitch>> {
    if let Some(id) = req.expected_switch_id {
        find_by_id(txn, id).await
    } else if let Some(mac) = req.bmc_mac_address {
        find_by_bmc_mac_address(txn, mac).await
    } else {
        Err(DatabaseError::InvalidArgument(
            "either expected_switch_id or bmc_mac_address must be provided".into(),
        ))
    }
}

/// delete deletes an expected switch by expected_switch_id if provided,
/// otherwise by bmc_mac_address.
pub async fn delete(txn: &mut PgConnection, req: &ExpectedSwitchRequest) -> DatabaseResult<()> {
    if let Some(id) = req.expected_switch_id {
        delete_by_id(txn, id).await
    } else if let Some(mac) = req.bmc_mac_address {
        delete_by_mac(txn, mac).await
    } else {
        Err(DatabaseError::InvalidArgument(
            "either expected_switch_id or bmc_mac_address must be provided".into(),
        ))
    }
}

/// delete_by_mac deletes an expected switch by bmc_mac_address.
pub async fn delete_by_mac(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<()> {
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

/// delete_by_id deletes an expected switch by expected_switch_id.
pub async fn delete_by_id(txn: &mut PgConnection, id: Uuid) -> DatabaseResult<()> {
    let query = "DELETE FROM expected_switches WHERE expected_switch_id=$1";
    let result = sqlx::query(query)
        .bind(id)
        .execute(txn)
        .await
        .map_err(|err| DatabaseError::query(query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_switch",
            id: id.to_string(),
        });
    }
    Ok(())
}

pub async fn update_nvos_mac_addresses(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
    nvos_mac_addresses: &[MacAddress],
) -> DatabaseResult<()> {
    let query = "UPDATE expected_switches SET nvos_mac_addresses = $1 WHERE bmc_mac_address = $2";
    sqlx::query(query)
        .bind(nvos_mac_addresses)
        .bind(bmc_mac_address)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|err| DatabaseError::query(query, err))
}

pub async fn clear(txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "DELETE FROM expected_switches";

    sqlx::query(query)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|err| DatabaseError::query(query, err))
}

/// update updates an existing expected switch. If expected_switch_id is set,
/// matches by ID; otherwise matches by bmc_mac_address.
pub async fn update(txn: &mut PgConnection, switch: &ExpectedSwitch) -> DatabaseResult<()> {
    let (where_clause, target_id) = match switch.expected_switch_id {
        Some(id) => ("expected_switch_id=$13::uuid", id.to_string()),
        None => (
            "bmc_mac_address=$13::macaddr",
            switch.bmc_mac_address.to_string(),
        ),
    };

    let query = format!(
        "UPDATE expected_switches \
         SET bmc_username=$1, bmc_password=$2, serial_number=$3, bmc_ip_address=$4, \
             metadata_name=$5, metadata_description=$6, metadata_labels=$7, \
             rack_id=$8, nvos_username=$9, nvos_password=$10, nvos_mac_addresses=$11::macaddr[], \
             bmc_retain_credentials=COALESCE($12, bmc_retain_credentials) \
         WHERE {where_clause}"
    );

    let result = sqlx::query(&query)
        .bind(&switch.bmc_username)
        .bind(&switch.bmc_password)
        .bind(&switch.serial_number)
        .bind(switch.bmc_ip_address)
        .bind(&switch.metadata.name)
        .bind(&switch.metadata.description)
        .bind(sqlx::types::Json(&switch.metadata.labels))
        .bind(&switch.rack_id)
        .bind(&switch.nvos_username)
        .bind(&switch.nvos_password)
        .bind(&switch.nvos_mac_addresses)
        .bind(switch.bmc_retain_credentials)
        .bind(&target_id)
        .execute(&mut *txn)
        .await
        .map_err(|err| DatabaseError::query(&query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_switch",
            id: target_id,
        });
    }
    Ok(())
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

        create(txn, expected_switch.clone()).await?;
    }

    Ok(())
}
