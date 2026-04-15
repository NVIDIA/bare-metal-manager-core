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
use model::expected_machine::{ExpectedMachine, ExpectedMachineRequest, LinkedExpectedMachine};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "expected_machines_bmc_mac_address_key";

pub async fn find_by_bmc_mac_address(
    txn: impl DbReader<'_>,
    bmc_mac_address: MacAddress,
) -> Result<Option<ExpectedMachine>, DatabaseError> {
    let sql = "SELECT * FROM expected_machines WHERE bmc_mac_address=$1";
    sqlx::query_as(sql)
        .bind(bmc_mac_address)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_by_id(
    txn: impl DbReader<'_>,
    id: Uuid,
) -> Result<Option<ExpectedMachine>, DatabaseError> {
    let sql = "SELECT * FROM expected_machines WHERE id=$1";
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_many_by_bmc_mac_address(
    txn: &mut PgConnection,
    bmc_mac_addresses: &[MacAddress],
) -> DatabaseResult<HashMap<MacAddress, ExpectedMachine>> {
    let sql = "SELECT * FROM expected_machines WHERE bmc_mac_address=ANY($1)";
    let v: Vec<ExpectedMachine> = sqlx::query_as(sql)
        .bind(bmc_mac_addresses)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))?;

    // expected_machines has a unique constraint on bmc_mac_address,
    // but if the constraint gets dropped and we have multiple mac addresses,
    // we want this code to generate an Err and not silently drop values
    // and/or return nothing.
    v.into_iter()
        .into_group_map_by(|exp| exp.bmc_mac_address)
        .drain()
        .map(|(k, mut v)| {
            if v.len() > 1 {
                Err(DatabaseError::AlreadyFoundError {
                    kind: "ExpectedMachine",
                    id: k.to_string(),
                })
            } else {
                Ok((k, v.pop().unwrap()))
            }
        })
        .collect()
}

// the expected machines table needs host mac addresses to control dhcp vending of ip's
// since the carbide dhcp server in some cases is not authoritative on a large network.
// search in the host_nics field before vending an ip.
pub async fn find_by_host_mac_address(
    txn: &mut PgConnection,
    host_mac_address: MacAddress,
) -> DatabaseResult<Option<ExpectedMachine>> {
    let sql = "SELECT * FROM expected_machines WHERE host_nics->>'mac_address'=$1";
    sqlx::query_as(sql)
        .bind(host_mac_address.to_string().to_ascii_lowercase())
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_one_linked(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<Option<LinkedExpectedMachine>> {
    let sql = r#"
 SELECT
 em.serial_number,
 em.bmc_mac_address,
 mi.id AS interface_id,
 host(ee.address) AS address,
 mt.machine_id,
 em.id AS expected_machine_id
FROM expected_machines em
 LEFT JOIN machine_interfaces mi ON em.bmc_mac_address = mi.mac_address
 LEFT JOIN machine_interface_addresses mia ON mi.id = mia.interface_id
 LEFT JOIN explored_endpoints ee ON mia.address = ee.address
 LEFT JOIN machine_topologies mt ON host(ee.address) = mt.topology->'bmc_info'->>'ip'
 WHERE em.bmc_mac_address = $1
 ORDER BY em.bmc_mac_address
 "#;
    sqlx::query_as(sql)
        .bind(bmc_mac_address)
        .fetch_optional(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_all(txn: impl DbReader<'_>) -> DatabaseResult<Vec<ExpectedMachine>> {
    let sql = "SELECT * FROM expected_machines";
    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

/// find_all_by_rack_id returns all expected machines for a given rack_id.
pub async fn find_all_by_rack_id(
    txn: &mut PgConnection,
    rack_id: &RackId,
) -> DatabaseResult<Vec<ExpectedMachine>> {
    let sql = "SELECT * FROM expected_machines WHERE rack_id=$1";
    sqlx::query_as(sql)
        .bind(rack_id)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn find_all_linked(txn: impl DbReader<'_>) -> DatabaseResult<Vec<LinkedExpectedMachine>> {
    let sql = r#"
 SELECT
 em.serial_number,
 em.bmc_mac_address,
 mi.id AS interface_id,
 host(ee.address) AS address,
 mt.machine_id,
 em.id AS expected_machine_id
FROM expected_machines em
 LEFT JOIN machine_interfaces mi ON em.bmc_mac_address = mi.mac_address
 LEFT JOIN machine_interface_addresses mia ON mi.id = mia.interface_id
 LEFT JOIN explored_endpoints ee ON mia.address = ee.address
 LEFT JOIN machine_topologies mt ON host(ee.address) = mt.topology->'bmc_info'->>'ip'
 ORDER BY em.bmc_mac_address
 "#;
    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(sql, err))
}

pub async fn update_bmc_credentials<'a>(
    value: &'a mut ExpectedMachine,
    txn: &mut PgConnection,
    bmc_username: String,
    bmc_password: String,
) -> DatabaseResult<&'a mut ExpectedMachine> {
    let query = "UPDATE expected_machines SET bmc_username=$1, bmc_password=$2 WHERE bmc_mac_address=$3 RETURNING bmc_mac_address";

    sqlx::query_as::<_, ()>(query)
        .bind(&bmc_username)
        .bind(&bmc_password)
        .bind(value.bmc_mac_address)
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::RowNotFound => DatabaseError::NotFoundError {
                kind: "expected_machine",
                id: value.bmc_mac_address.to_string(),
            },
            _ => DatabaseError::query(query, err),
        })?;

    value.data.bmc_username = bmc_username;
    value.data.bmc_password = bmc_password;

    Ok(value)
}

/// Inserts a new expected machine row. If the id field is None, a new UUID is generated.
///
/// Persisted `bmc_ip_address` is the configured static BMC IP; the API layer is responsible for
/// creating/updating the matching `machine_interface` rows before calling this (see
/// `preallocate_machine_interface` / `update_preallocated_machine_interface`).
pub async fn create(
    txn: &mut PgConnection,
    machine: ExpectedMachine,
) -> DatabaseResult<ExpectedMachine> {
    let id = machine.id.unwrap_or_else(Uuid::new_v4);
    let query = "INSERT INTO expected_machines
            (id, bmc_mac_address, bmc_username, bmc_password, serial_number, fallback_dpu_serial_numbers, metadata_name, metadata_description, metadata_labels, sku_id, host_nics, rack_id, default_pause_ingestion_and_poweron, dpf_enabled, bmc_ip_address, bmc_retain_credentials)
            VALUES
            ($1::uuid, $2::macaddr, $3::varchar, $4::varchar, $5::varchar, $6::text[], $7, $8, $9::jsonb, $10::varchar, $11::jsonb, $12, $13, $14, $15::inet, $16) RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(machine.bmc_mac_address)
        .bind(&machine.data.bmc_username)
        .bind(&machine.data.bmc_password)
        .bind(&machine.data.serial_number)
        .bind(&machine.data.fallback_dpu_serial_numbers)
        .bind(&machine.data.metadata.name)
        .bind(&machine.data.metadata.description)
        .bind(sqlx::types::Json(&machine.data.metadata.labels))
        .bind(&machine.data.sku_id)
        .bind(sqlx::types::Json(&machine.data.host_nics))
        .bind(&machine.data.rack_id)
        .bind(
            machine
                .data
                .default_pause_ingestion_and_poweron
                .unwrap_or(false),
        )
        .bind(machine.data.dpf_enabled.unwrap_or_default())
        .bind(machine.data.bmc_ip_address)
        .bind(machine.data.bmc_retain_credentials.unwrap_or(false))
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                DatabaseError::ExpectedHostDuplicateMacAddress(machine.bmc_mac_address)
            }
            _ => DatabaseError::query(query, err),
        })
}

/// find returns an expected machine by id if provided, otherwise by bmc_mac_address.
pub async fn find(
    txn: impl DbReader<'_>,
    req: &ExpectedMachineRequest,
) -> DatabaseResult<Option<ExpectedMachine>> {
    if let Some(id) = req.id {
        find_by_id(txn, id).await
    } else if let Some(mac) = req.bmc_mac_address {
        find_by_bmc_mac_address(txn, mac).await
    } else {
        Err(DatabaseError::InvalidArgument(
            "either id or bmc_mac_address must be provided".into(),
        ))
    }
}

/// delete deletes an expected machine by id if provided, otherwise by bmc_mac_address.
pub async fn delete(txn: &mut PgConnection, req: &ExpectedMachineRequest) -> DatabaseResult<()> {
    if let Some(id) = req.id {
        delete_by_id(txn, id).await
    } else if let Some(mac) = req.bmc_mac_address {
        delete_by_mac(txn, mac).await
    } else {
        Err(DatabaseError::InvalidArgument(
            "either id or bmc_mac_address must be provided".into(),
        ))
    }
}

/// delete_by_mac deletes an expected machine by bmc_mac_address.
pub async fn delete_by_mac(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<()> {
    let query = "DELETE FROM expected_machines WHERE bmc_mac_address=$1";

    let result = sqlx::query(query)
        .bind(bmc_mac_address)
        .execute(txn)
        .await
        .map_err(|err| DatabaseError::query(query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_machine",
            id: bmc_mac_address.to_string(),
        });
    }

    Ok(())
}

pub async fn delete_by_id(txn: &mut PgConnection, id: Uuid) -> DatabaseResult<()> {
    let query = "DELETE FROM expected_machines WHERE id=$1";

    let result = sqlx::query(query)
        .bind(id)
        .execute(txn)
        .await
        .map_err(|err| DatabaseError::query(query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_machine",
            id: id.to_string(),
        });
    }

    Ok(())
}

pub async fn clear(txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "DELETE FROM expected_machines";

    sqlx::query(query)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Updates an existing expected machine. If id is set, matches by ID; otherwise matches by
/// `bmc_mac_address`. Includes `bmc_ip_address` when the operator configures a static BMC IP.
pub async fn update(txn: &mut PgConnection, machine: &ExpectedMachine) -> DatabaseResult<()> {
    let (where_clause, target_id) = match machine.id {
        Some(id) => ("id=$15::uuid", id.to_string()),
        None => (
            "bmc_mac_address=$15::macaddr",
            machine.bmc_mac_address.to_string(),
        ),
    };

    let query = format!(
        "UPDATE expected_machines \
         SET bmc_username=$1, bmc_password=$2, serial_number=$3, \
             fallback_dpu_serial_numbers=$4, metadata_name=$5, metadata_description=$6, \
             metadata_labels=$7, sku_id=$8, host_nics=$9::jsonb, rack_id=$10, \
             default_pause_ingestion_and_poweron=COALESCE($11, default_pause_ingestion_and_poweron), \
             dpf_enabled=COALESCE($12, dpf_enabled), \
             bmc_ip_address=$13, \
             bmc_retain_credentials=COALESCE($14, bmc_retain_credentials) \
         WHERE {where_clause}"
    );

    let result = sqlx::query(&query)
        .bind(&machine.data.bmc_username)
        .bind(&machine.data.bmc_password)
        .bind(&machine.data.serial_number)
        .bind(&machine.data.fallback_dpu_serial_numbers)
        .bind(&machine.data.metadata.name)
        .bind(&machine.data.metadata.description)
        .bind(sqlx::types::Json(&machine.data.metadata.labels))
        .bind(&machine.data.sku_id)
        .bind(sqlx::types::Json(&machine.data.host_nics))
        .bind(&machine.data.rack_id)
        .bind(machine.data.default_pause_ingestion_and_poweron)
        .bind(machine.data.dpf_enabled)
        .bind(machine.data.bmc_ip_address)
        .bind(machine.data.bmc_retain_credentials)
        .bind(&target_id)
        .execute(&mut *txn)
        .await
        .map_err(|err| DatabaseError::query(&query, err))?;

    if result.rows_affected() == 0 {
        return Err(DatabaseError::NotFoundError {
            kind: "expected_machine",
            id: target_id,
        });
    }
    Ok(())
}

/// fn will insert rows that are not currently present in DB for each expected_machine arg in list,
/// but will NOT overwrite existing rows matching by MAC addr.
pub async fn create_missing_from(
    txn: &mut PgConnection,
    expected_machines: &[ExpectedMachine],
) -> DatabaseResult<()> {
    let existing_machines = find_all(&mut *txn).await?;
    let existing_map: BTreeMap<String, ExpectedMachine> = existing_machines
        .into_iter()
        .map(|machine| (machine.bmc_mac_address.to_string(), machine))
        .collect();

    for expected_machine in expected_machines {
        if existing_map.contains_key(&expected_machine.bmc_mac_address.to_string()) {
            tracing::debug!(
                "Not overwriting expected-machine with mac_addr: {}",
                expected_machine.bmc_mac_address.to_string()
            );
            continue;
        }

        create(txn, expected_machine.clone()).await?;
    }

    Ok(())
}
