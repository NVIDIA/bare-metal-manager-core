/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::forge as rpc;
use chrono::prelude::*;
use itertools::Itertools;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::model::{config_version::ConfigVersion, machine::MachineState};

use super::DatabaseError;

/// Representation of an event (state transition) on a machine.
///
/// The database stores a list of the events (and not state changes).  The state machine in the
/// database schema converts the state machine edges into a `current state` representation.  For
/// instance, creating an event called `adopt` on a Machine where the last event is `discover` will
/// result in a MachineState of `adopted`
///
#[derive(Debug)]
pub struct MachineStateHistory {
    /// The numeric identifier of the event, this should not be exposed to consumers of this API,
    /// it is not secure.
    id: i64,

    /// The UUID of the machine that the event Applies to (due to Rust self-referential rules
    /// around circular references, this is a UUID, not a machine type).
    machine_id: uuid::Uuid,

    /// The action that was performed
    pub state: MachineState,
    pub state_version: ConfigVersion,

    /// The timestamp of the event
    timestamp: DateTime<Utc>,
}

/// Conversion from a MachineEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<MachineStateHistory> for rpc::MachineEvent {
    fn from(event: MachineStateHistory) -> rpc::MachineEvent {
        rpc::MachineEvent {
            id: event.id,
            machine_id: Some(event.machine_id.into()),
            time: Some(event.timestamp.into()),
            event: event.state.to_string(),
        }
    }
}

impl<'r> FromRow<'r, PgRow> for MachineStateHistory {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let state_version_str: &str = row.try_get("state_version")?;
        let state_version = state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let state: sqlx::types::Json<MachineState> = row.try_get("state")?;
        Ok(MachineStateHistory {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            state: state.0,
            state_version,
            timestamp: row.try_get("timestamp")?,
        })
    }
}

impl MachineStateHistory {
    /// Find a list of MachineEvents given a list of machine Uuids.
    ///
    /// It returns a [HashMap][std::collections::HashMap] keyed by the machine Uuid and values of
    /// all the events.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to an open Transaction
    ///
    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        ids: &[uuid::Uuid],
    ) -> Result<HashMap<uuid::Uuid, Vec<Self>>, DatabaseError> {
        let query = "SELECT * FROM machine_state_history WHERE machine_id=ANY($1)";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(ids)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            .into_iter()
            .into_group_map_by(|event| event.machine_id))
    }

    pub async fn for_machine(
        txn: &mut Transaction<'_, Postgres>,
        id: &uuid::Uuid,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * FROM machine_state_history WHERE machine_id=$1::uuid";
        sqlx::query_as::<_, Self>(query)
            .bind(id)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    // Store each event for debugging purpose.
    pub async fn persist(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
        state: MachineState,
        state_version: ConfigVersion,
    ) -> Result<Self, DatabaseError> {
        let query =
            "INSERT INTO machine_state_history (machine_id, state, state_version) VALUES ($1, $2, $3) RETURNING *";
        sqlx::query_as::<_, Self>(query)
            .bind(machine_id)
            .bind(sqlx::types::Json(state))
            .bind(state_version.to_version_string())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
