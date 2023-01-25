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
use sqlx::{FromRow, Postgres, Transaction};

use super::DatabaseError;

/// Possible Events for Machine state-machine implementation
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "machine_action")]
#[sqlx(rename_all = "lowercase")]
pub enum MachineAction {
    Discover,
    Commission,
    Assign,
    Unassign,
    Fail,
    Recommission,
    Decommission,
    Release,
}

impl From<MachineAction> for rpc::MachineAction {
    fn from(src: MachineAction) -> Self {
        match src {
            MachineAction::Discover => rpc::MachineAction::Discover,
            MachineAction::Commission => rpc::MachineAction::Commission,
            MachineAction::Assign => rpc::MachineAction::Assign,
            MachineAction::Unassign => rpc::MachineAction::Unassign,
            MachineAction::Fail => rpc::MachineAction::Fail,
            MachineAction::Recommission => rpc::MachineAction::Recommission,
            MachineAction::Decommission => rpc::MachineAction::Decommission,
            MachineAction::Release => rpc::MachineAction::Release,
        }
    }
}

impl std::fmt::Display for MachineAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Representation of an event (state transition) on a machine.
///
/// The database stores a list of the events (and not state changes).  The state machine in the
/// database schema converts the state machine edges into a `current state` representation.  For
/// instance, creating an event called `adopt` on a Machine where the last event is `discover` will
/// result in a MachineState of `adopted`
///
#[derive(Debug, FromRow)]
pub struct MachineEvent {
    /// The numeric identifier of the event, this should not be exposed to consumers of this API,
    /// it is not secure.
    id: i64,

    /// The UUID of the machine that the event Applies to (due to Rust self-referential rules
    /// around circular references, this is a UUID, not a machine type).
    machine_id: uuid::Uuid,

    /// The action that was performed
    pub action: MachineAction,

    /// The timestamp of the event
    timestamp: DateTime<Utc>,
}

/// Conversion from a MachineEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<MachineEvent> for rpc::MachineEvent {
    fn from(event: MachineEvent) -> rpc::MachineEvent {
        let mut proto_event = rpc::MachineEvent {
            id: event.id,
            machine_id: Some(event.machine_id.into()),
            time: Some(event.timestamp.into()),
            event: 0, // 0 is usually null in protobuf I guess
        };

        proto_event.set_event(event.action.into());

        proto_event
    }
}

impl MachineEvent {
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
        let query = "SELECT * FROM machine_events WHERE machine_id=ANY($1)";
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
        let query = "SELECT * FROM machine_events WHERE machine_id=$1::uuid";
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
        action: MachineAction,
    ) -> Result<Self, DatabaseError> {
        let query = "INSERT INTO machine_events (machine_id, action) VALUES ($1, $2) RETURNING *";
        sqlx::query_as::<_, Self>(query)
            .bind(machine_id)
            .bind(action)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
