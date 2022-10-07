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
use std::convert::TryFrom;

use ipnetwork::IpNetwork;
use rust_fsm::StateMachine;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use ::rpc::forge as rpc;
use ::rpc::VpcResourceStateMachine;
use ::rpc::VpcResourceStateMachineInput;

use crate::db::network_prefix_event::NetworkPrefixEvent;
use crate::db::vpc_resource_action::VpcResourceAction;
use crate::db::vpc_resource_state::VpcResourceState;
use crate::db::UuidKeyedObjectFilter;
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Clone)]
pub struct NetworkPrefix {
    pub id: uuid::Uuid,
    pub segment_id: Uuid,
    pub prefix: IpNetwork,
    pub gateway: Option<IpNetwork>,
    pub num_reserved: i32,
    state: VpcResourceState,
    events: Vec<NetworkPrefixEvent>,
}

#[derive(Debug)]
pub struct NewNetworkPrefix {
    pub prefix: IpNetwork,
    pub gateway: Option<IpNetwork>,
    pub num_reserved: i32,
}

impl<'r> FromRow<'r, PgRow> for NetworkPrefix {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(NetworkPrefix {
            id: row.try_get("id")?,
            segment_id: row.try_get("segment_id")?,
            prefix: row.try_get("prefix")?,
            gateway: row.try_get("gateway")?,
            num_reserved: row.try_get("num_reserved")?,
            state: VpcResourceState::Init,
            events: Vec::new(),
        })
    }
}

impl TryFrom<rpc::NetworkPrefix> for NewNetworkPrefix {
    type Error = CarbideError;

    fn try_from(value: rpc::NetworkPrefix) -> Result<Self, Self::Error> {
        if let Some(_id) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Network Prefix",
            )));
        }

        Ok(NewNetworkPrefix {
            prefix: value.prefix.parse()?,
            gateway: match value.gateway {
                Some(g) => Some(g.parse()?),
                None => None,
            },
            num_reserved: value.reserve_first,
        })
    }
}

impl From<NetworkPrefix> for rpc::NetworkPrefix {
    fn from(src: NetworkPrefix) -> Self {
        rpc::NetworkPrefix {
            id: Some(src.id.into()),
            prefix: src.prefix.to_string(),
            gateway: src.gateway.map(|v| v.to_string()),
            reserve_first: src.num_reserved,
            state: Some(src.state.into()),
            events: src.events.iter().map(|event| event.into()).collect(),
        }
    }
}

impl NetworkPrefix {
    // Search for specific prefix
    #[tracing::instrument(skip(txn))]
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        uuid: uuid::Uuid,
    ) -> CarbideResult<NetworkPrefix> {
        Ok(
            sqlx::query_as::<_, NetworkPrefix>("select * from network_prefixes where id=$1")
                .bind(uuid)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
    /*
     * Return a list of `NetworkPrefix`es for a segment.
     */
    #[tracing::instrument(skip(filter))]
    pub async fn find_by_segment(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<NetworkPrefix>> {
        let base_query = "SELECT * FROM network_prefixes {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkPrefix>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, NetworkPrefix>(
                    &base_query.replace("{where}", "WHERE segment_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, NetworkPrefix>(
                    &base_query.replace("{where}", "WHERE segment_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        })
    }

    pub fn events(&self) -> &Vec<NetworkPrefixEvent> {
        &self.events
    }

    /// Return the current state of the machine based on the sequence of events the machine has
    /// experienced.
    ///
    /// This object does not store the current state, but calculates it from the actions that have
    /// been performed on the machines.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn current_state(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<VpcResourceState> {
        let events = NetworkPrefixEvent::for_network_prefix(txn, &self.id).await?;
        let state_machine = self.state_machine(&events)?;
        Ok(VpcResourceState::from(state_machine.state()))
    }

    fn state_machine(
        &self,
        events: &[NetworkPrefixEvent],
    ) -> CarbideResult<StateMachine<VpcResourceStateMachine>> {
        let mut machine: StateMachine<VpcResourceStateMachine> = StateMachine::new();
        events
            .iter()
            .map(|event| machine.consume(&VpcResourceStateMachineInput::from(&event.action)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CarbideError::InvalidState)?;

        Ok(machine)
    }

    /// Perform an arbitrary action to a Machine and advance it to the next state given the last
    /// state.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `action` - A reference to a VpcResourceAction enum
    ///
    pub async fn advance(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        action: &VpcResourceStateMachineInput,
    ) -> CarbideResult<bool> {
        // first validate the state change by getting the current state in the db
        let events = NetworkPrefixEvent::for_network_prefix(txn, &self.id).await?;
        let mut state_machine = self.state_machine(&events)?;
        state_machine
            .consume(action)
            .map_err(CarbideError::InvalidState)?;

        let id: (i64, ) = sqlx::query_as(
            "INSERT INTO network_prefix_events (network_prefix_id, action) VALUES ($1::uuid, $2) RETURNING id",
        )
            .bind(self.id)
            .bind(VpcResourceAction::from(action))
            .fetch_one(txn)
            .await?;

        log::info!("Event ID is {}", id.0);

        Ok(true)
    }

    /*
     * Create a prefix for a given segment id.
     *
     * Since this function will perform muliple inserts() it wraps the actions in a sub-transaction
     * and rolls it back if any of the inserts fail and wont leave half of them written.
     *
     * # Parameters
     *
     * txn: An in-progress transaction on a connection pool
     * segment: The UUID of a network segment, must already exist and be visible to this
     * transcation
     * prefixes: A slice of the `NewNetworkPrefix` to create.
     */
    pub async fn create_for(
        txn: &mut Transaction<'_, Postgres>,
        segment: &uuid::Uuid,
        prefixes: &[NewNetworkPrefix],
    ) -> CarbideResult<Vec<NetworkPrefix>> {
        let mut inner_transaction = txn.begin().await?;

        // https://github.com/launchbadge/sqlx/issues/294
        //
        // No way to insert multiple rows easily.  This is more readable than some hack to save
        // tiny amounts of time.
        //
        let mut inserted_prefixes: Vec<NetworkPrefix> = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let new_prefix: NetworkPrefix = sqlx::query_as("INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved) VALUES ($1::uuid, $2::cidr, $3::inet, $4::integer) RETURNING *")
                .bind(segment)
                .bind(prefix.prefix)
                .bind(prefix.gateway)
                .bind(prefix.num_reserved)
                .fetch_one(&mut *inner_transaction).await?;

            new_prefix
                .advance(
                    &mut inner_transaction,
                    &VpcResourceStateMachineInput::Initialize,
                )
                .await?;

            inserted_prefixes.push(new_prefix);
        }

        inner_transaction.commit().await?;

        Ok(inserted_prefixes)
    }
}
