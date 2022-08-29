use rust_fsm::StateMachine;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use ::rpc::VpcResourceStateMachine;
use ::rpc::VpcResourceStateMachineInput;

use crate::db::vpc_resource_action::VpcResourceAction;
use crate::db::vpc_resource_leaf_event::VpcResourceLeafEvent;
use crate::db::vpc_resource_state::VpcResourceState;
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VpcResourceLeaf {
    id: uuid::Uuid,
    state: VpcResourceState,
    events: Vec<VpcResourceLeafEvent>,
}

#[derive(Debug, Default)]
pub struct NewVpcResourceLeaf {}

impl<'r> FromRow<'r, PgRow> for VpcResourceLeaf {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(VpcResourceLeaf {
            id: row.try_get("id")?,
            state: VpcResourceState::Init,
            events: Vec::new(),
        })
    }
}

impl VpcResourceLeaf {
    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        name: uuid::Uuid,
    ) -> CarbideResult<VpcResourceLeaf> {
        Ok(
            sqlx::query_as("SELECT * from vpc_resource_leafs WHERE id = $1")
                .bind(name)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
    pub async fn current_state(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<VpcResourceState> {
        let events = VpcResourceLeafEvent::for_leaf(txn, &self.id).await?;
        let state_machine = self.state_machine(&events)?;
        Ok(VpcResourceState::from(state_machine.state()))
    }

    fn state_machine(
        &self,
        events: &[VpcResourceLeafEvent],
    ) -> CarbideResult<StateMachine<VpcResourceStateMachine>> {
        let mut machine: StateMachine<VpcResourceStateMachine> = StateMachine::new();
        events
            .iter()
            .map(|event| machine.consume(&VpcResourceStateMachineInput::from(&event.action)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CarbideError::InvalidState)?;

        Ok(machine)
    }

    pub async fn advance(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        action: &VpcResourceStateMachineInput,
    ) -> CarbideResult<bool> {
        // first validate the state change by getting the current state in the db
        let events = VpcResourceLeafEvent::for_leaf(&mut *txn, &self.id).await?;
        let mut state_machine = self.state_machine(&events)?;
        state_machine
            .consume(action)
            .map_err(CarbideError::InvalidState)?;

        let id: (i64, ) = sqlx::query_as(
            "INSERT INTO vpc_resource_leaf_events (vpc_leaf_id, action) VALUES ($1::uuid, $2) RETURNING id",
        )
            .bind(self.id())
            .bind(VpcResourceAction::from(action))
            .fetch_one(&mut *txn)
            .await?;

        log::info!("Event ID is {}", id.0);

        Ok(true)
    }
    /// Returns the UUID of the machine object
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Returns the list of Events the machine has experienced
    pub fn events(&self) -> &[VpcResourceLeafEvent] {
        &self.events
    }
}

impl NewVpcResourceLeaf {
    pub fn new() -> NewVpcResourceLeaf {
        Self {}
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<VpcResourceLeaf> {
        let (vpc_resource_id,) =
            sqlx::query_as("INSERT INTO vpc_resource_leafs DEFAULT VALUES returning id")
                .fetch_one(&mut *txn)
                .await?;

        let vpc_resource = VpcResourceLeaf::find(txn, vpc_resource_id).await?;

        // After Leaf object is created, set initial state of VpcResourceStateMachine
        vpc_resource
            .advance(txn, &VpcResourceStateMachineInput::Initialize)
            .await?;

        Ok(vpc_resource)
    }
}
