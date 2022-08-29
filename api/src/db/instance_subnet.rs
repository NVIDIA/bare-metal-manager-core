use rust_fsm::StateMachine;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use ::rpc::VpcResourceStateMachine;
use ::rpc::VpcResourceStateMachineInput;
use rpc::forge::v0 as rpc;

use crate::db::instance::Instance;
use crate::db::instance_subnet_address::InstanceSubnetAddress;
use crate::db::instance_subnet_event::InstanceSubnetEvent;
use crate::db::machine_interface::MachineInterface;
use crate::db::network_segment::NetworkSegment;
use crate::db::vpc_resource_action::VpcResourceAction;
use crate::db::vpc_resource_state::VpcResourceState;
use crate::{CarbideError, CarbideResult};

#[derive(Debug)]
pub struct InstanceSubnet {
    id: uuid::Uuid,
    machine_interface_id: uuid::Uuid,
    network_segment_id: uuid::Uuid,
    instance_id: uuid::Uuid,
    vf_id: Option<i32>,
    addresses: Vec<InstanceSubnetAddress>,
    state: VpcResourceState,
    events: Vec<InstanceSubnetEvent>,
}

impl<'r> FromRow<'r, PgRow> for InstanceSubnet {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(InstanceSubnet {
            id: row.try_get("id")?,
            machine_interface_id: row.try_get("machine_interface_id")?,
            network_segment_id: row.try_get("network_segment_id")?,
            instance_id: row.try_get("instance_id")?,
            vf_id: row.try_get("vfid")?,
            addresses: Vec::new(),
            state: VpcResourceState::Init,
            events: Vec::new(),
        })
    }
}

impl From<InstanceSubnet> for rpc::InstanceSubnet {
    fn from(instance_subnet: InstanceSubnet) -> Self {
        rpc::InstanceSubnet {
            id: Some(instance_subnet.id.into()),
            machine_interface_id: Some(instance_subnet.machine_interface_id.into()),
            network_segment_id: Some(instance_subnet.network_segment_id.into()),
            instance_id: Some(instance_subnet.instance_id.into()),
            vfid: instance_subnet.vf_id,
            addresses: instance_subnet
                .addresses
                .iter()
                .map(|addr| addr.address.to_string())
                .collect(),
            state: Some(instance_subnet.state.into()),
            events: instance_subnet
                .events
                .into_iter()
                .map(|e| e.into())
                .collect(),
        }
    }
}

impl InstanceSubnet {
    pub async fn current_state(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<VpcResourceState> {
        let events = InstanceSubnetEvent::for_instance_subnet(txn, &self.id).await?;
        let state_machine = self.state_machine(&events)?;
        Ok(VpcResourceState::from(state_machine.state()))
    }

    fn state_machine(
        &self,
        events: &[InstanceSubnetEvent],
    ) -> CarbideResult<StateMachine<VpcResourceStateMachine>> {
        let mut instance_subnet: StateMachine<VpcResourceStateMachine> = StateMachine::new();
        events
            .iter()
            .map(|event| {
                instance_subnet.consume(&VpcResourceStateMachineInput::from(&event.action))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(CarbideError::InvalidState)?;

        Ok(instance_subnet)
    }

    pub async fn advance(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        action: &VpcResourceStateMachineInput,
    ) -> CarbideResult<bool> {
        // first validate the state change by getting the current state in the db
        let events = InstanceSubnetEvent::for_instance_subnet(txn, &self.id).await?;
        let mut state_machine = self.state_machine(&events)?;
        state_machine
            .consume(action)
            .map_err(CarbideError::InvalidState)?;

        let id: (i64, ) = sqlx::query_as(
            "INSERT INTO instance_subnet_events (instance_subnet_id, action) VALUES ($1::uuid, $2) RETURNING id",
        )
            .bind(self.id)
            .bind(VpcResourceAction::from(action))
            .fetch_one(txn)
            .await?;

        log::info!("Event ID is {}", id.0);

        Ok(true)
    }

    /// Returns the list of Events the instance_subnet has experienced
    pub fn events(&self) -> &Vec<InstanceSubnetEvent> {
        &self.events
    }

    pub async fn associate_instance_subnet_with_instance(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        instance_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        Ok(sqlx::query_as(
            "UPDATE instance_subnets SET instance_id=$1::uuid where id=$2::uuid RETURNING *",
        )
        .bind(instance_id)
        .bind(self.id)
        .fetch_one(&mut *txn)
        .await?)
    }

    pub fn addresses(&self) -> &Vec<InstanceSubnetAddress> {
        &self.addresses
    }

    pub async fn for_instance_subnet(
        txn: &mut Transaction<'_, Postgres>,
        id: &uuid::Uuid,
    ) -> CarbideResult<Vec<Self>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM instance_subnet_events WHERE instance_subnet_id=$1::uuid;",
        )
        .bind(id)
        .fetch_all(&mut *txn)
        .await?)
    }

    pub async fn addresses_for_machine_id(
        _txn: &mut Transaction<'_, Postgres>,
        _machine_id: uuid::Uuid,
    ) -> CarbideResult<Vec<InstanceSubnetAddress>> {
        todo!();
    }

    pub async fn find_by_id(
        txn: &mut Transaction<'_, Postgres>,
        instance_subnet_id: uuid::Uuid,
    ) -> CarbideResult<InstanceSubnet> {
        Ok(
            sqlx::query_as("SELECT * FROM instance_subnets WHERE id = $1::uuid")
                .bind(instance_subnet_id)
                .fetch_one(txn)
                .await?,
        )
    }

    pub async fn create(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_interface: &MachineInterface,
        network_segment: &NetworkSegment,
        instance: &Instance,
        vfid: Option<i32>,
    ) -> CarbideResult<Self> {
        let instance_subnet: InstanceSubnet =
            sqlx::query_as("INSERT INTO instance_subnets (machine_interface_id, network_segment_id, instance_id, vfid) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::int) RETURNING *")
                .bind(machine_interface.id())
                .bind(network_segment.id())
                .bind(instance.id())
                .bind(vfid)
                .fetch_one(&mut *txn)
                .await?;

        instance_subnet
            .advance(&mut *txn, &VpcResourceStateMachineInput::Initialize)
            .await?;
        Ok(instance_subnet)
    }

    /// Get a reference to the instance network_segment_id.
    pub fn network_segment_id(&self) -> &uuid::Uuid {
        &self.network_segment_id
    }

    pub fn machine_interface_id(&self) -> &uuid::Uuid {
        &self.machine_interface_id
    }

    pub fn instance_id(&self) -> &uuid::Uuid {
        &self.instance_id
    }

    pub fn vfid(self) -> Option<i32> {
        self.vf_id
    }
}
