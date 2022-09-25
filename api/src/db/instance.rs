use std::{
    convert::{TryFrom, TryInto},
    net::IpAddr,
};

use chrono::prelude::*;
use mac_address::MacAddress;
use sqlx::{FromRow, Postgres, Transaction};

use ::rpc::Timestamp;
use rpc::forge::v0 as rpc;

use crate::{db::machine_interface::MachineInterface, CarbideError, CarbideResult};

use super::{
    instance_subnet::InstanceSubnet, machine::Machine, machine_state::MachineState,
    network_segment::NetworkSegment,
};

#[derive(Debug, FromRow)]
pub struct Instance {
    pub id: uuid::Uuid,
    pub machine_id: uuid::Uuid,
    pub requested: DateTime<Utc>,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
    pub user_data: Option<String>,
    pub custom_ipxe: String,
    pub ssh_keys: Vec<String>,
    pub managed_resource_id: uuid::Uuid,
}

pub struct NewInstance {
    pub machine_id: uuid::Uuid,
    pub segment_id: uuid::Uuid,
    pub user_data: Option<String>,
    pub custom_ipxe: String,
    pub ssh_keys: Vec<String>,
}

pub struct DeleteInstance {
    pub instance_id: uuid::Uuid,
}

impl From<Instance> for rpc::Instance {
    fn from(src: Instance) -> Self {
        rpc::Instance {
            id: Some(src.id.into()),
            segment_id: None,
            machine_id: Some(src.machine_id.into()),
            user_data: src.user_data,
            custom_ipxe: src.custom_ipxe,
            ssh_keys: src.ssh_keys,
            requested: Some(Timestamp {
                seconds: src.requested.timestamp(),
                nanos: 0,
            }),
            started: Some(Timestamp {
                seconds: src.started.timestamp(),
                nanos: 0,
            }),
            finished: src.finished.map(|t| Timestamp {
                seconds: t.timestamp(),
                nanos: 0,
            }),
        }
    }
}

impl TryFrom<rpc::Instance> for NewInstance {
    type Error = CarbideError;

    fn try_from(value: rpc::Instance) -> Result<Self, Self::Error> {
        if value.id.is_some() {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Instance",
            )));
        }
        Ok(NewInstance {
            machine_id: value
                .machine_id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
            segment_id: value
                .segment_id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
            user_data: value.user_data,
            custom_ipxe: value.custom_ipxe,
            ssh_keys: value.ssh_keys,
        })
    }
}

impl TryFrom<rpc::InstanceDeletionRequest> for DeleteInstance {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceDeletionRequest) -> Result<Self, Self::Error> {
        let id = value
            .id
            .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?;
        Ok(DeleteInstance {
            instance_id: id.try_into()?,
        })
    }
}

impl Instance {
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn find_by_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
    ) -> CarbideResult<Instance> {
        Ok(
            sqlx::query_as("SELECT * from instances WHERE id = $1::uuid")
                .bind(instance_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn find_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> CarbideResult<Instance> {
        Ok(
            sqlx::query_as("SELECT * from instances WHERE machine_id = $1::uuid")
                .bind(machine_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn is_instance_configured(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> CarbideResult<bool> {
        match Machine::find_one(&mut *txn, machine_id).await? {
            None => {
                log::warn!("Supplied invalid UUID: {}", machine_id);
                Err(CarbideError::NotFoundError(machine_id))
            }
            Some(m) => match m.current_state(&mut *txn).await? {
                MachineState::Assigned => Ok(true),
                _ => Ok(false),
            },
        }
    }

    pub async fn verify_and_assign_address(
        txn: &mut Transaction<'_, Postgres>,
        relay: IpAddr,
        mac_address: MacAddress,
    ) -> CarbideResult<uuid::Uuid> {
        let machine_interfaces = MachineInterface::find_by_mac_address(txn, mac_address).await?;
        match machine_interfaces.len() {
            1 => {
                let machine_interface = &machine_interfaces[0];
                let machine_id = machine_interface
                    .machine_id
                    .ok_or(CarbideError::NotFoundError(machine_interface.id))?;
                let instance = Instance::find_by_machine_id(txn, machine_id).await?;
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(segment) => {
                        let address = InstanceSubnet::get_address(
                            &mut *txn,
                            instance.id,
                            machine_interface,
                            &segment,
                        )
                        .await
                        .map(|x| x.ip())?;

                        log::info!("IP assigned to {} is {}.", instance.id(), address);
                        Ok(segment.id)
                    }
                }
            }
            0 => {
                log::warn!(
                    "No machine returned with mac: {} for relay: {}",
                    mac_address,
                    relay
                );
                Err(CarbideError::GenericError(format!(
                    "No machine returned with mac: {}",
                    mac_address
                )))
            }
            _ => {
                log::warn!(
                    "More than existing mac address ({}) for network segment (relay ip: {}), found: {:?}",
                    &mac_address,
                    &relay, machine_interfaces
                );
                Err(CarbideError::NetworkSegmentDuplicateMacAddress(mac_address))
            }
        }
    }
}

impl NewInstance {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Instance> {
        Ok(
            sqlx::query_as(
                "INSERT INTO instances (machine_id, user_data, custom_ipxe, ssh_keys) VALUES ($1::uuid, $2, $3, $4::text[]) RETURNING *",
            )
            .bind(&self.machine_id)
            .bind(&self.user_data)
            .bind(&self.custom_ipxe)
            .bind(&self.ssh_keys)
            .fetch_one(&mut *txn)
            .await?
        )
    }
}

impl DeleteInstance {
    pub async fn delete(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Instance> {
        Instance::find_by_id(&mut *txn, self.instance_id)
            .await
            .map_err(|_| CarbideError::NotFoundError(self.instance_id))?;

        InstanceSubnet::delete_by_instance_id(&mut *txn, self.instance_id).await?;

        Ok(
            sqlx::query_as("DELETE FROM instances where id=$1::uuid RETURNING *")
                .bind(&self.instance_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}
