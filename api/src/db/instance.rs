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
use std::{
    convert::{TryFrom, TryInto},
    net::IpAddr,
};

use chrono::prelude::*;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use ::rpc::forge as rpc;
use ::rpc::Timestamp;

use crate::db::instance_subnet_address::InstanceSubnetAddress;
use crate::db::UuidKeyedObjectFilter;
use crate::{CarbideError, CarbideResult};

use super::{instance_subnet::InstanceSubnet, network_segment::NetworkSegment};

#[derive(Debug, Clone)]
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
    pub addresses: Vec<InstanceSubnetAddress>,
}

#[derive(Debug, Clone)]
pub struct InstanceList {
    pub instances: Vec<Instance>,
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
impl<'r> FromRow<'r, PgRow> for Instance {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Instance {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            requested: row.try_get("requested")?,
            started: row.try_get("started")?,
            finished: row.try_get("finished")?,
            user_data: row.try_get("user_data")?,
            custom_ipxe: row.try_get("custom_ipxe")?,
            ssh_keys: Vec::new(),
            managed_resource_id: row.try_get("managed_resource_id")?,
            addresses: Vec::new(),
        })
    }
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
            addresses: src
                .addresses
                .into_iter()
                .map(|addr| addr.address.to_string())
                .collect(),
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
    ) -> CarbideResult<Option<Instance>> {
        let instance = if let Some(mut instance) =
            sqlx::query_as::<_, Instance>("SELECT * from instances WHERE machine_id = $1::uuid")
                .bind(machine_id)
                .fetch_optional(&mut *txn)
                .await?
        {
            let interface_address = InstanceSubnetAddress::find_for_instance(
                &mut *txn,
                UuidKeyedObjectFilter::One(instance.id().to_owned()),
            )
            .await?;

            let _ = interface_address
                .into_iter()
                .map(|(_, isa)| instance.addresses = isa);

            Some(instance)
        } else {
            None
        };

        Ok(instance)
    }

    async fn find_by_mac_and_segment(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: uuid::Uuid,
        parsed_mac: MacAddress,
    ) -> CarbideResult<Self> {
        Ok(sqlx::query_as(r#"SELECT i.id as id, i.machine_id as machine_id,
                                    i.requested as requested, i.started as started,
                                    i.finished as finished, i,user_data as user_data,
                                    i.custom_ipxe as custom_ipxe, i.ssh_keys as ssh_keys,
                                    i.managed_resource_id as managed_resource_id FROM instances i 
                                      INNER JOIN instance_subnets s ON i.id = s.instance_id
                                      INNER JOIN machine_interfaces ms ON ms.id = s.machine_interface_id
                                      WHERE
                                        ms.mac_address = $1 AND s.network_segment_id = $2"#)
            .bind(parsed_mac)
            .bind(segment_id)
            .fetch_one(&mut *txn)
            .await?)
    }

    pub async fn find_by_mac_and_relay(
        txn: &mut Transaction<'_, Postgres>,
        relay: IpAddr,
        parsed_mac: MacAddress,
    ) -> CarbideResult<Option<Instance>> {
        match NetworkSegment::for_relay(txn, relay).await? {
            None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
            Some(segment) => {
                Ok(
                    match Instance::find_by_mac_and_segment(&mut *txn, segment.id, parsed_mac).await
                    {
                        Ok(instance) => Some(instance),
                        Err(CarbideError::DatabaseError(sqlx::Error::RowNotFound)) => None, // Instance is not found.
                        Err(er) => {
                            return Err(er);
                        }
                    },
                )
            }
        }
    }

    pub async fn assign_address(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        subnet: InstanceSubnet,
        segment_id: uuid::Uuid,
    ) -> CarbideResult<IpAddr> {
        let mut segments =
            NetworkSegment::find(txn, super::UuidKeyedObjectFilter::One(segment_id)).await?;
        if segments.is_empty() {
            return Err(CarbideError::NotFoundError(segment_id));
        }

        let segment = segments.remove(0);
        let address = InstanceSubnet::get_address(&mut *txn, self.id, &segment, subnet)
            .await
            .map(|x| x.ip())?;

        log::info!("IP assigned to {} is {}.", self.id(), address);
        Ok(address)
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
