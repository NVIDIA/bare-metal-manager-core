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

use crate::{
    model::{
        config_version::Versioned,
        instance::{
            config::{
                network::InstanceNetworkConfig,
                tenant::{TenantConfig, TenantOrg},
            },
            status::network::InstanceNetworkStatusObservation,
        },
    },
    CarbideError, CarbideResult,
};

use super::UuidKeyedObjectFilter;
use super::{instance_subnet::InstanceSubnet, network_segment::NetworkSegment};

pub mod config;
pub mod status;

#[derive(Debug, Clone)]
pub struct Instance {
    pub id: uuid::Uuid,
    pub machine_id: uuid::Uuid,
    pub requested: DateTime<Utc>,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
    pub tenant_config: TenantConfig,
    pub ssh_keys: Vec<String>,
    pub use_custom_pxe_on_boot: bool,
    pub interfaces: Vec<InstanceSubnet>,
}

#[derive(Debug, Clone)]
pub struct InstanceList {
    pub instances: Vec<Instance>,
}

pub struct NewInstance<'a> {
    pub machine_id: uuid::Uuid,
    pub tenant_config: &'a TenantConfig,
    pub ssh_keys: Vec<String>,
    pub network_config: Versioned<&'a InstanceNetworkConfig>,
}

pub struct DeleteInstance {
    pub instance_id: uuid::Uuid,
}

impl<'r> FromRow<'r, PgRow> for Instance {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let user_data: Option<String> = row.try_get("user_data")?;
        let custom_ipxe = row.try_get("custom_ipxe")?;
        let tenant_org_str = row.try_get::<String, _>("tenant_org")?;
        let tenant_org =
            TenantOrg::try_from(tenant_org_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let tenant_config = TenantConfig {
            tenant_org,
            custom_ipxe,
            user_data,
        };

        Ok(Instance {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            requested: row.try_get("requested")?,
            started: row.try_get("started")?,
            finished: row.try_get("finished")?,
            tenant_config,
            ssh_keys: Vec::new(),
            use_custom_pxe_on_boot: row.try_get("use_custom_pxe_on_boot")?,
            interfaces: Vec::new(),
        })
    }
}

impl From<Instance> for rpc::Instance {
    fn from(src: Instance) -> Self {
        rpc::Instance {
            id: Some(src.id.into()),
            segment_id: None,
            machine_id: Some(src.machine_id.into()),
            user_data: src.tenant_config.user_data,
            custom_ipxe: src.tenant_config.custom_ipxe,
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
            interfaces: src
                .interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
            use_custom_pxe_on_boot: src.use_custom_pxe_on_boot,
        }
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
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<Instance>> {
        let base_query = "SELECT * FROM instances m {where} GROUP BY m.id".to_owned();

        let mut all_instances: Vec<Instance> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, Instance>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, Instance>(&base_query.replace("{where}", "WHERE m.id=$1"))
                    .bind(uuid)
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, Instance>(&base_query.replace("{where}", "WHERE m.id=ANY($1)"))
                    .bind(list)
                    .fetch_all(&mut *txn)
                    .await?
            }
        };

        for ins in all_instances.iter_mut() {
            let instance_subnets = InstanceSubnet::find_by_instance_id(&mut *txn, ins.id)
                .await
                .unwrap_or_default();
            ins.interfaces = instance_subnets;
        }

        Ok(all_instances)
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn find_id_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> Result<Option<uuid::Uuid>, sqlx::Error> {
        #[derive(Debug, Clone, Copy, FromRow)]
        pub struct InstanceId(uuid::Uuid);

        // TODO: This won't work anymore if instances are not hard deleted on user delete.
        // Multiple instances will map to the same machine. We would need to get the active one.
        let instance_id =
            sqlx::query_as::<_, InstanceId>("SELECT id from instances WHERE machine_id = $1::uuid")
                .bind(machine_id)
                .fetch_optional(&mut *txn)
                .await?;

        Ok(instance_id.map(|id| id.0))
    }

    pub async fn find_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> CarbideResult<Option<Instance>> {
        let mut instance =
            sqlx::query_as::<_, Instance>("SELECT * from instances WHERE machine_id = $1::uuid")
                .bind(machine_id)
                .fetch_optional(&mut *txn)
                .await?;

        // TODO handle more than one subnet assignment on an instance
        // has network_segment_id

        if let Some(ref mut ins) = instance {
            let instance_subnets =
                InstanceSubnet::find_by_instance_id(&mut *txn, *ins.id()).await?;
            ins.interfaces = instance_subnets;
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
                                    i.custom_ipxe as custom_ipxe, i.tenant_org as tenant_org,
                                    i.ssh_keys as ssh_keys,
                                    i.use_custom_pxe_on_boot as use_custom_pxe_on_boot
                                    FROM instances i
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

    pub async fn use_custom_ipxe_on_next_boot(
        machine_id: uuid::Uuid,
        boot_with_custom_ipxe: bool,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query =
            "UPDATE instances SET use_custom_pxe_on_boot=$1::bool WHERE machine_id=$2::uuid RETURNING machine_id";
        // Fetch one to make sure atleast one row is updated.
        let _: (uuid::Uuid,) = sqlx::query_as(query)
            .bind(boot_with_custom_ipxe)
            .bind(machine_id)
            .fetch_one(&mut *txn)
            .await?;

        Ok(())
    }
}

impl<'a> NewInstance<'a> {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Instance> {
        let network_version_string = self.network_config.version.to_version_string();
        // None means we haven't observed any network status from the DPU via VPC yet
        // The first report from the networking subsytem will set the field
        let network_status_observation = Option::<InstanceNetworkStatusObservation>::None;

        Ok(
            sqlx::query_as(concat!(
                "INSERT INTO instances (machine_id, user_data, custom_ipxe, tenant_org, ssh_keys, use_custom_pxe_on_boot, network_config, network_config_version, network_status_observation) ",
                "VALUES ($1::uuid, $2, $3, $4, $5::text[], true, $6::json, $7, $8::json) RETURNING *"),
            )
                .bind(self.machine_id)
                .bind(&self.tenant_config.user_data)
                .bind(&self.tenant_config.custom_ipxe)
                .bind(self.tenant_config.tenant_org.as_str())
                .bind(&self.ssh_keys)
                .bind(sqlx::types::Json(&self.network_config.config))
                .bind(&network_version_string)
                .bind(sqlx::types::Json(network_status_observation))
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
        if Instance::find(&mut *txn, UuidKeyedObjectFilter::One(self.instance_id))
            .await
            .map_err(|_| CarbideError::NotFoundError(self.instance_id))?
            .is_empty()
        {
            return Err(CarbideError::FindOneReturnedNoResultsError(
                self.instance_id,
            ));
        }

        InstanceSubnet::delete_by_instance_id(&mut *txn, self.instance_id).await?;

        Ok(
            sqlx::query_as("DELETE FROM instances where id=$1::uuid RETURNING *")
                .bind(self.instance_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}
