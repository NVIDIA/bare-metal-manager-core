/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::forge as rpc;
use chrono::prelude::*;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::{DatabaseError, UuidKeyedObjectFilter};
use crate::{
    db::{instance_address::InstanceAddress, machine::DbMachineId},
    model::{
        config_version::{ConfigVersion, Versioned},
        instance::{
            config::{
                infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig,
                tenant_config::TenantConfig,
            },
            status::infiniband::InstanceInfinibandStatusObservation,
            status::network::InstanceNetworkStatusObservation,
        },
        machine::machine_id::MachineId,
        tenant::TenantOrganizationId,
    },
    CarbideError, CarbideResult,
};

pub mod status;

#[derive(Debug, Clone)]
pub struct Instance {
    pub id: uuid::Uuid,
    pub machine_id: MachineId,
    pub requested: DateTime<Utc>,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
    pub tenant_config: TenantConfig,
    pub ssh_keys: Vec<String>,
    pub use_custom_pxe_on_boot: bool,
    pub deleted: Option<DateTime<Utc>>,
    pub network_config: Versioned<InstanceNetworkConfig>,
    pub network_status_observation: Option<InstanceNetworkStatusObservation>,
    pub ib_config: Versioned<InstanceInfinibandConfig>,
    pub ib_status_observation: Option<InstanceInfinibandStatusObservation>,
}

#[derive(Debug, Clone)]
pub struct InstanceList {
    pub instances: Vec<Instance>,
}

pub struct NewInstance<'a> {
    pub machine_id: MachineId,
    pub tenant_config: &'a TenantConfig,
    pub ssh_keys: Vec<String>,
    pub network_config: Versioned<&'a InstanceNetworkConfig>,
    pub ib_config: Versioned<&'a InstanceInfinibandConfig>,
}

pub struct DeleteInstance {
    pub instance_id: uuid::Uuid,
}

impl<'r> FromRow<'r, PgRow> for Instance {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        /// This is wrapper to allow implementing FromRow on the Option
        #[derive(serde::Deserialize)]
        struct OptionalNetworkStatusObservation(Option<InstanceNetworkStatusObservation>);
        #[derive(serde::Deserialize)]
        struct OptionalIbStatusObservation(Option<InstanceInfinibandStatusObservation>);

        let user_data: Option<String> = row.try_get("user_data")?;
        let custom_ipxe = row.try_get("custom_ipxe")?;
        let machine_id: DbMachineId = row.try_get("machine_id")?;
        let tenant_org_str = row.try_get::<String, _>("tenant_org")?;
        let tenant_org = TenantOrganizationId::try_from(tenant_org_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let tenant_config = TenantConfig {
            tenant_organization_id: tenant_org,
            custom_ipxe,
            user_data,
            tenant_keyset_ids: row.try_get("keyset_ids")?,
        };

        let network_config_version_str: &str = row.try_get("network_config_version")?;
        let network_config_version = network_config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let network_config: sqlx::types::Json<InstanceNetworkConfig> =
            row.try_get("network_config")?;
        let network_status_observation: sqlx::types::Json<OptionalNetworkStatusObservation> =
            row.try_get("network_status_observation")?;

        let ib_config_version_str: &str = row.try_get("ib_config_version")?;
        let ib_config_version = ib_config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let ib_config: sqlx::types::Json<InstanceInfinibandConfig> = row.try_get("ib_config")?;
        let ib_status_observation: sqlx::types::Json<OptionalIbStatusObservation> =
            row.try_get("ib_status_observation")?;

        Ok(Instance {
            id: row.try_get("id")?,
            machine_id: machine_id.into_inner(),
            requested: row.try_get("requested")?,
            started: row.try_get("started")?,
            finished: row.try_get("finished")?,
            tenant_config,
            ssh_keys: Vec::new(),
            use_custom_pxe_on_boot: row.try_get("use_custom_pxe_on_boot")?,
            deleted: row.try_get("deleted")?,
            network_config: Versioned::new(network_config.0, network_config_version),
            network_status_observation: network_status_observation.0 .0,
            ib_config: Versioned::new(ib_config.0, ib_config_version),
            ib_status_observation: ib_status_observation.0 .0,
        })
    }
}

impl TryFrom<rpc::InstanceReleaseRequest> for DeleteInstance {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceReleaseRequest) -> Result<Self, Self::Error> {
        let id = value
            .id
            .ok_or(CarbideError::IdentifierNotSpecifiedForObject)?;
        Ok(DeleteInstance {
            instance_id: id.try_into()?,
        })
    }
}

impl Instance {
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<Vec<Instance>, DatabaseError> {
        let base_query = "SELECT * FROM instances m {where} GROUP BY m.id".to_owned();

        let all_instances: Vec<Instance> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, Instance>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "instances All", e))?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, Instance>(&base_query.replace("{where}", "WHERE m.id=$1"))
                    .bind(uuid)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "instances One", e))?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, Instance>(&base_query.replace("{where}", "WHERE m.id=ANY($1)"))
                    .bind(list)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?
            }
        };

        Ok(all_instances)
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn find_id_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<Option<uuid::Uuid>, DatabaseError> {
        #[derive(Debug, Clone, Copy, FromRow)]
        pub struct InstanceId(uuid::Uuid);

        // TODO: This won't work anymore if instances are not hard deleted on user delete.
        // Multiple instances will map to the same machine. We would need to get the active one.
        let query = "SELECT id from instances WHERE machine_id = $1";
        let instance_id = sqlx::query_as::<_, InstanceId>(query)
            .bind(machine_id.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(instance_id.map(|id| id.0))
    }

    pub async fn find_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<Option<Instance>, DatabaseError> {
        let query = "SELECT * from instances WHERE machine_id = $1";
        let instance = sqlx::query_as::<_, Instance>(query)
            .bind(machine_id.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        // TODO handle more than one subnet assignment on an instance
        // has network_segment_id
        Ok(instance)
    }

    pub async fn find_by_relay_ip(
        txn: &mut Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> Result<Option<Instance>, DatabaseError> {
        let query = "
SELECT i.* from instances i
INNER JOIN machine_interfaces m ON m.machine_id = i.machine_id
INNER JOIN machines s ON s.id = m.attached_dpu_machine_id
WHERE s.network_config->>'loopback_ip'=$1";
        sqlx::query_as(query)
            .bind(relay.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn use_custom_ipxe_on_next_boot(
        machine_id: &MachineId,
        boot_with_custom_ipxe: bool,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE instances SET use_custom_pxe_on_boot=$1::bool WHERE machine_id=$2 RETURNING machine_id";
        // Fetch one to make sure atleast one row is updated.
        let _: (DbMachineId,) = sqlx::query_as(query)
            .bind(boot_with_custom_ipxe)
            .bind(machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    /// Updates the desired network configuration for an instance
    pub async fn update_network_config(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &InstanceNetworkConfig,
        increment_version: bool,
    ) -> Result<(), DatabaseError> {
        let expected_version_str = expected_version.version_string();
        let next_version = if increment_version {
            expected_version.increment()
        } else {
            expected_version
        };
        let next_version_str = next_version.version_string();

        let query = "UPDATE instances SET network_config_version=$1, network_config=$2::json
            WHERE id=$3 AND network_config_version=$4
            RETURNING id";
        let query_result: Result<(uuid::Uuid,), _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(instance_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    /// Updates the desired infiniband configuration for an instance
    pub async fn update_ib_config(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &InstanceInfinibandConfig,
        increment_version: bool,
    ) -> Result<(), DatabaseError> {
        let expected_version_str = expected_version.version_string();
        let next_version = if increment_version {
            expected_version.increment()
        } else {
            expected_version
        };
        let next_version_str = next_version.version_string();

        let query = "UPDATE instances SET ib_config_version=$1, ib_config=$2::json
            WHERE id=$3 AND ib_config_version=$4
            RETURNING id";
        let query_result: Result<(uuid::Uuid,), _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(instance_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }
}

impl<'a> NewInstance<'a> {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Instance, DatabaseError> {
        let network_version_string = self.network_config.version.version_string();
        // None means we haven't observed any network status from the DPU via VPC yet
        // The first report from the networking subsytem will set the field
        let network_status_observation = Option::<InstanceNetworkStatusObservation>::None;

        let ib_config_version = self.ib_config.version.version_string();
        let ib_status_observation = Option::<InstanceInfinibandStatusObservation>::None;

        let query = "INSERT INTO instances (
                        machine_id,
                        user_data,
                        custom_ipxe,
                        tenant_org,
                        ssh_keys,
                        use_custom_pxe_on_boot,
                        network_config,
                        network_config_version,
                        network_status_observation,
                        ib_config,
                        ib_config_version,
                        ib_status_observation,
                        keyset_ids
                    )
                    VALUES ($1, $2, $3, $4, $5::text[], true, $6::json, $7, $8::json, $9::json, $10, $11::json, $12)
                    RETURNING *";
        sqlx::query_as(query)
            .bind(self.machine_id.to_string())
            .bind(&self.tenant_config.user_data)
            .bind(&self.tenant_config.custom_ipxe)
            .bind(self.tenant_config.tenant_organization_id.as_str())
            .bind(&self.ssh_keys)
            .bind(sqlx::types::Json(&self.network_config.value))
            .bind(&network_version_string)
            .bind(sqlx::types::Json(network_status_observation))
            .bind(sqlx::types::Json(&self.ib_config.value))
            .bind(&ib_config_version)
            .bind(sqlx::types::Json(ib_status_observation))
            .bind(&self.tenant_config.tenant_keyset_ids)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

impl DeleteInstance {
    pub async fn delete(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Instance> {
        InstanceAddress::delete(&mut *txn, self.instance_id).await?;

        let query = "DELETE FROM instances where id=$1::uuid RETURNING *";
        sqlx::query_as(query)
            .bind(self.instance_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }
    pub async fn mark_as_deleted(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Instance> {
        let query = "UPDATE instances SET deleted=NOW() WHERE id=$1::uuid RETURNING *";

        sqlx::query_as(query)
            .bind(self.instance_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }
}
