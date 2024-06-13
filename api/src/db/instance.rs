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

use std::collections::HashMap;
use std::net::IpAddr;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::{DatabaseError, UuidKeyedObjectFilter};
use crate::model::instance::config::InstanceConfig;
use crate::model::os::{IpxeOperatingSystem, OperatingSystemVariant};
use crate::{
    db::{instance_address::InstanceAddress, machine::DbMachineId},
    model::{
        instance::{
            config::{
                infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig,
                tenant_config::TenantConfig,
            },
            status::infiniband::InstanceInfinibandStatusObservation,
            status::network::InstanceNetworkStatusObservation,
        },
        machine::machine_id::MachineId,
        metadata::Metadata,
        os::OperatingSystem,
        tenant::TenantOrganizationId,
    },
    CarbideError, CarbideResult,
};

#[derive(Debug, Clone)]
pub struct Instance {
    pub id: uuid::Uuid,
    pub machine_id: MachineId,
    pub requested: DateTime<Utc>,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
    pub use_custom_pxe_on_boot: bool,
    pub deleted: Option<DateTime<Utc>>,
    pub config: InstanceConfig,
    pub config_version: ConfigVersion,
    pub network_config_version: ConfigVersion,
    pub ib_config_version: ConfigVersion,
    pub network_status_observation: Option<InstanceNetworkStatusObservation>,
    pub ib_status_observation: Option<InstanceInfinibandStatusObservation>,
    pub phone_home_last_contact: Option<DateTime<Utc>>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone)]
pub struct InstanceList {
    pub instances: Vec<Instance>,
}

pub struct NewInstance<'a> {
    pub machine_id: MachineId,
    pub instance_id: uuid::Uuid,
    pub config: &'a InstanceConfig,
    pub metadata: Metadata,
    pub config_version: ConfigVersion,
    pub network_config_version: ConfigVersion,
    pub ib_config_version: ConfigVersion,
}

pub struct DeleteInstance {
    pub instance_id: uuid::Uuid,
}

pub enum FindInstanceTypeFilter<'a> {
    Id(&'a UuidKeyedObjectFilter<'a>),
    Label(&'a rpc::Label),
}

impl<'r> FromRow<'r, PgRow> for Instance {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        /// This is wrapper to allow implementing FromRow on the Option
        #[derive(serde::Deserialize)]
        struct OptionalNetworkStatusObservation(Option<InstanceNetworkStatusObservation>);
        #[derive(serde::Deserialize)]
        struct OptionalIbStatusObservation(Option<InstanceInfinibandStatusObservation>);

        let machine_id: DbMachineId = row.try_get("machine_id")?;
        let tenant_org_str = row.try_get::<String, _>("tenant_org")?;
        let tenant_org = TenantOrganizationId::try_from(tenant_org_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let os_user_data: Option<String> = row.try_get("os_user_data")?;
        let os_ipxe_script: String = row.try_get("os_ipxe_script")?;
        let os_always_boot_with_ipxe = row.try_get("os_always_boot_with_ipxe")?;
        let os_phone_home_enabled = row.try_get("os_phone_home_enabled")?;

        let os = OperatingSystem {
            variant: OperatingSystemVariant::Ipxe(IpxeOperatingSystem {
                ipxe_script: os_ipxe_script,
                user_data: os_user_data,
                always_boot_with_ipxe: os_always_boot_with_ipxe,
            }),
            phone_home_enabled: os_phone_home_enabled,
        };

        let tenant_config = TenantConfig {
            tenant_organization_id: tenant_org,
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

        let version_str: &str = row.try_get("config_version")?;
        let config_version = version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let instance_labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: instance_labels.0,
        };

        let config = InstanceConfig {
            tenant: tenant_config,
            os,
            network: network_config.0,
            infiniband: ib_config.0,
        };

        Ok(Instance {
            id: row.try_get("id")?,
            machine_id: machine_id.into_inner(),
            requested: row.try_get("requested")?,
            started: row.try_get("started")?,
            finished: row.try_get("finished")?,
            use_custom_pxe_on_boot: row.try_get("use_custom_pxe_on_boot")?,
            deleted: row.try_get("deleted")?,
            config,
            config_version,
            network_config_version,
            ib_config_version,
            network_status_observation: network_status_observation.0 .0,
            ib_status_observation: ib_status_observation.0 .0,
            phone_home_last_contact: row.try_get("phone_home_last_contact")?,
            metadata,
        })
    }
}

impl TryFrom<rpc::InstanceReleaseRequest> for DeleteInstance {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceReleaseRequest) -> Result<Self, Self::Error> {
        let id = value.id.ok_or(CarbideError::MissingArgument("id"))?;
        Ok(DeleteInstance {
            instance_id: id.try_into()?,
        })
    }
}

impl Instance {
    pub async fn find_ids(
        txn: &mut Transaction<'_, Postgres>,
        search_config: rpc::InstanceSearchConfig,
    ) -> Result<Vec<uuid::Uuid>, CarbideError> {
        let mut builder = sqlx::QueryBuilder::new("SELECT id FROM instances");

        #[derive(Debug, Clone, Copy, FromRow)]
        pub struct InstanceId(uuid::Uuid);

        if search_config.label.is_some() {
            let label = search_config.label.unwrap();
            if label.key.is_empty() && label.value.is_some() {
                builder.push(
                    " WHERE EXISTS (
                        SELECT 1
                        FROM jsonb_each_text(labels) AS kv
                        WHERE kv.value = ",
                );
                builder.push_bind(label.value.unwrap());
                builder.push(")");
            } else if label.key.is_empty() && label.value.is_none() {
                return Err(CarbideError::InvalidArgument(
                    "finding instances based on label needs either key or a value.".to_string(),
                ));
            } else if !label.key.is_empty() && label.value.is_none() {
                builder.push(" WHERE labels ->> ");
                builder.push_bind(label.key);
                builder.push(" IS NOT NULL");
            } else if !label.key.is_empty() && label.value.is_some() {
                builder.push(" WHERE labels ->> ");
                builder.push_bind(label.key);
                builder.push(" = ");
                builder.push_bind(label.value.unwrap());
            }
        }

        let query = builder.build_query_as();
        let ids: Vec<InstanceId> = query
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "instance::find_ids", e))?;

        Ok(ids.into_iter().map(|id| id.0).collect())
    }

    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        filter: FindInstanceTypeFilter<'_>,
    ) -> Result<Vec<Instance>, CarbideError> {
        let base_query_for_id = "SELECT * FROM instances m {where} GROUP BY m.id".to_owned();

        let all_instances: Vec<Instance> = match filter {
            FindInstanceTypeFilter::Id(id) => match id {
                UuidKeyedObjectFilter::All => {
                    sqlx::query_as::<_, Instance>(&base_query_for_id.replace("{where}", ""))
                        .fetch_all(&mut **txn)
                        .await
                        .map_err(|e| DatabaseError::new(file!(), line!(), "instances All", e))?
                }
                UuidKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, Instance>(
                    &base_query_for_id.replace("{where}", "WHERE m.id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances One", e))?,
                UuidKeyedObjectFilter::List(list) => sqlx::query_as::<_, Instance>(
                    &base_query_for_id.replace("{where}", "WHERE m.id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,
            },

            FindInstanceTypeFilter::Label(label) => match (label.key.is_empty(), &label.value) {
                (true, Some(value)) => sqlx::query_as::<_, Instance>(
                    "SELECT * FROM instances WHERE EXISTS (
                        SELECT 1 
                        FROM jsonb_each_text(labels) AS kv 
                        WHERE kv.value = $1
                    );",
                )
                .bind(value)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,
                (true, None) => {
                    return Err(CarbideError::InvalidArgument(
                        "finding instances based on label needs either key or a value.".to_string(),
                    ));
                }

                (false, None) => sqlx::query_as::<_, Instance>(
                    "SELECT * FROM instances WHERE labels ->> $1 IS NOT NULL",
                )
                .bind(label.key.clone())
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,

                (false, Some(value)) => sqlx::query_as::<_, Instance>(
                    "SELECT * FROM instances WHERE labels ->> $1 = $2",
                )
                .bind(label.key.clone())
                .bind(value)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,
            },
        };

        Ok(all_instances)
    }

    pub async fn find_by_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: uuid::Uuid,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = "SELECT * from instances WHERE id = $1";
        let instance = sqlx::query_as::<_, Instance>(query)
            .bind(id)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(instance)
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

    pub async fn update_phone_home_last_contact(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
    ) -> Result<DateTime<Utc>, DatabaseError> {
        let query = "UPDATE instances SET phone_home_last_contact=now() WHERE id=$1 RETURNING phone_home_last_contact";

        let query_result: (DateTime<Utc>,) = sqlx::query_as::<_, (DateTime<Utc>,)>(query) // Specify return type
            .bind(instance_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        tracing::info!(
            "Phone home last contact updated for instance {}",
            query_result.0
        );
        Ok(query_result.0)
    }

    /// Updates the Operating System
    ///
    /// This method does not check if the instance still exists.
    /// A previous `Instance::find` call should fulfill this purpose.
    pub async fn update_os(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        expected_version: ConfigVersion,
        os: OperatingSystem,
    ) -> Result<(), CarbideError> {
        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let os_ipxe_script;
        let os_user_data;
        let os_always_boot_with_ipxe;
        match &os.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                os_ipxe_script = &ipxe.ipxe_script;
                os_user_data = &ipxe.user_data;
                os_always_boot_with_ipxe = ipxe.always_boot_with_ipxe;
            }
        }

        let query = "UPDATE instances SET config_version=$1,
            os_ipxe_script=$2, os_user_data=$3, os_always_boot_with_ipxe=$4, os_phone_home_enabled=$5
            WHERE id=$6 AND config_version=$7
            RETURNING id";
        let query_result: Result<(uuid::Uuid,), _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(os_ipxe_script)
            .bind(os_user_data)
            .bind(os_always_boot_with_ipxe)
            .bind(os.phone_home_enabled)
            .bind(instance_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(match e {
                sqlx::Error::RowNotFound => {
                    CarbideError::ConcurrentModificationError("instance", expected_version)
                }
                e => DatabaseError::new(file!(), line!(), query, e).into(),
            }),
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

    /// Updates the latest network status observation for an instance
    pub async fn update_network_status_observation(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        status: &InstanceNetworkStatusObservation,
    ) -> Result<(), DatabaseError> {
        // TODO: This might rather belong into the API layer
        // We will move move it there once that code is in place
        status.validate().map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "ioerror",
                sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )),
            )
        })?;

        let query =
            "UPDATE instances SET network_status_observation=$1::json where id = $2::uuid returning id";
        let (_,): (uuid::Uuid,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(status))
            .bind(instance_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    /// Updates the latest infiniband status observation for an instance
    pub async fn update_infiniband_status_observation(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        status: &InstanceInfinibandStatusObservation,
    ) -> Result<(), DatabaseError> {
        // TODO: This might rather belong into the API layer
        // We will move move it there once that code is in place
        status.validate().map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "ioerror",
                sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )),
            )
        })?;

        let query =
            "UPDATE instances SET ib_status_observation=$1::json where id = $2::uuid returning id";
        let (_,): (uuid::Uuid,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(status))
            .bind(instance_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }
}

impl<'a> NewInstance<'a> {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Instance, DatabaseError> {
        let network_version_string = self.network_config_version.version_string();
        // None means we haven't observed any network status from forge-dpu-agent yet
        // The first report from the agent will set the field
        let network_status_observation = Option::<InstanceNetworkStatusObservation>::None;

        let ib_config_version = self.ib_config_version.version_string();
        // None means we haven't registered the Host at UFM yet
        let ib_status_observation = Option::<InstanceInfinibandStatusObservation>::None;

        let os_ipxe_script;
        let os_user_data;
        let os_always_boot_with_ipxe;
        match &self.config.os.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                os_ipxe_script = &ipxe.ipxe_script;
                os_user_data = &ipxe.user_data;
                os_always_boot_with_ipxe = ipxe.always_boot_with_ipxe;
            }
        }

        let query = "INSERT INTO instances (
                        id,
                        machine_id,
                        os_user_data,
                        os_ipxe_script,
                        os_always_boot_with_ipxe,
                        tenant_org,
                        use_custom_pxe_on_boot,
                        network_config,
                        network_config_version,
                        network_status_observation,
                        ib_config,
                        ib_config_version,
                        ib_status_observation,
                        keyset_ids,
                        os_phone_home_enabled,
                        name,
                        description,
                        labels,
                        config_version
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, true, $7::json, $8, $9::json, $10::json, $11, $12::json, $13, $14, $15, $16, $17, $18)
                    RETURNING *";
        sqlx::query_as(query)
            .bind(self.instance_id)
            .bind(self.machine_id.to_string())
            .bind(os_user_data)
            .bind(os_ipxe_script)
            .bind(os_always_boot_with_ipxe)
            .bind(self.config.tenant.tenant_organization_id.as_str())
            .bind(sqlx::types::Json(&self.config.network))
            .bind(&network_version_string)
            .bind(sqlx::types::Json(network_status_observation))
            .bind(sqlx::types::Json(&self.config.infiniband))
            .bind(&ib_config_version)
            .bind(sqlx::types::Json(ib_status_observation))
            .bind(&self.config.tenant.tenant_keyset_ids)
            .bind(self.config.os.phone_home_enabled)
            .bind(&self.metadata.name)
            .bind(&self.metadata.description)
            .bind(sqlx::types::Json(&self.metadata.labels))
            .bind(&self.config_version.version_string())
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
