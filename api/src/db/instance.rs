/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::ops::DerefMut;
use std::str::FromStr;

use crate::{
    db::{instance_address::InstanceAddress, DatabaseError},
    model::{
        instance::{
            config::{
                infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig,
                storage::InstanceStorageConfig, tenant_config::TenantConfig, InstanceConfig,
            },
            snapshot::InstanceSnapshot,
            status::{
                network::InstanceNetworkStatusObservation,
                storage::InstanceStorageStatusObservation, InstanceStatusObservations,
            },
        },
        metadata::Metadata,
        os::{IpxeOperatingSystem, OperatingSystem, OperatingSystemVariant},
        storage::StorageVolume,
        tenant::TenantOrganizationId,
    },
    CarbideError, CarbideResult,
};

use crate::db::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use forge_uuid::{
    instance::InstanceId, instance_type::InstanceTypeId, machine::MachineId, vpc::VpcId,
};
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Copy, Clone)]
pub struct IdColumn;

impl ColumnInfo<'_> for IdColumn {
    type TableType = Instance;
    type ColumnType = InstanceId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Debug, Clone)]
pub struct Instance {}

pub struct NewInstance<'a> {
    pub instance_id: InstanceId,
    pub machine_id: MachineId,
    pub instance_type_id: Option<InstanceTypeId>,
    pub config: &'a InstanceConfig,
    pub metadata: Metadata,
    pub config_version: ConfigVersion,
    pub network_config_version: ConfigVersion,
    pub ib_config_version: ConfigVersion,
    pub storage_config_version: ConfigVersion,
}

pub struct DeleteInstance {
    pub instance_id: InstanceId,
}

pub enum FindInstanceTypeFilter<'a> {
    Id(ObjectColumnFilter<'a, IdColumn>),
    Label(&'a rpc::Label),
}

impl<'r> FromRow<'r, PgRow> for InstanceSnapshot {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        /// This is wrapper to allow implementing FromRow on the Option
        #[derive(serde::Deserialize)]
        struct OptionalNetworkStatusObservation(Option<InstanceNetworkStatusObservation>);
        #[derive(serde::Deserialize)]
        struct OptionalStorageStatusObservation(Option<InstanceStorageStatusObservation>);

        let tenant_org_str = row.try_get::<String, _>("tenant_org")?;
        let tenant_org = TenantOrganizationId::try_from(tenant_org_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let os_user_data: Option<String> = row.try_get("os_user_data")?;
        let os_ipxe_script: String = row.try_get("os_ipxe_script")?;
        let os_always_boot_with_ipxe = row.try_get("os_always_boot_with_ipxe")?;
        let os_phone_home_enabled = row.try_get("os_phone_home_enabled")?;
        let os_image_id: Option<Uuid> = row.try_get("os_image_id")?;
        let os = OperatingSystem {
            variant: match os_image_id {
                Some(x) => OperatingSystemVariant::OsImage(x),
                None => OperatingSystemVariant::Ipxe(IpxeOperatingSystem {
                    ipxe_script: os_ipxe_script,
                }),
            },
            run_provisioning_instructions_on_every_boot: os_always_boot_with_ipxe,
            phone_home_enabled: os_phone_home_enabled,
            user_data: os_user_data,
        };

        let tenant_config = TenantConfig {
            tenant_organization_id: tenant_org,
            tenant_keyset_ids: row.try_get("keyset_ids")?,
            hostname: row.try_get("hostname")?,
        };

        let network_config: sqlx::types::Json<InstanceNetworkConfig> =
            row.try_get("network_config")?;
        let network_status_observation: sqlx::types::Json<OptionalNetworkStatusObservation> =
            row.try_get("network_status_observation")?;

        let ib_config: sqlx::types::Json<InstanceInfinibandConfig> = row.try_get("ib_config")?;

        let storage_config: sqlx::types::Json<InstanceStorageConfig> =
            row.try_get("storage_config")?;
        let storage_status_observation: sqlx::types::Json<OptionalStorageStatusObservation> =
            row.try_get("storage_status_observation")?;

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
            storage: storage_config.0,
        };

        Ok(InstanceSnapshot {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            instance_type_id: row.try_get("instance_type_id")?,
            use_custom_pxe_on_boot: row.try_get("use_custom_pxe_on_boot")?,
            deleted: row.try_get("deleted")?,
            config,
            config_version: row.try_get("config_version")?,
            network_config_version: row.try_get("network_config_version")?,
            ib_config_version: row.try_get("ib_config_version")?,
            storage_config_version: row.try_get("storage_config_version")?,
            observations: InstanceStatusObservations {
                network: network_status_observation.0 .0,
                storage: storage_status_observation.0 .0,
                phone_home_last_contact: row.try_get("phone_home_last_contact")?,
            },
            metadata,
            // Unused as of today
            // requested: row.try_get("requested")?,
            // started: row.try_get("started")?,
            // finished: row.try_get("finished")?,
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
        filter: rpc::InstanceSearchFilter,
    ) -> Result<Vec<InstanceId>, CarbideError> {
        let mut builder = sqlx::QueryBuilder::new("SELECT id FROM instances ");
        let mut has_filter = false;
        let mut has_tenant_org_id = false;

        if let Some(label) = filter.label {
            if label.key.is_empty() && label.value.is_some() {
                builder.push(
                    "WHERE EXISTS (
                        SELECT 1
                        FROM jsonb_each_text(labels) AS kv
                        WHERE kv.value = ",
                );
                builder.push_bind(label.value.unwrap());
                builder.push(")");
                has_filter = true;
            } else if label.key.is_empty() && label.value.is_none() {
                return Err(CarbideError::InvalidArgument(
                    "finding instances based on label needs either key or a value.".to_string(),
                ));
            } else if !label.key.is_empty() && label.value.is_none() {
                builder.push("WHERE labels ->> ");
                builder.push_bind(label.key);
                builder.push(" IS NOT NULL");
                has_filter = true;
            } else if !label.key.is_empty() && label.value.is_some() {
                builder.push("WHERE labels ->> ");
                builder.push_bind(label.key);
                builder.push(" = ");
                builder.push_bind(label.value.unwrap());
                has_filter = true;
            }
        }

        if let Some(tenant_org_id) = filter.tenant_org_id {
            has_tenant_org_id = true;
            if has_filter {
                builder.push(" AND ");
            } else {
                builder.push("WHERE ");
            }
            builder.push("tenant_org = ");
            builder.push_bind(tenant_org_id);
        }

        if let Some(vpc_id) = filter.vpc_id {
            // vpc_id needs to be converted to a UUID type. We could
            // just do a uuid::Uuid, but it seems more appropriate and
            // correct to convert it into a VpcId (which is what it
            // *actually* is, and has the necessary sqlx bindings).
            let vpc_id = VpcId::from_str(&vpc_id).map_err(CarbideError::from)?;
            if has_filter || has_tenant_org_id {
                builder.push(" AND ");
            } else {
                builder.push("WHERE ");
            }
            builder.push("id IN (");
            builder.push(
                "SELECT instances.id FROM instances
INNER JOIN instance_addresses ON instance_addresses.instance_id = instances.id
INNER JOIN network_prefixes ON instance_addresses.circuit_id = network_prefixes.circuit_id
INNER JOIN network_segments ON network_prefixes.segment_id = network_segments.id
INNER JOIN vpcs ON network_segments.vpc_id = vpcs.id
WHERE vpc_id = ",
            );
            builder.push_bind(vpc_id);
            builder.push(")");
        }

        let query = builder.build_query_as();
        Ok(query
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "instance::find_ids", e))?)
    }

    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        filter: FindInstanceTypeFilter<'_>,
    ) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
        let all_instances: Vec<InstanceSnapshot> = match filter {
            FindInstanceTypeFilter::Id(id) => {
                let mut query = FilterableQueryBuilder::new("SELECT * FROM instances").filter(&id);
                query
                    .build_query_as()
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query.sql(), e))?
            }

            FindInstanceTypeFilter::Label(label) => match (label.key.is_empty(), &label.value) {
                (true, Some(value)) => sqlx::query_as::<_, InstanceSnapshot>(
                    "SELECT * FROM instances WHERE EXISTS (
                        SELECT 1
                        FROM jsonb_each_text(labels) AS kv
                        WHERE kv.value = $1
                    );",
                )
                .bind(value)
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,
                (true, None) => {
                    // TODO: This is really an invalid argument error - which we can't return from here
                    // However the whole argument validation story should happen outside the scope of this method
                    return Err(DatabaseError::new(
                        file!(),
                        line!(),
                        "Instance::find",
                        sqlx::Error::Protocol(
                            "finding instances based on label needs either key or a value."
                                .to_string(),
                        ),
                    ));
                }

                (false, None) => sqlx::query_as::<_, InstanceSnapshot>(
                    "SELECT * FROM instances WHERE labels ->> $1 IS NOT NULL",
                )
                .bind(label.key.clone())
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,

                (false, Some(value)) => sqlx::query_as::<_, InstanceSnapshot>(
                    "SELECT * FROM instances WHERE labels ->> $1 = $2",
                )
                .bind(label.key.clone())
                .bind(value)
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "instances List", e))?,
            },
        };

        Ok(all_instances)
    }

    pub async fn find_by_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: InstanceId,
    ) -> Result<Option<InstanceSnapshot>, DatabaseError> {
        let query = "SELECT * from instances WHERE id = $1";
        sqlx::query_as(query)
            .bind(id)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_id_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<Option<InstanceId>, DatabaseError> {
        let query = "SELECT id from instances WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<Option<InstanceSnapshot>, DatabaseError> {
        let query = "SELECT * from instances WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_machine_ids(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_ids: &[MachineId],
    ) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
        let query = "SELECT * from instances WHERE machine_id = ANY($1)";
        sqlx::query_as(query)
            .bind(machine_ids)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_relay_ip(
        txn: &mut Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> Result<Option<InstanceSnapshot>, DatabaseError> {
        let query = "
SELECT i.* from instances i
INNER JOIN machine_interfaces m ON m.machine_id = i.machine_id
INNER JOIN machines s ON s.id = m.attached_dpu_machine_id
WHERE s.network_config->>'loopback_ip'=$1";
        sqlx::query_as(query)
            .bind(relay.to_string())
            .fetch_optional(txn.deref_mut())
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
        let _: (MachineId,) = sqlx::query_as(query)
            .bind(boot_with_custom_ipxe)
            .bind(machine_id.to_string())
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    /// Updates the desired network configuration for an instance
    pub async fn update_network_config(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: InstanceId,
        expected_version: ConfigVersion,
        new_state: &InstanceNetworkConfig,
        increment_version: bool,
    ) -> Result<(), DatabaseError> {
        let next_version = if increment_version {
            expected_version.increment()
        } else {
            expected_version
        };

        let query = "UPDATE instances SET network_config_version=$1, network_config=$2::json
            WHERE id=$3 AND network_config_version=$4
            RETURNING id";
        let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
            .bind(next_version)
            .bind(sqlx::types::Json(new_state))
            .bind(instance_id)
            .bind(expected_version)
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    pub async fn update_phone_home_last_contact(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: InstanceId,
    ) -> Result<DateTime<Utc>, DatabaseError> {
        let query = "UPDATE instances SET phone_home_last_contact=now() WHERE id=$1 RETURNING phone_home_last_contact";

        let query_result: (DateTime<Utc>,) = sqlx::query_as::<_, (DateTime<Utc>,)>(query) // Specify return type
            .bind(instance_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        tracing::info!(
            "Phone home last contact updated for instance {}",
            query_result.0
        );
        Ok(query_result.0)
    }

    /// Updates updateable configurations of an instance
    /// - OS
    /// - Keyset IDs
    /// - Metadata
    ///
    /// This method will not update
    /// - instance network and infiniband configurations
    /// - tenant organization IDs
    ///
    /// This method does not check if the instance still exists.
    /// A previous `Instance::find` call should fulfill this purpose.
    pub async fn update_config(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: InstanceId,
        expected_version: ConfigVersion,
        config: InstanceConfig,
        metadata: Metadata,
    ) -> Result<(), CarbideError> {
        let next_version = expected_version.increment();

        let mut os_ipxe_script = String::new();
        let os_user_data = config.os.user_data;
        let mut os_image_id = None;
        match &config.os.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                os_ipxe_script = ipxe.ipxe_script.clone();
            }
            OperatingSystemVariant::OsImage(id) => os_image_id = Some(id),
        }

        let query = "UPDATE instances SET config_version=$1,
            os_ipxe_script=$2, os_user_data=$3, os_always_boot_with_ipxe=$4, os_phone_home_enabled=$5,
            os_image_id=$6, keyset_ids=$7,
            name=$8, description=$9, labels=$10::json
            WHERE id=$11 AND config_version=$12
            RETURNING id";
        let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
            .bind(next_version)
            .bind(os_ipxe_script)
            .bind(os_user_data)
            .bind(config.os.run_provisioning_instructions_on_every_boot)
            .bind(config.os.phone_home_enabled)
            .bind(os_image_id)
            .bind(config.tenant.tenant_keyset_ids)
            .bind(&metadata.name)
            .bind(&metadata.description)
            .bind(sqlx::types::Json(&metadata.labels))
            .bind(instance_id)
            .bind(expected_version)
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(match e {
                sqlx::Error::RowNotFound => CarbideError::ConcurrentModificationError(
                    "instance",
                    expected_version.to_string(),
                ),
                e => DatabaseError::new(file!(), line!(), query, e).into(),
            }),
        }
    }

    /// Updates the Operating System
    ///
    /// This method does not check if the instance still exists.
    /// A previous `Instance::find` call should fulfill this purpose.
    pub async fn update_os(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: InstanceId,
        expected_version: ConfigVersion,
        os: OperatingSystem,
    ) -> Result<(), CarbideError> {
        let next_version = expected_version.increment();

        let mut os_ipxe_script = String::new();
        let os_user_data = os.user_data;
        let mut os_image_id = None;
        match &os.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                os_ipxe_script = ipxe.ipxe_script.clone();
            }
            OperatingSystemVariant::OsImage(id) => os_image_id = Some(id),
        }

        let query = "UPDATE instances SET config_version=$1,
            os_ipxe_script=$2, os_user_data=$3, os_always_boot_with_ipxe=$4, os_phone_home_enabled=$5, os_image_id=$6
            WHERE id=$7 AND config_version=$8
            RETURNING id";
        let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
            .bind(next_version)
            .bind(os_ipxe_script)
            .bind(os_user_data)
            .bind(os.run_provisioning_instructions_on_every_boot)
            .bind(os.phone_home_enabled)
            .bind(os_image_id)
            .bind(instance_id)
            .bind(expected_version)
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(match e {
                sqlx::Error::RowNotFound => CarbideError::ConcurrentModificationError(
                    "instance",
                    expected_version.to_string(),
                ),
                e => DatabaseError::new(file!(), line!(), query, e).into(),
            }),
        }
    }

    /// Updates the desired infiniband configuration for an instance
    pub async fn update_ib_config(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: InstanceId,
        expected_version: ConfigVersion,
        new_state: &InstanceInfinibandConfig,
        increment_version: bool,
    ) -> Result<(), DatabaseError> {
        let next_version = if increment_version {
            expected_version.increment()
        } else {
            expected_version
        };

        let query = "UPDATE instances SET ib_config_version=$1, ib_config=$2::json
            WHERE id=$3 AND ib_config_version=$4
            RETURNING id";
        let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
            .bind(next_version)
            .bind(sqlx::types::Json(new_state))
            .bind(instance_id)
            .bind(expected_version)
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    /// Updates the storage configuration for an instance
    pub async fn update_storage_config(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &InstanceStorageConfig,
        increment_version: bool,
    ) -> Result<(), DatabaseError> {
        let next_version = if increment_version {
            expected_version.increment()
        } else {
            expected_version
        };

        // check if volumes need to be allocated, currently only supporting pre-created volumes
        // todo: handle volume creation as part of instance allocation
        for attrs in new_state.volumes.iter() {
            // let mut volume =
            match attrs.use_existing_volume {
                Some(x) => {
                    if x {
                        StorageVolume::get(txn, attrs.id).await?
                    } else {
                        return Err(DatabaseError::new(
                            file!(),
                            line!(),
                            "instance update_storage_config",
                            sqlx::Error::ColumnNotFound("volume must exist".to_string()),
                        ));
                    }
                }
                None => {
                    return Err(DatabaseError::new(
                        file!(),
                        line!(),
                        "instance update_storage_config",
                        sqlx::Error::ColumnNotFound("volume must exist".to_string()),
                    ))
                }
            };
            // update the volume in the db, associate this instance and dpu to it
            // for now we will do the backend nvmesh client attach and then update the db
            // in the machine state handler attach_storage_volumes()
            // volume.attach(txn, &instance_id, dpu_id).await?;
        }

        // update the db. for now storing the attrs as is, could optimize and only store volume ids
        // instance volumes config is an ordered list of volumes to attach to the instance
        // the actual volume details are stored in storage_volumes like other storage objects
        let query = "UPDATE instances SET storage_config_version=$1, storage_config=$2::json
            WHERE id=$3 AND storage_config_version=$4
            RETURNING id";
        let query_result: Result<(uuid::Uuid,), _> = sqlx::query_as(query)
            .bind(next_version)
            .bind(sqlx::types::Json(new_state))
            .bind(instance_id)
            .bind(expected_version)
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
        instance_id: InstanceId,
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
        let (_,): (InstanceId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(status))
            .bind(instance_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn update_storage_status_observation(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: InstanceId,
        status: &InstanceStorageStatusObservation,
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
            "UPDATE instances SET storage_status_observation=$1::json where id = $2::uuid returning id";
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
    /// Persists the new instance to the DB.
    ///
    /// Does ***not*** check for the existence of the associated machine.
    ///
    /// It's expected that the machine associated with the request has
    /// already been checked for existence and that appropriate locking has
    /// been used.
    ///
    /// * `txn` - A reference to an active DB transaction
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<InstanceSnapshot> {
        // None means we haven't observed any network status from forge-dpu-agent yet
        // The first report from the agent will set the field
        let network_status_observation = Option::<InstanceNetworkStatusObservation>::None;

        let mut os_ipxe_script = String::new();
        let os_user_data = self.config.os.user_data.clone();
        let mut os_image_id = None;
        match &self.config.os.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                os_ipxe_script = ipxe.ipxe_script.clone();
            }
            OperatingSystemVariant::OsImage(id) => os_image_id = Some(id),
        }

        let storage_status_observation = Option::<InstanceStorageStatusObservation>::None;

        let query = "INSERT INTO instances (
                        id,
                        machine_id,
                        os_user_data,
                        os_ipxe_script,
                        os_image_id,
                        os_always_boot_with_ipxe,
                        tenant_org,
                        use_custom_pxe_on_boot,
                        network_config,
                        network_config_version,
                        network_status_observation,
                        ib_config,
                        ib_config_version,
                        keyset_ids,
                        os_phone_home_enabled,
                        name,
                        description,
                        labels,
                        config_version,
                        hostname,
                        storage_config,
                        storage_config_version,
                        storage_status_observation,
                        instance_type_id
                    )
                    SELECT 
                            $1, $2, $3, $4, $5, $6, $7, true, $8::json, $9, $10::json, $11::json,
                            $12, $13, $14, $15, $16, $17::json, $18, $19, $20::json, $21, $22::json,
                            m.instance_type_id
                    FROM machines m WHERE m.id=$23 AND ($24 IS NULL OR m.instance_type_id=$24) FOR UPDATE
                    RETURNING *";
        match sqlx::query_as(query)
            .bind(self.instance_id)
            .bind(self.machine_id.to_string())
            .bind(os_user_data)
            .bind(os_ipxe_script)
            .bind(os_image_id)
            .bind(self.config.os.run_provisioning_instructions_on_every_boot)
            .bind(self.config.tenant.tenant_organization_id.as_str())
            .bind(sqlx::types::Json(&self.config.network))
            .bind(self.network_config_version)
            .bind(sqlx::types::Json(network_status_observation))
            .bind(sqlx::types::Json(&self.config.infiniband))
            .bind(self.ib_config_version)
            .bind(&self.config.tenant.tenant_keyset_ids)
            .bind(self.config.os.phone_home_enabled)
            .bind(&self.metadata.name)
            .bind(&self.metadata.description)
            .bind(sqlx::types::Json(&self.metadata.labels))
            .bind(self.config_version)
            .bind(&self.config.tenant.hostname)
            .bind(sqlx::types::Json(&self.config.storage))
            .bind(self.storage_config_version)
            .bind(sqlx::types::Json(storage_status_observation))
            .bind(self.machine_id.to_string())
            .bind(&self.instance_type_id)
            .fetch_one(&mut **txn)
            .await
        {
            // Not sure which error feels better here, FailedPrecondition or InvalidArgument,
            // since the state of the system (the instance type of the machine) might be correct,
            // in which case maybe InvalidArgument, or the state of the system might be incorrect,
            // in which case FailedPrecondition.  Since both depend on the state of the system,
            // which could change and make the argument acceptable or not, this is probably
            // FailedPrecondition.
            Err(sqlx::Error::RowNotFound) => Err(CarbideError::FailedPrecondition(
                "expected InstanceTypeId does not match source machine".to_string(),
            )),
            Err(e) => Err(CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                query,
                e,
            ))),
            Ok(o) => Ok(o),
        }
    }
}

impl DeleteInstance {
    pub async fn delete(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<()> {
        InstanceAddress::delete(&mut *txn, self.instance_id).await?;

        let query = "DELETE FROM instances where id=$1::uuid RETURNING id";
        sqlx::query_as::<_, InstanceId>(query)
            .bind(self.instance_id)
            .fetch_one(txn.deref_mut())
            .await
            .map(|_| ())
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn mark_as_deleted(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query = "UPDATE instances SET deleted=NOW() WHERE id=$1::uuid RETURNING id";

        let _id = sqlx::query_as::<_, InstanceId>(query)
            .bind(self.instance_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(())
    }
}
