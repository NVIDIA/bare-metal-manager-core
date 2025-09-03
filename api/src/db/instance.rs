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

use std::str::FromStr;
use std::{collections::HashMap, ops::DerefMut};

use crate::{
    CarbideError, CarbideResult,
    db::{DatabaseError, instance_address::InstanceAddress},
    model::{
        instance::{
            config::{
                InstanceConfig,
                infiniband::InstanceInfinibandConfig,
                network::{InstanceNetworkConfig, InstanceNetworkConfigUpdate},
                storage::InstanceStorageConfig,
                tenant_config::TenantConfig,
            },
            snapshot::InstanceSnapshot,
            status::{InstanceStatusObservations, storage::InstanceStorageStatusObservation},
        },
        metadata::Metadata,
        os::{IpxeOperatingSystem, OperatingSystem, OperatingSystemVariant},
        storage::StorageVolume,
        tenant::TenantOrganizationId,
    },
};

use crate::db::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use forge_uuid::{
    instance::InstanceId, instance_type::InstanceTypeId, machine::MachineId,
    network_security_group::NetworkSecurityGroupId, vpc::VpcId,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, Row, postgres::PgRow};

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
    pub issue: Option<rpc::Issue>,
    pub is_repair_tenant: Option<bool>,
}

/// This represents the structure of an instance we get from postgres via the row_to_json or
/// JSONB_AGG functions. Its fields need to match the column names of the instances table exactly.
/// It's expected that we read this directly from the JSON returned by the query, and then
/// convert it into an InstanceSnapshot.
#[derive(Serialize, Deserialize)]
pub struct InstanceSnapshotPgJson {
    id: InstanceId,
    machine_id: MachineId,
    name: String,
    description: String,
    labels: HashMap<String, String>,
    network_config: InstanceNetworkConfig,
    network_config_version: String,
    ib_config: InstanceInfinibandConfig,
    ib_config_version: String,
    storage_config: InstanceStorageConfig,
    storage_config_version: String,
    config_version: String,
    storage_status_observation: Option<InstanceStorageStatusObservation>,
    phone_home_last_contact: Option<DateTime<Utc>>,
    use_custom_pxe_on_boot: bool,
    tenant_org: Option<String>,
    keyset_ids: Vec<String>,
    hostname: Option<String>,
    os_user_data: Option<String>,
    os_ipxe_script: String,
    os_always_boot_with_ipxe: bool,
    os_phone_home_enabled: bool,
    os_image_id: Option<uuid::Uuid>,
    instance_type_id: Option<InstanceTypeId>,
    network_security_group_id: Option<NetworkSecurityGroupId>,
    requested: DateTime<Utc>,
    started: DateTime<Utc>,
    finished: Option<DateTime<Utc>>,
    deleted: Option<DateTime<Utc>>,
    update_network_config_request: Option<InstanceNetworkConfigUpdate>,
}

impl<'r> FromRow<'r, PgRow> for InstanceSnapshot {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        InstanceSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

impl TryFrom<InstanceSnapshotPgJson> for InstanceSnapshot {
    type Error = sqlx::Error;

    fn try_from(value: InstanceSnapshotPgJson) -> Result<Self, Self::Error> {
        let metadata = Metadata {
            name: value.name,
            description: value.description,
            labels: value.labels,
        };

        let tenant_organization_id =
            TenantOrganizationId::try_from(value.tenant_org.unwrap_or_default())
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let os = OperatingSystem {
            variant: match value.os_image_id {
                Some(x) => OperatingSystemVariant::OsImage(x),
                None => OperatingSystemVariant::Ipxe(IpxeOperatingSystem {
                    ipxe_script: value.os_ipxe_script,
                }),
            },
            run_provisioning_instructions_on_every_boot: value.os_always_boot_with_ipxe,
            phone_home_enabled: value.os_phone_home_enabled,
            user_data: value.os_user_data,
        };

        let config = InstanceConfig {
            tenant: TenantConfig {
                tenant_organization_id,
                tenant_keyset_ids: value.keyset_ids,
                hostname: value.hostname,
            },
            os,
            network: value.network_config,
            infiniband: value.ib_config,
            storage: value.storage_config,
            network_security_group_id: value.network_security_group_id,
        };

        Ok(InstanceSnapshot {
            id: value.id,
            machine_id: value.machine_id,
            instance_type_id: value.instance_type_id,
            metadata,
            config,
            config_version: value.config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            network_config_version: value.network_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "network_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            ib_config_version: value.ib_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "ib_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            storage_config_version: value.storage_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "storage_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            observations: InstanceStatusObservations {
                network: HashMap::default(),
                storage: value.storage_status_observation,
                phone_home_last_contact: value.phone_home_last_contact,
            },
            use_custom_pxe_on_boot: value.use_custom_pxe_on_boot,
            deleted: value.deleted,
            update_network_config_request: value.update_network_config_request,
            // Unused as of today
            // requested: value.requested,
            // started: value.started,
            // finished: value.finished,
        })
    }
}

impl TryFrom<rpc::InstanceReleaseRequest> for DeleteInstance {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceReleaseRequest) -> Result<Self, Self::Error> {
        let id = value.id.ok_or(CarbideError::MissingArgument("id"))?;
        Ok(DeleteInstance {
            instance_id: id.try_into()?,
            issue: value.issue,
            is_repair_tenant: value.is_repair_tenant,
        })
    }
}

impl Instance {
    pub async fn find_ids(
        txn: &mut PgConnection,
        filter: rpc::InstanceSearchFilter,
    ) -> Result<Vec<InstanceId>, CarbideError> {
        let mut builder = sqlx::QueryBuilder::new("SELECT id FROM instances WHERE TRUE "); // The TRUE will be optimized away.

        if let Some(label) = filter.label {
            if label.key.is_empty() && label.value.is_some() {
                builder.push(
                    " AND EXISTS (
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
                builder.push(" AND labels ->> ");
                builder.push_bind(label.key);
                builder.push(" IS NOT NULL");
            } else if !label.key.is_empty() && label.value.is_some() {
                builder.push(" AND labels ->> ");
                builder.push_bind(label.key);
                builder.push(" = ");
                builder.push_bind(label.value.unwrap());
            }
        }

        if let Some(tenant_org_id) = filter.tenant_org_id {
            builder.push(" AND tenant_org = ");
            builder.push_bind(tenant_org_id);
        }

        if let Some(instance_type_id) = filter.instance_type_id {
            builder.push(" AND instance_type_id = ");
            builder.push_bind(instance_type_id);
        }

        if let Some(vpc_id) = filter.vpc_id {
            // vpc_id needs to be converted to a UUID type. We could
            // just do a uuid::Uuid, but it seems more appropriate and
            // correct to convert it into a VpcId (which is what it
            // *actually* is, and has the necessary sqlx bindings).
            let vpc_id = VpcId::from_str(&vpc_id).map_err(CarbideError::from)?;
            builder.push(" AND id IN (");
            builder.push(
                "SELECT instances.id FROM instances
INNER JOIN instance_addresses ON instance_addresses.instance_id = instances.id
INNER JOIN network_segments ON instance_addresses.segment_id = network_segments.id
INNER JOIN vpcs ON network_segments.vpc_id = vpcs.id
WHERE vpc_id = ",
            );
            builder.push_bind(vpc_id);
            builder.push(")");
        }

        let query = builder.build_query_as();
        Ok(query
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "instance::find_ids", e))?)
    }

    pub async fn find(
        txn: &mut PgConnection,
        filter: ObjectColumnFilter<'_, IdColumn>,
    ) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
        let mut query = FilterableQueryBuilder::new("SELECT row_to_json(i.*) FROM instances i")
            .filter_relation(&filter, Some("i"));
        query
            .build_query_as()
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query.sql(), e))
    }

    pub async fn find_by_id(
        txn: &mut PgConnection,
        id: InstanceId,
    ) -> Result<Option<InstanceSnapshot>, DatabaseError> {
        let query = "SELECT row_to_json(i.*) from instances i WHERE id = $1";
        sqlx::query_as(query)
            .bind(id)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    pub async fn find_id_by_machine_id(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<Option<InstanceId>, DatabaseError> {
        let query = "SELECT id from instances WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    pub async fn find_by_machine_id(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<Option<InstanceSnapshot>, DatabaseError> {
        let query = "SELECT row_to_json(i.*) from instances i WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    pub async fn find_by_machine_ids(
        txn: &mut PgConnection,
        machine_ids: &[&MachineId],
    ) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
        let query = "SELECT row_to_json(i.*) from instances i WHERE machine_id = ANY($1)";
        sqlx::query_as(query)
            .bind(machine_ids)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    pub async fn use_custom_ipxe_on_next_boot(
        machine_id: &MachineId,
        boot_with_custom_ipxe: bool,
        txn: &mut PgConnection,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE instances SET use_custom_pxe_on_boot=$1::bool WHERE machine_id=$2 RETURNING machine_id";
        // Fetch one to make sure atleast one row is updated.
        let _: (MachineId,) = sqlx::query_as(query)
            .bind(boot_with_custom_ipxe)
            .bind(machine_id.to_string())
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(())
    }

    /// Updates the desired network configuration for an instance
    pub async fn update_network_config(
        txn: &mut PgConnection,
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
            .fetch_one(txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::query(query, e)),
        }
    }

    pub async fn update_phone_home_last_contact(
        txn: &mut PgConnection,
        instance_id: InstanceId,
    ) -> Result<DateTime<Utc>, DatabaseError> {
        let query = "UPDATE instances SET phone_home_last_contact=now() WHERE id=$1 RETURNING phone_home_last_contact";

        let query_result: (DateTime<Utc>,) = sqlx::query_as::<_, (DateTime<Utc>,)>(query) // Specify return type
            .bind(instance_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

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
    /// - Security Group
    ///
    /// This method will not update
    /// - instance network and infiniband configurations
    /// - tenant organization IDs
    ///
    /// This method does not check if the instance still exists.
    /// A previous `Instance::find` call should fulfill this purpose.
    pub async fn update_config(
        txn: &mut PgConnection,
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
            name=$8, description=$9, labels=$10::json, network_security_group_id=$13
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
            .bind(config.network_security_group_id)
            .fetch_one(txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(match e {
                sqlx::Error::RowNotFound => CarbideError::ConcurrentModificationError(
                    "instance",
                    expected_version.to_string(),
                ),
                e => DatabaseError::query(query, e).into(),
            }),
        }
    }

    /// Updates the Operating System
    ///
    /// This method does not check if the instance still exists.
    /// A previous `Instance::find` call should fulfill this purpose.
    pub async fn update_os(
        txn: &mut PgConnection,
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
            .fetch_one(txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(match e {
                sqlx::Error::RowNotFound => CarbideError::ConcurrentModificationError(
                    "instance",
                    expected_version.to_string(),
                ),
                e => DatabaseError::query(query, e).into(),
            }),
        }
    }

    /// Updates the desired infiniband configuration for an instance
    pub async fn update_ib_config(
        txn: &mut PgConnection,
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
            .fetch_one(txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::query(query, e)),
        }
    }

    /// Updates the storage configuration for an instance
    pub async fn update_storage_config(
        txn: &mut PgConnection,
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
                    ));
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
            .fetch_one(txn)
            .await;

        match query_result {
            Ok((_instance_id,)) => Ok(()),
            Err(e) => Err(DatabaseError::query(query, e)),
        }
    }

    pub async fn update_storage_status_observation(
        txn: &mut PgConnection,
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
                sqlx::Error::Io(std::io::Error::other(e.to_string())),
            )
        })?;

        let query = "UPDATE instances SET storage_status_observation=$1::json where id = $2::uuid returning id";
        let (_,): (uuid::Uuid,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(status))
            .bind(instance_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(())
    }

    pub(crate) async fn trigger_update_network_config_request(
        instance_id: &InstanceId,
        current: &InstanceNetworkConfig,
        requested: &InstanceNetworkConfig,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), DatabaseError> {
        let network_config_request = InstanceNetworkConfigUpdate {
            old_config: current.clone(),
            new_config: requested.clone(),
        };
        let query = r#"UPDATE instances SET update_network_config_request=$1::json 
                        WHERE id = $2::uuid 
                          AND update_network_config_request IS NULL 
                          AND deleted IS NULL
                        RETURNING id"#;
        let (_,): (InstanceId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(network_config_request))
            .bind(instance_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(())
    }

    pub async fn delete_update_network_config_request(
        instance_id: &InstanceId,
        txn: &mut PgConnection,
    ) -> Result<(), DatabaseError> {
        let query = r#"UPDATE instances SET update_network_config_request=NULL 
                        WHERE id = $1::uuid"#;
        sqlx::query(query)
            .bind(instance_id)
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(())
    }
}

impl NewInstance<'_> {
    /// Persists the new instance to the DB.
    ///
    /// Does ***not*** check for the existence of the associated machine.
    ///
    /// It's expected that the machine associated with the request has
    /// already been checked for existence and that appropriate locking has
    /// been used.
    ///
    /// * `txn` - A reference to an active DB transaction
    pub async fn persist(&self, txn: &mut PgConnection) -> CarbideResult<InstanceSnapshot> {
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
                        instance_type_id,
                        network_security_group_id
                    )
                    SELECT 
                            $1, $2, $3, $4, $5, $6, $7, true, $8::json, $9, $10::json, 
                            $11, $12, $13, $14, $15, $16::json, $17, $18, $19::json, $20, $21::json,
                            m.instance_type_id, $24
                    FROM machines m WHERE m.id=$22 AND ($23 IS NULL OR m.instance_type_id=$23) FOR UPDATE
                    RETURNING row_to_json(instances.*)";
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
            .bind(&self.config.network_security_group_id)
            .fetch_one(txn)
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
            Err(e) => Err(CarbideError::from(DatabaseError::query(query, e))),
            Ok(o) => Ok(o),
        }
    }
}

impl DeleteInstance {
    pub async fn delete(&self, txn: &mut PgConnection) -> CarbideResult<()> {
        InstanceAddress::delete(&mut *txn, self.instance_id).await?;

        let query = "DELETE FROM instances where id=$1::uuid RETURNING id";
        sqlx::query_as::<_, InstanceId>(query)
            .bind(self.instance_id)
            .fetch_one(txn)
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::query(query, e))
            .map_err(CarbideError::from)
    }

    pub async fn mark_as_deleted(&self, txn: &mut PgConnection) -> CarbideResult<()> {
        let query = "UPDATE instances SET deleted=NOW() WHERE id=$1::uuid RETURNING id";

        let _id = sqlx::query_as::<_, InstanceId>(query)
            .bind(self.instance_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        Ok(())
    }
}
