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

use std::ops::DerefMut;
use std::str::FromStr;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use forge_uuid::instance::InstanceId;
use forge_uuid::machine::MachineId;
use forge_uuid::vpc::VpcId;
use model::instance::NewInstance;
use model::instance::config::InstanceConfig;
use model::instance::config::infiniband::InstanceInfinibandConfig;
use model::instance::config::network::{InstanceNetworkConfig, InstanceNetworkConfigUpdate};
use model::instance::snapshot::InstanceSnapshot;
use model::metadata::Metadata;
use model::os::{OperatingSystem, OperatingSystemVariant};
use sqlx::PgConnection;

use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
    instance_address,
};

#[derive(Copy, Clone)]
pub struct IdColumn;

impl ColumnInfo<'_> for IdColumn {
    type TableType = InstanceTable;
    type ColumnType = InstanceId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InstanceTable {}

pub async fn find_ids(
    txn: &mut PgConnection,
    filter: rpc::InstanceSearchFilter,
) -> Result<Vec<InstanceId>, DatabaseError> {
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
            return Err(DatabaseError::InvalidArgument(
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
        let vpc_id = VpcId::from_str(&vpc_id).map_err(DatabaseError::from)?;
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
    query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("instance::find_ids", e))
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
) -> Result<(), DatabaseError> {
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
            sqlx::Error::RowNotFound => {
                DatabaseError::ConcurrentModificationError("instance", expected_version.to_string())
            }
            e => DatabaseError::query(query, e),
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
) -> Result<(), DatabaseError> {
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
            sqlx::Error::RowNotFound => {
                DatabaseError::ConcurrentModificationError("instance", expected_version.to_string())
            }
            e => DatabaseError::query(query, e),
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

pub async fn trigger_update_network_config_request(
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
    value: NewInstance<'_>,
    txn: &mut PgConnection,
) -> DatabaseResult<InstanceSnapshot> {
    let mut os_ipxe_script = String::new();
    let os_user_data = value.config.os.user_data.clone();
    let mut os_image_id = None;
    match &value.config.os.variant {
        OperatingSystemVariant::Ipxe(ipxe) => {
            os_ipxe_script = ipxe.ipxe_script.clone();
        }
        OperatingSystemVariant::OsImage(id) => os_image_id = Some(id),
    }

    let query = "INSERT INTO instances (
                        id,
                        machine_id,
                        os_user_data,
                        os_ipxe_script,
                        os_image_id,
                        os_always_boot_with_ipxe,
                        tenant_org,
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
                        network_security_group_id,
                        use_custom_pxe_on_boot,
                        instance_type_id
                    )
                    SELECT 
                            $1, $2, $3, $4, $5, $6, $7, $8::json, $9, $10::json,
                            $11, $12, $13, $14, $15, $16::json, $17, $18,
                            $19, true, m.instance_type_id
                    FROM machines m WHERE m.id=$20 AND ($21 IS NULL OR m.instance_type_id=$21) FOR UPDATE
                    RETURNING row_to_json(instances.*)";
    match sqlx::query_as(query)
        .bind(value.instance_id)
        .bind(value.machine_id.to_string())
        .bind(os_user_data)
        .bind(os_ipxe_script)
        .bind(os_image_id)
        .bind(value.config.os.run_provisioning_instructions_on_every_boot)
        .bind(value.config.tenant.tenant_organization_id.as_str())
        .bind(sqlx::types::Json(&value.config.network))
        .bind(value.network_config_version)
        .bind(sqlx::types::Json(&value.config.infiniband))
        .bind(value.ib_config_version)
        .bind(&value.config.tenant.tenant_keyset_ids)
        .bind(value.config.os.phone_home_enabled)
        .bind(&value.metadata.name)
        .bind(&value.metadata.description)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(value.config_version)
        .bind(&value.config.tenant.hostname)
        .bind(&value.config.network_security_group_id)
        .bind(value.machine_id.to_string())
        .bind(&value.instance_type_id)
        .fetch_one(txn)
        .await
    {
        // Not sure which error feels better here, FailedPrecondition or InvalidArgument,
        // since the state of the system (the instance type of the machine) might be correct,
        // in which case maybe InvalidArgument, or the state of the system might be incorrect,
        // in which case FailedPrecondition.  Since both depend on the state of the system,
        // which could change and make the argument acceptable or not, this is probably
        // FailedPrecondition.
        Err(sqlx::Error::RowNotFound) => Err(DatabaseError::FailedPrecondition(
            "expected InstanceTypeId does not match source machine".to_string(),
        )),
        Err(e) => Err(DatabaseError::query(query, e)),
        Ok(o) => Ok(o),
    }
}

pub async fn delete(instance_id: InstanceId, txn: &mut PgConnection) -> DatabaseResult<()> {
    instance_address::delete(&mut *txn, instance_id).await?;

    let query = "DELETE FROM instances where id=$1::uuid RETURNING id";
    sqlx::query_as::<_, InstanceId>(query)
        .bind(instance_id)
        .fetch_one(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn mark_as_deleted(
    instance_id: InstanceId,
    txn: &mut PgConnection,
) -> DatabaseResult<()> {
    let query = "UPDATE instances SET deleted=NOW() WHERE id=$1::uuid RETURNING id";

    let _id = sqlx::query_as::<_, InstanceId>(query)
        .bind(instance_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}
