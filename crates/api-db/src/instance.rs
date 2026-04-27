/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::ops::DerefMut;
use std::str::FromStr;

use carbide_uuid::extension_service::ExtensionServiceId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use carbide_uuid::vpc::VpcId;
use chrono::prelude::*;
use config_version::ConfigVersion;
use model::instance::NewInstance;
use model::instance::config::InstanceConfig;
use model::instance::config::extension_services::InstanceExtensionServicesConfig;
use model::instance::config::infiniband::InstanceInfinibandConfig;
use model::instance::config::network::{InstanceNetworkConfig, InstanceNetworkConfigUpdate};
use model::instance::config::nvlink::InstanceNvLinkConfig;
use model::instance::snapshot::{self, InstanceSnapshot, InstanceSnapshotPgJson};
use model::metadata::Metadata;
use model::os::{InlineIpxe, OperatingSystem, OperatingSystemVariant};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::operating_system::{self, OperatingSystem as OsRow};
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
    txn: impl DbReader<'_>,
    filter: model::instance::InstanceSearchFilter,
) -> Result<Vec<InstanceId>, DatabaseError> {
    let mut builder = sqlx::QueryBuilder::new("SELECT id FROM instances WHERE TRUE "); // The TRUE will be optimized away.

    if let Some(label) = filter.label {
        match (label.key.is_empty(), label.value) {
            // Label key is empty, label value is set.
            (true, Some(value)) => {
                builder.push(
                    " AND EXISTS (
                        SELECT 1
                        FROM jsonb_each_text(labels) AS kv
                        WHERE kv.value = ",
                );
                builder.push_bind(value);
                builder.push(")");
            }
            // Label key is empty, label value is not set.
            (true, None) => {
                return Err(DatabaseError::InvalidArgument(
                    "finding instances based on label needs either key or a value.".to_string(),
                ));
            }
            // Label key is not empty, label value is not set.
            (false, None) => {
                builder.push(" AND labels ->> ");
                builder.push_bind(label.key);
                builder.push(" IS NOT NULL");
            }
            // Label key is not empty, label value is set.
            (false, Some(value)) => {
                builder.push(" AND labels ->> ");
                builder.push_bind(label.key);
                builder.push(" = ");
                builder.push_bind(value);
            }
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
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'_, IdColumn>,
) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(
        "SELECT row_to_json(i.*), row_to_json(o.*) FROM instances i \
         LEFT JOIN operating_systems o ON i.operating_system_id = o.id AND o.deleted IS NULL",
    )
    .filter_relation(&filter, Some("i"));
    let rows: Vec<(serde_json::Value, Option<serde_json::Value>)> = query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))?;
    let mut snapshots = Vec::with_capacity(rows.len());
    for (instance_json, os_json) in rows {
        let pg_json: InstanceSnapshotPgJson =
            serde_json::from_value(instance_json).map_err(|e| DatabaseError::Internal {
                message: format!("instance snapshot json decode: {e}"),
            })?;
        let snapshot = match os_json {
            Some(oj) => {
                let os_row: OsRow =
                    serde_json::from_value(oj).map_err(|e| DatabaseError::Internal {
                        message: format!("operating_system row json decode: {e}"),
                    })?;
                let os = build_operating_system_for_snapshot(&os_row, &pg_json);
                snapshot::from_pg_json_and_os(pg_json, os).map_err(|e| DatabaseError::Internal {
                    message: format!("instance snapshot from_pg_json_and_os: {e}"),
                })?
            }
            None => InstanceSnapshot::try_from(pg_json).map_err(|e| DatabaseError::Internal {
                message: format!("instance snapshot try_from: {e}"),
            })?,
        };
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

/// Converts raw JSON rows to InstanceSnapshots, batch-loading OS definitions as needed.
async fn resolve_snapshots_from_json_rows(
    txn: &mut PgConnection,
    rows: Vec<(serde_json::Value,)>,
) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
    let mut pg_jsons: Vec<InstanceSnapshotPgJson> = Vec::with_capacity(rows.len());
    for (json,) in rows {
        let pg_json: InstanceSnapshotPgJson =
            serde_json::from_value(json).map_err(|e| DatabaseError::Internal {
                message: format!("instance snapshot json decode: {e}"),
            })?;
        pg_jsons.push(pg_json);
    }
    if pg_jsons.is_empty() {
        return Ok(Vec::new());
    }
    let os_ids: Vec<uuid::Uuid> = pg_jsons
        .iter()
        .filter_map(|p| p.operating_system_id)
        .collect();
    let os_by_id: std::collections::HashMap<uuid::Uuid, OsRow> = if os_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        operating_system::get_many(&mut *txn, &os_ids)
            .await?
            .into_iter()
            .map(|r| (r.id, r))
            .collect()
    };
    let mut snapshots = Vec::with_capacity(pg_jsons.len());
    for pg_json in pg_jsons {
        let snapshot = match pg_json.operating_system_id.and_then(|id| os_by_id.get(&id)) {
            Some(os_row) => {
                let os = build_operating_system_for_snapshot(os_row, &pg_json);
                snapshot::from_pg_json_and_os(pg_json, os).map_err(|e| DatabaseError::Internal {
                    message: format!("instance snapshot from_pg_json_and_os: {e}"),
                })?
            }
            None => InstanceSnapshot::try_from(pg_json).map_err(|e| DatabaseError::Internal {
                message: format!("instance snapshot try_from: {e}"),
            })?,
        };
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

/// Builds the effective OperatingSystem for an instance by merging the OS definition with instance overrides.
fn build_operating_system_for_snapshot(
    os_row: &OsRow,
    pg_json: &InstanceSnapshotPgJson,
) -> OperatingSystem {
    let user_data = pg_json
        .os_user_data
        .clone()
        .or_else(|| os_row.user_data.clone());
    let variant = match os_row.type_.as_str() {
        model::operating_system_definition::OS_TYPE_IPXE => {
            let script = if os_row.allow_override && !pg_json.os_ipxe_script.is_empty() {
                pg_json.os_ipxe_script.clone()
            } else {
                os_row.ipxe_script.clone().unwrap_or_default()
            };
            OperatingSystemVariant::Ipxe(InlineIpxe {
                ipxe_script: script,
            })
        }
        model::operating_system_definition::OS_TYPE_TEMPLATED_IPXE => {
            OperatingSystemVariant::OperatingSystemId(os_row.id)
        }
        _ => {
            tracing::warn!(
                os_id = %os_row.id,
                os_type = %os_row.type_,
                "unexpected operating_system type, falling back to inline iPXE"
            );
            OperatingSystemVariant::Ipxe(InlineIpxe {
                ipxe_script: os_row
                    .ipxe_script
                    .clone()
                    .unwrap_or_else(|| pg_json.os_ipxe_script.clone()),
            })
        }
    };
    OperatingSystem {
        variant,
        user_data,
        phone_home_enabled: pg_json.os_phone_home_enabled,
        run_provisioning_instructions_on_every_boot: pg_json.os_always_boot_with_ipxe,
    }
}

pub async fn find_by_id(
    txn: impl DbReader<'_>,
    id: InstanceId,
) -> Result<Option<InstanceSnapshot>, DatabaseError> {
    // Single query; LEFT JOIN so we get instance even when operating_system_id is NULL.
    let query = "SELECT row_to_json(i.*), row_to_json(o.*) FROM instances i
        LEFT JOIN operating_systems o ON i.operating_system_id = o.id AND o.deleted IS NULL
        WHERE i.id = $1";
    let row: Option<(serde_json::Value, Option<serde_json::Value>)> = sqlx::query_as(query)
        .bind(id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    let Some((instance_json, os_json)) = row else {
        return Ok(None);
    };
    let pg_json: InstanceSnapshotPgJson =
        serde_json::from_value(instance_json).map_err(|e| DatabaseError::Internal {
            message: format!("instance snapshot json decode: {e}"),
        })?;
    let snapshot = match os_json {
        Some(oj) => {
            let os_row: OsRow =
                serde_json::from_value(oj).map_err(|e| DatabaseError::Internal {
                    message: format!("operating_system row json decode: {e}"),
                })?;
            let os = build_operating_system_for_snapshot(&os_row, &pg_json);
            snapshot::from_pg_json_and_os(pg_json, os).map_err(|e| DatabaseError::Internal {
                message: format!("instance snapshot from_pg_json_and_os: {e}"),
            })?
        }
        None => {
            // No OS reference: derive OS from instance columns only (legacy behavior).
            InstanceSnapshot::try_from(pg_json).map_err(|e| DatabaseError::Internal {
                message: format!("instance snapshot try_from: {e}"),
            })?
        }
    };
    Ok(Some(snapshot))
}

pub async fn find_id_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<Option<InstanceId>, DatabaseError> {
    let query = "SELECT id from instances WHERE machine_id = $1";
    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<Option<InstanceSnapshot>, DatabaseError> {
    let Some(instance_id) = find_id_by_machine_id(txn, machine_id).await? else {
        return Ok(None);
    };
    find_by_id(txn, instance_id).await
}

pub async fn find_by_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[&MachineId],
) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
    if machine_ids.is_empty() {
        return Ok(Vec::new());
    }
    let query = "SELECT row_to_json(i.*) from instances i WHERE machine_id = ANY($1)";
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(query)
        .bind(machine_ids)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    resolve_snapshots_from_json_rows(&mut *txn, rows).await
}

pub async fn find_by_extension_service(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    version: Option<ConfigVersion>,
) -> Result<Vec<InstanceSnapshot>, DatabaseError> {
    let mut builder = sqlx::QueryBuilder::new(
        r#"SELECT row_to_json(i.*) FROM instances i
            WHERE i.deleted IS NULL AND EXISTS (
                SELECT 1
                FROM jsonb_array_elements(i.extension_services_config->'service_configs') AS es_config(cfg)
                WHERE cfg->>'service_id' =
        "#,
    );
    builder.push_bind(service_id.to_string());

    if let Some(version) = version {
        builder.push(" AND cfg->>'version' = ");
        builder.push_bind(version.to_string());
    }
    builder.push(")");

    let rows: Vec<(serde_json::Value,)> = builder
        .build_query_as()
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))?;
    resolve_snapshots_from_json_rows(txn, rows).await
}

/// Returns true if any non-deleted instance has this logical partition ID in
/// config.nvlink.gpu_configs[].logical_partition_id.
pub async fn any_instance_referencing_nvlink_logical_partition(
    txn: impl DbReader<'_>,
    logical_partition_id: &NvLinkLogicalPartitionId,
) -> Result<bool, DatabaseError> {
    let query = r#"SELECT EXISTS (
        SELECT 1 FROM instances
        WHERE deleted IS NULL
          AND nvlink_config->'gpu_configs' IS NOT NULL
          AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(nvlink_config->'gpu_configs') AS gpu(g)
            WHERE g->>'logical_partition_id' = $1::text
          )
    )"#;
    sqlx::query_scalar(query)
        .bind(logical_partition_id.to_string())
        .fetch_one(txn)
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
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

/// Sets the custom_pxe_reboot_requested flag. This flag is set by the API when a tenant
/// requests a reboot with custom iPXE. The Ready handler checks this flag to initiate
/// the HostPlatformConfiguration flow. The WaitingForRebootToReady handler clears this
/// flag after setting use_custom_pxe_on_boot.
pub async fn set_custom_pxe_reboot_requested(
    machine_id: &MachineId,
    requested: bool,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE instances SET custom_pxe_reboot_requested=$1::bool WHERE machine_id=$2 RETURNING machine_id";
    let _: (MachineId,) = sqlx::query_as(query)
        .bind(requested)
        .bind(machine_id)
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
    batch_update_network_config(
        txn,
        &[(instance_id, expected_version, new_state)],
        increment_version,
    )
    .await
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
    let operating_system_id = match &config.os.variant {
        OperatingSystemVariant::Ipxe(ipxe) => {
            os_ipxe_script = ipxe.ipxe_script.clone();
            None
        }
        OperatingSystemVariant::OsImage(id) => {
            os_image_id = Some(id);
            None
        }
        OperatingSystemVariant::OperatingSystemId(id) => Some(*id),
    };

    let query = "UPDATE instances SET config_version=$1,
            operating_system_id=$2, os_ipxe_script=$3, os_user_data=$4, os_always_boot_with_ipxe=$5, os_phone_home_enabled=$6,
            os_image_id=$7, keyset_ids=$8,
            name=$9, description=$10, labels=$11::json, network_security_group_id=$14
            WHERE id=$12 AND config_version=$13
            RETURNING id";
    let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(operating_system_id)
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
    let operating_system_id = match &os.variant {
        OperatingSystemVariant::Ipxe(ipxe) => {
            os_ipxe_script = ipxe.ipxe_script.clone();
            None
        }
        OperatingSystemVariant::OsImage(id) => {
            os_image_id = Some(id);
            None
        }
        OperatingSystemVariant::OperatingSystemId(id) => Some(*id),
    };

    let query = "UPDATE instances SET config_version=$1,
            operating_system_id=$2, os_ipxe_script=$3, os_user_data=$4, os_always_boot_with_ipxe=$5, os_phone_home_enabled=$6, os_image_id=$7
            WHERE id=$8 AND config_version=$9
            RETURNING id";
    let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(operating_system_id)
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
    batch_update_ib_config(
        txn,
        &[(instance_id, expected_version, new_state)],
        increment_version,
    )
    .await
}

/// Updates the desired nvlink configuration for an instance
pub async fn update_nvlink_config(
    txn: &mut PgConnection,
    instance_id: InstanceId,
    expected_version: ConfigVersion,
    new_state: &InstanceNvLinkConfig,
    increment_version: bool,
) -> Result<(), DatabaseError> {
    batch_update_nvlink_config(
        txn,
        &[(instance_id, expected_version, new_state)],
        increment_version,
    )
    .await
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

pub async fn update_extension_services_config(
    txn: &mut PgConnection,
    instance_id: InstanceId,
    expected_version: ConfigVersion,
    new_config: &InstanceExtensionServicesConfig,
    increment_version: bool,
) -> Result<(), DatabaseError> {
    let next_version = if increment_version {
        expected_version.increment()
    } else {
        expected_version
    };

    let query = "UPDATE instances SET extension_services_config_version=$1, extension_services_config=$2::json
        WHERE id=$3 AND extension_services_config_version=$4
        RETURNING id";
    let query_result: Result<(InstanceId,), _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_config))
        .bind(instance_id)
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok((_instance_id,)) => Ok(()),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

/// Batch insert for multiple instances.
/// This is optimized for inserting many instances in a single database operation.
///
/// Note: This function expects all machines to exist and be locked before calling.
/// It will fail if any machine doesn't exist or has a mismatched instance_type_id.
pub async fn batch_persist<'a>(
    values: Vec<NewInstance<'a>>,
    txn: &mut PgConnection,
) -> DatabaseResult<Vec<InstanceSnapshot>> {
    if values.is_empty() {
        return Ok(Vec::new());
    }

    // For batch insert, we need to collect all the instance IDs and then query them back
    // because Postgres INSERT ... RETURNING with push_values doesn't work well with row_to_json
    let instance_ids: Vec<InstanceId> = values.iter().map(|v| v.instance_id).collect();

    let query = "INSERT INTO instances (
                        id,
                        machine_id,
                        operating_system_id,
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
                        instance_type_id,
                        extension_services_config,
                        extension_services_config_version,
                        nvlink_config,
                        nvlink_config_version
                    )
                    SELECT 
                            vals.id, vals.machine_id, vals.operating_system_id, vals.os_user_data, vals.os_ipxe_script,
                            vals.os_image_id, vals.os_always_boot_with_ipxe, vals.tenant_org, 
                            vals.network_config::json, vals.network_config_version, 
                            vals.ib_config::json, vals.ib_config_version, vals.keyset_ids, 
                            vals.os_phone_home_enabled, vals.name, vals.description, 
                            vals.labels::json, vals.config_version, vals.hostname, 
                            vals.network_security_group_id, true,
                            vals.instance_type_id, vals.extension_services_config::json, 
                            vals.extension_services_config_version, vals.nvlink_config::json, 
                            vals.nvlink_config_version
                    FROM (VALUES ";

    let mut qb = sqlx::QueryBuilder::new(query);

    // Build VALUES clause
    let mut separated = qb.separated(", ");
    for value in &values {
        let mut os_ipxe_script = String::new();
        let os_user_data = value.config.os.user_data.clone();
        let mut os_image_id: Option<uuid::Uuid> = None;
        let operating_system_id = match &value.config.os.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                os_ipxe_script = ipxe.ipxe_script.clone();
                None
            }
            OperatingSystemVariant::OsImage(id) => {
                os_image_id = Some(*id);
                None
            }
            OperatingSystemVariant::OperatingSystemId(id) => Some(*id),
        };

        separated.push("(");
        separated.push_bind_unseparated(value.instance_id);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.machine_id.to_string());
        separated.push_unseparated(",");
        separated.push_bind_unseparated(operating_system_id);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(os_user_data);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(os_ipxe_script);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(os_image_id);
        separated.push_unseparated(",");
        separated
            .push_bind_unseparated(value.config.os.run_provisioning_instructions_on_every_boot);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.config.tenant.tenant_organization_id.as_str());
        separated.push_unseparated(",");
        separated.push_bind_unseparated(
            serde_json::to_string(&value.config.network).unwrap_or_default(),
        );
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.network_config_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(
            serde_json::to_string(&value.config.infiniband).unwrap_or_default(),
        );
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.ib_config_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(&value.config.tenant.tenant_keyset_ids);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.config.os.phone_home_enabled);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(&value.metadata.name);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(&value.metadata.description);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(
            serde_json::to_string(&value.metadata.labels).unwrap_or_default(),
        );
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.config_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(&value.config.tenant.hostname);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(&value.config.network_security_group_id);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(&value.instance_type_id);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(
            serde_json::to_string(&value.config.extension_services).unwrap_or_default(),
        );
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.extension_services_config_version);
        separated.push_unseparated(",");
        separated
            .push_bind_unseparated(serde_json::to_string(&value.config.nvlink).unwrap_or_default());
        separated.push_unseparated(",");
        separated.push_bind_unseparated(value.nvlink_config_version);
        separated.push_unseparated(")");
    }

    qb.push(") AS vals(id, machine_id, operating_system_id, os_user_data, os_ipxe_script, os_image_id,
                       os_always_boot_with_ipxe, tenant_org, network_config, network_config_version,
                       ib_config, ib_config_version, keyset_ids, os_phone_home_enabled, name, 
                       description, labels, config_version, hostname, network_security_group_id,
                       instance_type_id, extension_services_config, extension_services_config_version,
                       nvlink_config, nvlink_config_version)
            INNER JOIN machines m ON m.id = vals.machine_id 
                AND (vals.instance_type_id IS NULL OR m.instance_type_id = vals.instance_type_id)");

    let result = qb
        .build()
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new("batch_persist", e))?;

    // Check if all instances were inserted
    // If instance_type_id doesn't match, the row won't be inserted due to the JOIN condition
    let expected_count = values.len() as u64;
    if result.rows_affected() != expected_count {
        return Err(DatabaseError::FailedPrecondition(
            "expected InstanceTypeId does not match source machine".to_string(),
        ));
    }

    // Fetch the inserted instances, resolving OS definitions as needed.
    let query = "SELECT row_to_json(i.*) FROM instances i WHERE i.id = ANY($1)";
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(query)
        .bind(&instance_ids)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    resolve_snapshots_from_json_rows(txn, rows).await
}

/// Batch update network configs for multiple instances
/// Each update contains (instance_id, expected_version, config)
/// The increment_version flag controls whether to increment the version
pub async fn batch_update_network_config(
    txn: &mut PgConnection,
    updates: &[(InstanceId, ConfigVersion, &InstanceNetworkConfig)],
    increment_version: bool,
) -> Result<(), DatabaseError> {
    if updates.is_empty() {
        return Ok(());
    }

    let expected_count = updates.len() as u64;

    // Use a CTE to batch update with version check
    let mut qb = sqlx::QueryBuilder::new(
        "UPDATE instances SET 
            network_config_version = updates.new_version,
            network_config = updates.config::json
        FROM (VALUES ",
    );

    let mut separated = qb.separated(", ");
    for (instance_id, expected_version, config) in updates {
        // Compute new_version per-row (ConfigVersion is a complex struct, can't do arithmetic in SQL)
        let new_version = if increment_version {
            expected_version.increment()
        } else {
            *expected_version
        };
        separated.push("(");
        separated.push_bind_unseparated(*instance_id);
        separated.push_unseparated("::uuid,");
        separated.push_bind_unseparated(*expected_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(new_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(serde_json::to_string(config).unwrap_or_default());
        separated.push_unseparated(")");
    }

    qb.push(
        ") AS updates(id, expected_version, new_version, config) 
        WHERE instances.id = updates.id 
        AND instances.network_config_version = updates.expected_version",
    );

    let result = qb
        .build()
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("batch_update_network_config", e))?;

    // Verify all rows were updated (version check passed)
    if result.rows_affected() != expected_count {
        return Err(DatabaseError::FailedPrecondition(
            "Network config version mismatch during batch update".to_string(),
        ));
    }

    Ok(())
}

/// Batch update IB configs for multiple instances
/// Each update contains (instance_id, expected_version, config)
pub async fn batch_update_ib_config(
    txn: &mut PgConnection,
    updates: &[(InstanceId, ConfigVersion, &InstanceInfinibandConfig)],
    increment_version: bool,
) -> Result<(), DatabaseError> {
    if updates.is_empty() {
        return Ok(());
    }

    let expected_count = updates.len() as u64;

    let mut qb = sqlx::QueryBuilder::new(
        "UPDATE instances SET 
            ib_config_version = updates.new_version,
            ib_config = updates.config::json
        FROM (VALUES ",
    );

    let mut separated = qb.separated(", ");
    for (instance_id, expected_version, config) in updates {
        let new_version = if increment_version {
            expected_version.increment()
        } else {
            *expected_version
        };
        separated.push("(");
        separated.push_bind_unseparated(*instance_id);
        separated.push_unseparated("::uuid,");
        separated.push_bind_unseparated(*expected_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(new_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(serde_json::to_string(config).unwrap_or_default());
        separated.push_unseparated(")");
    }

    qb.push(
        ") AS updates(id, expected_version, new_version, config) 
        WHERE instances.id = updates.id 
        AND instances.ib_config_version = updates.expected_version",
    );

    let result = qb
        .build()
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("batch_update_ib_config", e))?;

    // Verify all rows were updated (version check passed)
    if result.rows_affected() != expected_count {
        return Err(DatabaseError::FailedPrecondition(
            "IB config version mismatch during batch update".to_string(),
        ));
    }

    Ok(())
}

/// Batch update nvlink configs for multiple instances
/// Each update contains (instance_id, expected_version, config)
pub async fn batch_update_nvlink_config(
    txn: &mut PgConnection,
    updates: &[(InstanceId, ConfigVersion, &InstanceNvLinkConfig)],
    increment_version: bool,
) -> Result<(), DatabaseError> {
    if updates.is_empty() {
        return Ok(());
    }

    let expected_count = updates.len() as u64;

    let mut qb = sqlx::QueryBuilder::new(
        "UPDATE instances SET 
            nvlink_config_version = updates.new_version,
            nvlink_config = updates.config::json
        FROM (VALUES ",
    );

    let mut separated = qb.separated(", ");
    for (instance_id, expected_version, config) in updates {
        let new_version = if increment_version {
            expected_version.increment()
        } else {
            *expected_version
        };
        separated.push("(");
        separated.push_bind_unseparated(*instance_id);
        separated.push_unseparated("::uuid,");
        separated.push_bind_unseparated(*expected_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(new_version);
        separated.push_unseparated(",");
        separated.push_bind_unseparated(serde_json::to_string(config).unwrap_or_default());
        separated.push_unseparated(")");
    }

    qb.push(
        ") AS updates(id, expected_version, new_version, config) 
        WHERE instances.id = updates.id 
        AND instances.nvlink_config_version = updates.expected_version",
    );

    let result = qb
        .build()
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("batch_update_nvlink_config", e))?;

    // Verify all rows were updated (version check passed)
    if result.rows_affected() != expected_count {
        return Err(DatabaseError::FailedPrecondition(
            "NVLink config version mismatch during batch update".to_string(),
        ));
    }

    Ok(())
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
