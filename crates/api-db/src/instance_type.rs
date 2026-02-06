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

use carbide_uuid::instance_type::InstanceTypeId;
use config_version::ConfigVersion;
use model::instance_type::{InstanceType, InstanceTypeMachineCapabilityFilter};
use model::metadata::Metadata;
use sqlx::{PgConnection, Postgres};

use crate::DatabaseError;

/// Creates a new InstanceType DB record.  It enforces a unique `name` by
/// only creating if there is no active record found with the same name.
///
/// * `txn`               - A reference to an active DB transaction
/// * `new_instance_type` - A reference to a NewInstanceType struct with the
///   details of the InstanceType to create
pub async fn create(
    txn: &mut PgConnection,
    id: &InstanceTypeId,
    metadata: &Metadata,
    desired_capabilities: &[InstanceTypeMachineCapabilityFilter],
) -> Result<InstanceType, DatabaseError> {
    let query = "INSERT INTO instance_types
                (id, name, labels, description, desired_capabilities, version)
            SELECT $1::varchar, $2::varchar, $3::jsonb, $4::varchar, $5::jsonb, $6::varchar
            WHERE NOT EXISTS
                /* There should be a unique constraint on id.  The condition here is just defensive. */
                (SELECT id FROM instance_types WHERE id=$7::varchar OR (name=$8::varchar AND deleted IS NULL))
            RETURNING *";

    match sqlx::query_as::<Postgres, InstanceType>(query)
        .bind(id)
        .bind(&metadata.name)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(&metadata.description)
        .bind(sqlx::types::Json(desired_capabilities))
        .bind(ConfigVersion::initial())
        .bind(id)
        .bind(&metadata.name)
        .fetch_one(txn)
        .await
    {
        Ok(instance_type) => Ok(instance_type),
        // This error should only show up when we didn't
        // create a record because the subquery found an existing name already.
        Err(sqlx::Error::RowNotFound) => Err(DatabaseError::AlreadyFoundError {
            kind: "InstanceType",
            id: metadata.name.clone(),
        }),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

/// Returns a list of IDs for all non-deleted InstanceType records.
///
/// * `txn`        - A reference to an active DB transaction
/// * `for_update` - A boolean flag to acquire DB locks for synchronization
pub async fn find_ids(
    txn: &mut PgConnection,
    for_update: bool,
) -> Result<Vec<InstanceTypeId>, DatabaseError> {
    let mut builder =
        sqlx::QueryBuilder::new("SELECT id FROM instance_types WHERE deleted is NULL");

    if for_update {
        builder.push(" FOR UPDATE ");
    }

    builder
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(builder.sql(), err))
}

/// Queries the DB for non-deleted InstanceType records
/// based on the supplied list of IDs
///
/// * `txn`               - A reference to an active DB transaction
/// * `instance_type_ids` - A list of InstanceTypeId values to use for querying the Db for active InstanceType records
/// * `for_update`        - A boolean flag to acquire DB locks for synchronization
pub async fn find_by_ids(
    txn: &mut PgConnection,
    instance_type_ids: &[InstanceTypeId],
    for_update: bool,
) -> Result<Vec<InstanceType>, DatabaseError> {
    let mut builder =
        sqlx::QueryBuilder::new("SELECT * from instance_types WHERE deleted is NULL AND");

    builder.push(" id = ANY(");
    builder.push_bind(instance_type_ids);
    builder.push(") ");

    if for_update {
        builder.push(" FOR UPDATE ");
    }

    builder
        .build_query_as()
        .bind(instance_type_ids)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::query(builder.sql(), err))
}

/// Updates an InstanceType records in the DB.
///
/// This does **NOT** check for any machine associations.
///
/// * `txn`                  - A reference to an active DB transaction
/// * `update_instance_type` - A reference to an UpdateInstanceType struct
///   with the details of the InstanceType to update
pub async fn update(
    txn: &mut PgConnection,
    id: &InstanceTypeId,
    metadata: &Metadata,
    desired_capabilities: &[InstanceTypeMachineCapabilityFilter],
    expected_version: ConfigVersion,
) -> Result<InstanceType, DatabaseError> {
    let query = "UPDATE instance_types
            SET
                name=$1::varchar,
                labels=$2::jsonb,
                description=$3::varchar,
                desired_capabilities=$4::jsonb,
                version=$5::varchar
            WHERE
                id=$6::varchar
                AND version = $7::varchar /* This is just to be defensive.  This case is already covered when we query in advance to check and bump version */
                AND deleted IS NULL       /* Also just here to be defensive and for the same reason */
                AND NOT EXISTS
                    (SELECT id FROM instance_types WHERE id!=$8::varchar AND name=$9::varchar AND deleted IS NULL)
            RETURNING *";

    match sqlx::query_as::<Postgres, InstanceType>(query)
        .bind(&metadata.name)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&desired_capabilities))
        .bind(expected_version.increment())
        .bind(id)
        .bind(expected_version)
        .bind(id)
        .bind(&metadata.name)
        .fetch_one(txn)
        .await
    {
        Ok(instance_type) => Ok(instance_type),
        // This error should only show up when we didn't
        // update a record because the subquery found an existing name already.
        // deleted and version should have already been checked and reported
        // before calling update()
        Err(sqlx::Error::RowNotFound) => Err(DatabaseError::AlreadyFoundError {
            kind: "InstanceType",
            id: metadata.name.clone(),
        }),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

/// Soft deletes an instance type by updating the deleted column in the DB.
/// If the record with that ID is already deleted, nothing changes and Ok(None)
/// is returned.
///
/// This does **NOT** check for any machine associations.
///
/// * `txn`              - A reference to an active DB transaction
/// * `instance_type_id` - An InstanceTypeId for the InstanceType to be soft-deleted
pub async fn soft_delete(
    txn: &mut PgConnection,
    instance_type_id: &InstanceTypeId,
) -> Result<Option<InstanceTypeId>, DatabaseError> {
    let query = "UPDATE instance_types SET deleted=NOW() WHERE id=$1::varchar AND deleted is NULL RETURNING id";

    match sqlx::query_as(query)
        .bind(instance_type_id)
        .fetch_one(txn)
        .await
    {
        Ok(instance_type) => Ok(Some(instance_type)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use model::instance_type::InstanceTypeMachineCapabilityFilter;
    use model::machine::capabilities::{MachineCapabilityDeviceType, MachineCapabilityType};
    use model::metadata::Metadata;

    use super::*;

    #[crate::sqlx_test]
    async fn instance_type_crud(pool: sqlx::PgPool) {
        let mut txn = pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let id_str = "can_i_see_some_id?";

        // Prepare some attributes we can (re)use for comparison later
        let cap_attrs = InstanceTypeMachineCapabilityFilter {
            capability_type: MachineCapabilityType::Cpu,
            name: Some("pentium 4 HT".to_string()),
            frequency: Some("1.3 GHz".to_string()),
            capacity: None,
            vendor: Some("intel".to_string()),
            count: Some(1),
            hardware_revision: None,
            cores: Some(1),
            threads: Some(2),
            inactive_devices: Some(vec![2, 4]),
            device_type: Some(MachineCapabilityDeviceType::Unknown),
        };

        let update_cap_attrs = InstanceTypeMachineCapabilityFilter {
            capability_type: MachineCapabilityType::Gpu,
            name: Some("H100".to_string()),
            frequency: None,
            capacity: None,
            vendor: Some("nvidia".to_string()),
            count: None,
            hardware_revision: None,
            cores: None,
            threads: None,
            inactive_devices: None,
            device_type: Some(MachineCapabilityDeviceType::Unknown),
        };

        // Create a NewInstanceType to feed to the query
        // to create a new DB record.
        let id = id_str.parse::<InstanceTypeId>().unwrap();
        let metadata = Metadata {
            name: "the best type".to_string(),
            description: "".to_string(),
            labels: HashMap::new(),
        };

        let desired_capabilities = vec![cap_attrs.clone()];

        let cmp_id = id_str.parse::<InstanceTypeId>().unwrap();

        let instance_type = create(&mut txn, &id, &metadata, &desired_capabilities)
            .await
            .unwrap();

        assert_eq!(instance_type.version.version_nr(), 1);
        assert_eq!(instance_type.id, cmp_id);
        assert_eq!(instance_type.desired_capabilities.len(), 1);
        assert_eq!(instance_type.desired_capabilities[0], cap_attrs);

        // Get all instance type IDs in the system.
        // There should be only one.
        let res = find_ids(&mut txn, true).await.unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0], cmp_id);

        // Find all instances types for the IDs we found.
        // There should be only one.
        let res = find_by_ids(&mut txn, &res, true).await.unwrap();

        assert_eq!(res.len(), 1);

        assert_eq!(res[0].desired_capabilities.len(), 1);
        assert_eq!(res[0].desired_capabilities[0], cap_attrs);

        // Now update the instance type
        // Create an UpdateInstanceType to feed to the query
        // to create a new DB record.
        let id = id_str.parse().unwrap();
        let metadata = Metadata {
            name: "the best type".to_string(),
            description: "".to_string(),
            labels: HashMap::new(),
        };
        let desired_capabilities = vec![cap_attrs.clone(), update_cap_attrs.clone()];

        let res = update(
            &mut txn,
            &id,
            &metadata,
            &desired_capabilities,
            instance_type.version,
        )
        .await
        .unwrap();

        // Now make sure the id is what we expect and that all properties are what we expect.
        assert_eq!(res.id, cmp_id);
        assert_eq!(res.desired_capabilities.len(), 2);
        assert_eq!(res.desired_capabilities[0], cap_attrs);
        assert_eq!(res.desired_capabilities[1], update_cap_attrs);

        // Now soft delete the instance type
        let res = soft_delete(&mut txn, &cmp_id).await.unwrap();

        // Make sure we changed what we expected to change
        assert_eq!(res, Some(cmp_id.clone()));

        // Now soft delete the instance type AGAIN
        let res = soft_delete(&mut txn, &cmp_id).await.unwrap();

        // Make sure we get nothing back because nothing changed.
        assert_eq!(res, None);

        txn.commit().await.unwrap();
    }
}
