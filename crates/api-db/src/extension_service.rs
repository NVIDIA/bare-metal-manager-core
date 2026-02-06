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

use std::collections::HashMap;

use carbide_uuid::extension_service::ExtensionServiceId;
use config_version::{ConfigVersion, ConfigVersionChange};
use model::extension_service::{
    ExtensionService, ExtensionServiceObservability, ExtensionServiceSnapshot,
    ExtensionServiceType, ExtensionServiceVersionInfo,
};
use model::tenant::TenantOrganizationId;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

/// Creates a new extension service and creates its initial extension service version.
/// It enforces a unique `(tenant_organization_id, name)` combination.
///
/// # Parameters
/// * `txn`                    - A reference to an active DB transaction
/// * `service_type`           - The type of the extension service
/// * `service_name`           - The name of the extension service
/// * `description`            - The description of the extension service
/// * `data`                   - Data of the initial version of the extension service
/// * `observability`          - Observability config for the extension service
/// * `has_credential`         - Whether the initial extension service version has a credential
///   stored in the vault
///
#[allow(clippy::too_many_arguments)]
pub async fn create(
    txn: &mut PgConnection,
    version: ConfigVersion,
    service_id: &ExtensionServiceId,
    service_type: &ExtensionServiceType,
    service_name: &str,
    tenant_organization_id: &TenantOrganizationId,
    description: Option<&str>,
    data: &str,
    observability: Option<ExtensionServiceObservability>,
    has_credential: bool,
) -> Result<(ExtensionService, ExtensionServiceVersionInfo), DatabaseError> {
    let initial_version_ctr = 1;

    // First create the extension service record
    let service_query = "INSERT INTO extension_services
            (id, type, name, description, tenant_organization_id, version_ctr)
            VALUES ($1, $2::varchar, $3::varchar, $4::varchar, $5::varchar, $6::integer) 
            RETURNING id, type, name, description, tenant_organization_id, version_ctr, created, updated, deleted";

    let service = match sqlx::query_as::<_, ExtensionService>(service_query)
        .bind(service_id)
        .bind(service_type.to_string())
        .bind(service_name)
        .bind(description.unwrap_or(""))
        .bind(tenant_organization_id.to_string())
        .bind(initial_version_ctr)
        .fetch_one(&mut *txn)
        .await
    {
        Ok(service) => service,
        Err(sqlx::Error::Database(db_err))
            if db_err.is_unique_violation()
                && db_err.constraint() == Some("extension_services_tenant_lowername_unique") =>
        {
            return Err(DatabaseError::AlreadyFoundError {
                kind: "extension_service",
                id: format!("{}:{}", service_type, service_name),
            });
        }
        Err(e) => return Err(DatabaseError::query(service_query, e)),
    };

    // Insert the initial version using the service id
    let service_id = service.id;

    let version_query = "INSERT INTO extension_service_versions 
            (service_id, version, data, observability, has_credential)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING service_id, version, data, observability, has_credential, created, deleted";

    let version = sqlx::query_as::<_, ExtensionServiceVersionInfo>(version_query)
        .bind(service_id)
        .bind(version.to_string())
        .bind(data)
        .bind(observability.map(sqlx::types::Json))
        .bind(has_credential)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(version_query, e))?;

    Ok((service, version))
}

/// Updates an extension service by creating a new version.
/// - Always bumps `updated = now()` on the parent service and optionally updates metadata
///   (name/description)
/// - Inserts a new version with the next version number (1 + current latest version)
/// - Sets `has_credential` on the new version as provided
///
/// # Parameters
/// * `txn`                    - A reference to an active DB transaction
/// * `service_id`             - The id of the extension service to insert new version for
/// * `service_name`           - Optional new name of the extension service, must be unique within the tenant organization
/// * `description`            - Optional new description of the extension service
/// * `data`                   - Data of the new version of the extension service
/// * `observability`          - Observability config for the extension service
/// * `has_credential`         - Whether the new extension service version has a credential stored
///   in vault
///
#[allow(clippy::too_many_arguments)]
pub async fn update(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    service_name: Option<&str>,
    description: Option<&str>,
    data: &str,
    observability: Option<ExtensionServiceObservability>,
    has_credential: bool,
    config_version_change: ConfigVersionChange,
) -> Result<(ExtensionService, ExtensionServiceVersionInfo), DatabaseError> {
    // Update the "updated" timestamp of the extension service, and optionally update any provided
    // metadata (name, description)
    let mut builder =
        sqlx::QueryBuilder::new("UPDATE extension_services SET updated = CURRENT_TIMESTAMP");

    if let Some(name) = service_name {
        builder.push(", name = ");
        builder.push_bind(name);
    }
    if let Some(desc) = description {
        builder.push(", description = ");
        builder.push_bind(desc);
    }
    builder
        .push(", version_ctr = ")
        .push_bind(config_version_change.new.version_nr().cast_signed());
    builder.push(" WHERE id = ");
    builder.push_bind(service_id);
    builder
        .push(" AND version_ctr = ")
        .push_bind(config_version_change.current.version_nr().cast_signed());
    builder.push(" AND deleted IS NULL");
    builder.push(" RETURNING id, type, name, description, tenant_organization_id, version_ctr, created, updated, deleted");

    let updated_service = match builder
        .build_query_as::<ExtensionService>()
        .fetch_one(&mut *txn)
        .await
    {
        Ok(service) => service,
        Err(sqlx::Error::RowNotFound) => {
            return Err(DatabaseError::NotFoundError {
                kind: "extension_service",
                id: service_id.to_string(),
            });
        }
        Err(sqlx::Error::Database(db_err))
            if db_err.is_unique_violation()
                && db_err.constraint() == Some("extension_services_tenant_lowername_unique")
                && service_name.is_some() =>
        {
            return Err(DatabaseError::AlreadyFoundError {
                kind: "extension_service",
                id: format!("conflict on name {}", service_name.unwrap()),
            });
        }
        Err(e) => return Err(DatabaseError::query(builder.sql(), e)),
    };

    // Insert the new version with the next version number.
    // Since all updates will first take the extension service row for update, we do not need to worry
    // about concurrent update issue here.
    let version_query =
        "INSERT INTO extension_service_versions (service_id, version, data, observability, has_credential)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING service_id, version, data, observability, has_credential, created, deleted";

    let new_version = sqlx::query_as::<_, ExtensionServiceVersionInfo>(version_query)
        .bind(service_id)
        .bind(config_version_change.new)
        .bind(data)
        .bind(observability.map(sqlx::types::Json))
        .bind(has_credential)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(version_query, e))?;

    Ok((updated_service, new_version))
}

pub async fn update_metadata(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    service_name: Option<&str>,
    description: Option<&str>,
) -> Result<ExtensionService, DatabaseError> {
    // Update the "updated" timestamp of the extension service, and optionally update any provided
    // metadata (name, description)
    let mut builder =
        sqlx::QueryBuilder::new("UPDATE extension_services SET updated = CURRENT_TIMESTAMP");

    if let Some(name) = service_name {
        builder.push(", name = ");
        builder.push_bind(name);
    }
    if let Some(desc) = description {
        builder.push(", description = ");
        builder.push_bind(desc);
    }
    builder.push(" WHERE id = ");
    builder.push_bind(service_id);
    builder.push(" AND deleted IS NULL");
    builder.push(" RETURNING id, type, name, description, tenant_organization_id, version_ctr, created, updated, deleted");

    let updated_service = match builder
        .build_query_as::<ExtensionService>()
        .fetch_one(&mut *txn)
        .await
    {
        Ok(service) => service,
        Err(sqlx::Error::RowNotFound) => {
            return Err(DatabaseError::NotFoundError {
                kind: "extension_service",
                id: service_id.to_string(),
            });
        }
        Err(sqlx::Error::Database(db_err))
            if db_err.is_unique_violation()
                && db_err.constraint() == Some("extension_services_tenant_lowername_unique")
                && service_name.is_some() =>
        {
            return Err(DatabaseError::AlreadyFoundError {
                kind: "extension_service",
                id: format!("conflict on name {}", service_name.unwrap()),
            });
        }
        Err(e) => return Err(DatabaseError::query(builder.sql(), e)),
    };

    Ok(updated_service)
}

/// Finds the IDs of extension services, optionally filtered by type, name, and tenant organization ID.
///
/// # Parameters
/// * `txn`          - A reference to an active DB transaction
/// * `service_type` - Optional filter on the type of the extension service
/// * `service_name` - Optional filter by case-insensitive exact match on service name
/// * `tenant_organization_id` - Optional filter by tenant organization ID
/// * `for_update`   - A boolean flag to acquire DB locks for synchronization
///
/// # Returns
/// A vector of matching `ExtensionServiceId`s (may be empty).
///
pub async fn find_ids(
    txn: &mut PgConnection,
    service_type: Option<ExtensionServiceType>,
    service_name: Option<&str>,
    tenant_organization_id: Option<&TenantOrganizationId>,
    for_update: bool,
) -> Result<Vec<ExtensionServiceId>, DatabaseError> {
    let mut builder =
        sqlx::QueryBuilder::new("SELECT id FROM extension_services WHERE deleted IS NULL");

    if let Some(service_type) = service_type {
        builder.push(" AND type = ");
        builder.push_bind(service_type.to_string());
    }

    if let Some(name) = service_name {
        // Extension service name is case-insensitive
        builder
            .push(" AND lower(name) = lower(")
            .push_bind(name)
            .push(")");
    }

    if let Some(tenant_organization_id) = tenant_organization_id {
        builder.push(" AND tenant_organization_id = ");
        builder.push_bind(tenant_organization_id.to_string());
    }

    builder.push(" ORDER BY created DESC");

    if for_update {
        builder.push(" FOR UPDATE");
    }

    builder
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))
}

/// Finds extension services by their IDs.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `ids`        - A list of extension service IDs to query
/// * `for_update` - Whether to lock the extension services for update
///
pub async fn find_by_ids(
    txn: &mut PgConnection,
    ids: &[ExtensionServiceId],
    for_update: bool,
) -> DatabaseResult<Vec<ExtensionService>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut builder = sqlx::QueryBuilder::new(
        "SELECT id, type, name, description, tenant_organization_id, version_ctr, created, updated, deleted FROM
         extension_services WHERE deleted IS NULL AND id = ANY(",
    );
    builder.push_bind(ids);
    builder.push(")");

    if for_update {
        builder.push(" FOR UPDATE");
    }

    builder
        .build_query_as::<ExtensionService>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))
}

pub async fn find_snapshots_by_ids(
    txn: &mut PgConnection,
    ids: &[ExtensionServiceId],
) -> DatabaseResult<Vec<ExtensionServiceSnapshot>> {
    // We order the active versions using the version number in descending order
    let query = "WITH versions AS (
        SELECT 
            service_id, version, data, observability, has_credential, created,
            (split_part(split_part(version, '-', 1), 'V', 2))::integer AS version_nr
        FROM extension_service_versions
        WHERE deleted IS NULL AND service_id = ANY($1)
    ),
    agg AS (
        SELECT service_id,
            ARRAY_AGG(version ORDER BY version_nr DESC, created DESC) AS active_versions,
            (ARRAY_AGG(version ORDER BY version_nr DESC, created DESC))[1] AS latest_version
        FROM versions
        GROUP BY service_id
    )
    SELECT
        s.id AS service_id,
        s.name AS service_name,
        s.type AS service_type,
        s.version_ctr AS version_ctr,
        s.description AS description,
        s.tenant_organization_id AS tenant_organization_id,
        s.created AS created,
        s.updated AS updated,
        s.deleted AS deleted,
        a.active_versions AS active_versions,
        a.latest_version AS latest_version,
        v.data as latest_data,
        v.observability as latest_observability,
        v.has_credential as latest_has_credential,
        v.created as latest_created
    FROM extension_services s
    LEFT JOIN agg a ON a.service_id = s.id
    LEFT JOIN versions v ON v.service_id = s.id AND v.version = a.latest_version
    WHERE s.deleted IS NULL AND s.id = ANY($1) ORDER BY s.created DESC";

    sqlx::query_as::<_, ExtensionServiceSnapshot>(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Finds a specific version of an extension service, or the latest version if not specified.
/// Returns a NotFoundError if the version is not found.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service
/// * `version`    - Optional specific version number to retrieve. If None, returns the latest version
///
pub async fn find_version_info(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    version: Option<ConfigVersion>,
) -> DatabaseResult<ExtensionServiceVersionInfo> {
    // We check if the extension service exists first to return a precise service not found error
    let service_query = "SELECT id FROM extension_services WHERE id = $1 AND deleted IS NULL";

    match sqlx::query_scalar::<_, uuid::Uuid>(service_query)
        .bind(service_id)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(service_query, e))?
    {
        Some(_) => {}
        None => {
            return Err(DatabaseError::NotFoundError {
                kind: "extension_service",
                id: service_id.to_string(),
            });
        }
    }

    // Build the version lookup query.
    let mut builder = sqlx::QueryBuilder::new(
        "SELECT service_id, version, data, observability, has_credential, created, deleted \
         FROM extension_service_versions \
         WHERE deleted IS NULL AND service_id = ",
    );
    builder.push_bind(service_id);

    if let Some(v) = version {
        builder.push(" AND version = ");
        builder.push_bind(v);
    } else {
        builder.push(
            " ORDER BY (split_part(split_part(version, '-', 1), 'V', 2))::integer DESC LIMIT 1",
        );
    }

    let query = builder.build_query_as::<ExtensionServiceVersionInfo>();
    match query.fetch_one(txn).await {
        Ok(ver) => Ok(ver),
        Err(sqlx::Error::RowNotFound) => {
            let id_text = if let Some(v) = version {
                format!("{}/{}", service_id, v)
            } else {
                format!("{}/{}", service_id, "latest")
            };
            Err(DatabaseError::NotFoundError {
                kind: "extension_service_version",
                id: id_text,
            })
        }
        Err(e) => Err(DatabaseError::query(builder.sql(), e)),
    }
}

/// Finds version infos for a given extension service, optionally filtered by version numbers.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service
/// * `versions`   - Optional slice of version numbers to filter by. If None, returns all version infos.
///
pub async fn find_versions_info(
    txn: &mut PgConnection,
    service_id: &ExtensionServiceId,
    versions: Option<&[ConfigVersion]>,
) -> DatabaseResult<Vec<ExtensionServiceVersionInfo>> {
    // Build the version lookup query.
    let mut builder = sqlx::QueryBuilder::new(
        "SELECT service_id, version, data, observability, has_credential, created, deleted \
     FROM extension_service_versions \
     WHERE deleted IS NULL AND service_id = ",
    );
    builder.push_bind(service_id);

    if let Some(versions) = versions {
        builder.push(" AND version = ANY(");
        builder.push_bind(
            versions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>(),
        );
        builder.push(")");
    }
    builder.push(" ORDER BY (split_part(split_part(version, '-', 1), 'V', 2))::integer DESC");

    let query = builder.build_query_as::<ExtensionServiceVersionInfo>();
    match query.fetch_all(txn).await {
        Ok(versions) => Ok(versions),
        Err(e) => Err(DatabaseError::query(builder.sql(), e)),
    }
}

/// Finds all non-deleted version numbers for a given extension service.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service
///
pub async fn find_all_versions(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
) -> DatabaseResult<Vec<ConfigVersion>> {
    let query = "SELECT version FROM extension_service_versions WHERE deleted IS NULL AND service_id = $1 ORDER BY (split_part(split_part(version, '-', 1), 'V', 2))::integer DESC";

    sqlx::query_scalar::<_, ConfigVersion>(query)
        .bind(service_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Finds all active versions for a given list of extension service IDs, optionally locked the
/// services for update.
///
/// This is a helper function for checking validity of instance extension service configuration.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_ids` - A list of extension service IDs to query
///
/// # Returns
/// A map of extension service IDs to their active versions
///
pub async fn find_versions_by_service_ids(
    txn: &mut PgConnection,
    service_ids: &[ExtensionServiceId],
    for_update: bool,
) -> DatabaseResult<HashMap<ExtensionServiceId, Vec<ConfigVersion>>> {
    if service_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut builder = sqlx::QueryBuilder::new(
        "SELECT s.id AS service_id, v.version AS version
        FROM extension_services s
        JOIN extension_service_versions v ON s.id = v.service_id
        WHERE s.deleted IS NULL
          AND v.deleted IS NULL
          AND s.id = ANY(",
    );
    builder.push_bind(service_ids);
    builder.push(
        ")
        ORDER BY s.id, (split_part(split_part(v.version, '-', 1), 'V', 2))::integer DESC",
    );
    if for_update {
        builder.push(" FOR UPDATE");
    }

    let versions = builder
        .build_query_as::<(ExtensionServiceId, ConfigVersion)>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))?;

    let mut service_versions: HashMap<ExtensionServiceId, Vec<ConfigVersion>> = HashMap::new();
    for (id, version) in versions {
        service_versions.entry(id).or_default().push(version);
    }

    Ok(service_versions)
}

/// Soft deletes an extension service by setting its deleted timestamp.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service to soft delete
///
/// # Returns
/// * `Some(service_id)` if the service was successfully soft deleted
/// * `None` if the service is already deleted or not found
/// * `Err` if there is a database error other than RowNotFound
///
pub async fn soft_delete_service(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
) -> DatabaseResult<Option<ExtensionServiceId>> {
    let query = "UPDATE extension_services SET deleted = NOW(), updated = NOW()
            WHERE id = $1 AND deleted IS NULL
            RETURNING id";

    match sqlx::query_as::<_, ExtensionServiceId>(query)
        .bind(service_id)
        .fetch_one(txn)
        .await
    {
        Ok(service_id) => Ok(Some(service_id)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

/// Soft deletes specific versions of an extension service by setting their deleted timestamp.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service
/// * `versions`   - Optional slice of version numbers to soft delete, rf empty, all non-deleted
///   versions will be soft deleted.
///
/// # Returns
/// A vector of version numbers that were successfully soft deleted (excluding ones that were
/// already deleted or missing).
///
pub async fn soft_delete_versions(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    versions: &[ConfigVersion],
) -> DatabaseResult<Vec<ConfigVersion>> {
    let mut builder = sqlx::QueryBuilder::new(
        "UPDATE extension_service_versions SET deleted = NOW() WHERE deleted IS NULL",
    );
    builder.push(" AND service_id = ");
    builder.push_bind(service_id);
    if !versions.is_empty() {
        builder.push(" AND version = ANY(");
        builder.push_bind(
            versions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>(),
        );
        builder.push(")");
    }
    builder.push(" RETURNING version");

    builder
        .build_query_scalar::<ConfigVersion>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))
}

/// Checks if the extension service is in use by any instance.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service
/// * `versions`   - Optional slice of version numbers to check if the service is in use by any instance
///
pub async fn is_service_in_use(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    versions: &[ConfigVersion],
) -> DatabaseResult<bool> {
    let mut builder = sqlx::QueryBuilder::new(
        r#"
        SELECT 1
          FROM instances
         WHERE deleted IS NULL
           AND EXISTS (
                 SELECT 1
                   FROM jsonb_array_elements(extension_services_config->'service_configs') AS cfg
                  WHERE cfg->>'service_id' = "#,
    );
    builder.push_bind(service_id.to_string());
    builder.push("::text");

    // If filtering by versions, add a version filter
    if !versions.is_empty() {
        builder.push(" AND cfg->>'version' = ANY(");
        builder.push_bind(
            versions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>(),
        );
        builder.push(")");
    }

    builder.push(") LIMIT 1");

    let exists = builder
        .build_query_scalar::<i32>()
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))?
        .is_some();

    Ok(exists)
}

/// Returns the subset of (active) versions of an extension service that have credentials.
///
/// # Parameters
/// * `txn`        - A reference to an active DB transaction
/// * `service_id` - The ID of the extension service
/// * `versions`   - Optional slice of version numbers to check if the service has credentials
///
pub async fn find_versions_with_credentials(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
    versions: &[ConfigVersion],
) -> DatabaseResult<Vec<ConfigVersion>> {
    let mut builder = sqlx::QueryBuilder::new(
        "SELECT version \
           FROM extension_service_versions \
          WHERE service_id = ",
    );
    builder.push_bind(service_id);
    builder.push(" AND deleted IS NULL AND has_credential = TRUE");

    if !versions.is_empty() {
        builder.push(" AND version = ANY(");
        builder.push_bind(
            versions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>(),
        );
        builder.push(")");
    }
    builder.push(" ORDER BY (split_part(split_part(version, '-', 1), 'V', 2))::integer DESC");

    builder
        .build_query_scalar::<ConfigVersion>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))
}

/// Set the extension service's updated timestamp.
pub async fn set_updated_timestamp(
    txn: &mut PgConnection,
    service_id: ExtensionServiceId,
) -> DatabaseResult<()> {
    let query = "UPDATE extension_services SET updated = NOW() \
             WHERE id = $1 AND deleted IS NULL";
    sqlx::query(query)
        .bind(service_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}
