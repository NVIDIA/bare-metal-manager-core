/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use forge_uuid::extension_service::ExtensionServiceId;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use super::tenant::TenantOrganizationId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExtensionServiceType {
    KubernetesPod,
}

impl std::fmt::Display for ExtensionServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionServiceType::KubernetesPod => write!(f, "kubernetes_pod"),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone)]
#[error("Extension service type \"{0}\" is not valid")]
pub struct InvalidExtensionServiceTypeError(String);

impl std::str::FromStr for ExtensionServiceType {
    type Err = InvalidExtensionServiceTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kubernetes_pod" => Ok(ExtensionServiceType::KubernetesPod),
            _ => Err(InvalidExtensionServiceTypeError(s.to_string())),
        }
    }
}

impl From<ExtensionServiceType> for rpc::DpuExtensionServiceType {
    fn from(service_type: ExtensionServiceType) -> Self {
        match service_type {
            ExtensionServiceType::KubernetesPod => rpc::DpuExtensionServiceType::KubernetesPod,
        }
    }
}

impl From<rpc::DpuExtensionServiceType> for ExtensionServiceType {
    fn from(service_type: rpc::DpuExtensionServiceType) -> Self {
        match service_type {
            rpc::DpuExtensionServiceType::KubernetesPod => ExtensionServiceType::KubernetesPod,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionService {
    pub id: ExtensionServiceId,
    pub service_type: ExtensionServiceType,
    pub name: String,
    pub tenant_organization_id: TenantOrganizationId,
    pub description: String,
    pub version_ctr: i32, // Version counter for the extension service, always incremented
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for ExtensionService {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let service_type_str: String = row.try_get("type")?;
        let service_type = service_type_str
            .parse::<ExtensionServiceType>()
            .map_err(|e| sqlx::Error::ColumnDecode {
                index: "type".to_string(),
                source: Box::new(e),
            })?;

        let tenant_organization_id: String = row.try_get("tenant_organization_id")?;

        Ok(ExtensionService {
            id: row.try_get("id")?,
            service_type,
            name: row.try_get("name")?,
            tenant_organization_id: tenant_organization_id
                .parse::<TenantOrganizationId>()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            description: row.try_get("description")?,
            version_ctr: row.try_get::<i32, _>("version_ctr")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionServiceVersionInfo {
    pub service_id: ExtensionServiceId,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub data: String,
    pub has_credential: bool,
    pub deleted: Option<DateTime<Utc>>,
}

impl From<ExtensionServiceVersionInfo> for rpc::DpuExtensionServiceVersionInfo {
    fn from(version: ExtensionServiceVersionInfo) -> Self {
        Self {
            version: version.version.to_string(),
            data: version.data,
            has_credential: version.has_credential,
            created: version.created.to_string(),
        }
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for ExtensionServiceVersionInfo {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(ExtensionServiceVersionInfo {
            service_id: row.try_get("service_id")?,
            version: row.try_get("version")?,
            data: row.try_get("data")?,
            has_credential: row.try_get("has_credential")?,
            created: row.try_get("created")?,
            deleted: row.try_get("deleted")?,
        })
    }
}

/// A snapshot of the extension service information from DB that matches rpc::ExtensionService message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionServiceSnapshot {
    pub service_id: ExtensionServiceId,
    pub service_type: ExtensionServiceType,
    pub service_name: String,
    pub tenant_organization_id: TenantOrganizationId,
    pub version_ctr: i32,
    pub latest_version: Option<ExtensionServiceVersionInfo>,
    pub active_versions: Vec<ConfigVersion>,
    pub description: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

impl<'r> FromRow<'r, PgRow> for ExtensionServiceSnapshot {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let service_id: ExtensionServiceId = row.try_get("service_id")?;
        let service_type_str: String = row.try_get("service_type")?;
        let service_type = service_type_str
            .parse::<ExtensionServiceType>()
            .map_err(|e| sqlx::Error::ColumnDecode {
                index: "type".to_string(),
                source: Box::new(e),
            })?;
        let service_name: String = row.try_get("service_name")?;
        let tenant_organization_id_str: String = row.try_get("tenant_organization_id")?;
        let tenant_organization_id: TenantOrganizationId = tenant_organization_id_str
            .parse::<TenantOrganizationId>()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let version_ctr: i32 = row.try_get("version_ctr")?;
        let description: String = row.try_get("description")?;
        let created: DateTime<Utc> = row.try_get("created")?;
        let updated: DateTime<Utc> = row.try_get("updated")?;
        let deleted: Option<DateTime<Utc>> = row.try_get("deleted")?;

        let active_versions_str: Vec<String> = row.try_get("active_versions")?;
        let active_versions: Vec<ConfigVersion> = active_versions_str
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let latest_version = row.try_get("latest_version")?;
        let latest_data = row.try_get("latest_data")?;
        let latest_has_credential = row.try_get("latest_has_credential")?;
        let latest_created = row.try_get("latest_created")?;

        let latest_service_version = match (
            latest_version,
            latest_data,
            latest_has_credential,
            latest_created,
        ) {
            (Some(version), Some(data), Some(has_credential), Some(created)) => {
                Some(ExtensionServiceVersionInfo {
                    service_id,
                    version,
                    data,
                    has_credential,
                    created,
                    deleted: None,
                })
            }
            _ => None,
        };

        Ok(ExtensionServiceSnapshot {
            service_id,
            service_type,
            service_name,
            tenant_organization_id,
            version_ctr,
            latest_version: latest_service_version,
            active_versions,
            description,
            created,
            updated,
            deleted,
        })
    }
}

impl From<ExtensionServiceSnapshot> for rpc::DpuExtensionService {
    fn from(snapshot: ExtensionServiceSnapshot) -> Self {
        Self {
            service_id: snapshot.service_id.to_string(),
            service_type: snapshot.service_type as i32,
            service_name: snapshot.service_name,
            tenant_organization_id: snapshot.tenant_organization_id.to_string(),
            version_ctr: snapshot.version_ctr,
            latest_version_info: snapshot.latest_version.map(|v| v.into()),
            active_versions: snapshot
                .active_versions
                .iter()
                .map(|v| v.to_string())
                .collect(),
            description: snapshot.description,
            created: snapshot.created.to_string(),
            updated: snapshot.updated.to_string(),
        }
    }
}
