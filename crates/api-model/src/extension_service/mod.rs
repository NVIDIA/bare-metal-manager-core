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

use carbide_uuid::extension_service::ExtensionServiceId;
use chrono::prelude::*;
use config_version::ConfigVersion;
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
    pub observability: Option<ExtensionServiceObservability>,
    pub has_credential: bool,
    pub deleted: Option<DateTime<Utc>>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for ExtensionServiceVersionInfo {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let obvs: Option<sqlx::types::Json<ExtensionServiceObservability>> =
            row.try_get("observability")?;

        Ok(ExtensionServiceVersionInfo {
            service_id: row.try_get("service_id")?,
            version: row.try_get("version")?,
            data: row.try_get("data")?,
            has_credential: row.try_get("has_credential")?,
            created: row.try_get("created")?,
            deleted: row.try_get("deleted")?,
            observability: obvs.map(|o| o.0),
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

        let latest_observability: Option<sqlx::types::Json<ExtensionServiceObservability>> =
            row.try_get("latest_observability")?;

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
                    observability: latest_observability.map(|o| o.0),
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

/// Observability configuration options for an extension service version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionServiceObservabilityConfigTypePrometheus {
    pub scrape_interval_seconds: u32,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionServiceObservabilityConfigTypeLogging {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExtensionServiceObservabilityConfigType {
    Prometheus(ExtensionServiceObservabilityConfigTypePrometheus),
    Logging(ExtensionServiceObservabilityConfigTypeLogging),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionServiceObservabilityConfig {
    pub name: Option<String>,
    pub config: ExtensionServiceObservabilityConfigType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionServiceObservability {
    pub configs: Vec<ExtensionServiceObservabilityConfig>,
}
