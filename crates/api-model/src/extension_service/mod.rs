/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::extension_service::ExtensionServiceId;
use chrono::prelude::*;
use config_version::ConfigVersion;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use super::tenant::TenantOrganizationId;

const MAX_OBSERVABILITY_CONFIG_NAME: usize = 64;
const MAX_OBSERVABILITY_PROPERTY_LEN: usize = 128;

static PROM_ENDPOINT_BAD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-zA-Z0-9:\-]+").unwrap());
static LOG_PATH_BAD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-zA-Z0-9\-\_\/\.\@]+").unwrap());

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
    pub observability: Option<ExtensionServiceObservability>,
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
            observability: version.observability.map(|o| o.into()),
        }
    }
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

impl From<ExtensionServiceSnapshot> for rpc::DpuExtensionService {
    fn from(snapshot: ExtensionServiceSnapshot) -> Self {
        Self {
            service_id: snapshot.service_id.into(),
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

impl From<ExtensionServiceObservability> for rpc::DpuExtensionServiceObservability {
    fn from(o: ExtensionServiceObservability) -> Self {
        Self {
            configs: o.configs.into_iter().map(|c| c.into()).collect(),
        }
    }
}

impl TryFrom<rpc::DpuExtensionServiceObservability> for ExtensionServiceObservability {
    type Error = RpcDataConversionError;

    fn try_from(o: rpc::DpuExtensionServiceObservability) -> Result<Self, Self::Error> {
        Ok(Self {
            configs: o
                .configs
                .into_iter()
                .map(|c| c.try_into())
                .collect::<Result<Vec<ExtensionServiceObservabilityConfig>, _>>()?,
        })
    }
}

impl From<ExtensionServiceObservabilityConfig> for rpc::DpuExtensionServiceObservabilityConfig {
    fn from(o: ExtensionServiceObservabilityConfig) -> Self {
        Self {
            name: o.name,
            config: Some(match o.config {
                ExtensionServiceObservabilityConfigType::Prometheus(c) => {
                    rpc::dpu_extension_service_observability_config::Config::Prometheus(
                        rpc::DpuExtensionServiceObservabilityConfigPrometheus {
                            scrape_interval_seconds: c.scrape_interval_seconds,
                            endpoint: c.endpoint,
                        },
                    )
                }
                ExtensionServiceObservabilityConfigType::Logging(c) => {
                    rpc::dpu_extension_service_observability_config::Config::Logging(
                        rpc::DpuExtensionServiceObservabilityConfigLogging { path: c.path },
                    )
                }
            }),
        }
    }
}

impl TryFrom<rpc::DpuExtensionServiceObservabilityConfig> for ExtensionServiceObservabilityConfig {
    type Error = RpcDataConversionError;

    fn try_from(c: rpc::DpuExtensionServiceObservabilityConfig) -> Result<Self, Self::Error> {
        let Some(config) = c.config else {
            return Err(RpcDataConversionError::MissingArgument(
                "DpuExtensionServiceObservability.config",
            ));
        };

        if let Some(ref name) = c.name
            && name.len() > MAX_OBSERVABILITY_CONFIG_NAME
        {
            return Err(RpcDataConversionError::InvalidValue(
                "DpuExtensionServiceObservability.name".to_string(),
                format!("length exceeds {MAX_OBSERVABILITY_CONFIG_NAME}"),
            ));
        }

        Ok(Self {
            name: c.name,
            config: match config {
                rpc::dpu_extension_service_observability_config::Config::Prometheus(c) => {
                    if c.endpoint.len() > MAX_OBSERVABILITY_PROPERTY_LEN {
                        return Err(RpcDataConversionError::InvalidValue(
                            "DpuExtensionServiceObservability.config.endpoint".to_string(),
                            format!("length exceeds {MAX_OBSERVABILITY_PROPERTY_LEN}"),
                        ));
                    }

                    if PROM_ENDPOINT_BAD_RE.is_match(&c.endpoint) {
                        return Err(RpcDataConversionError::InvalidValue(
                            "DpuExtensionServiceObservability.config.endpoint".to_string(),
                            format!(
                                "characters that match the pattern `{}` are invalid",
                                PROM_ENDPOINT_BAD_RE.as_str()
                            ),
                        ));
                    }

                    ExtensionServiceObservabilityConfigType::Prometheus(
                        ExtensionServiceObservabilityConfigTypePrometheus {
                            scrape_interval_seconds: c.scrape_interval_seconds,
                            endpoint: c.endpoint,
                        },
                    )
                }
                rpc::dpu_extension_service_observability_config::Config::Logging(c) => {
                    if c.path.len() > MAX_OBSERVABILITY_PROPERTY_LEN {
                        return Err(RpcDataConversionError::InvalidValue(
                            "DpuExtensionServiceObservability.config.path".to_string(),
                            format!("length exceeds {MAX_OBSERVABILITY_PROPERTY_LEN}"),
                        ));
                    }

                    if LOG_PATH_BAD_RE.is_match(&c.path) {
                        return Err(RpcDataConversionError::InvalidValue(
                            "DpuExtensionServiceObservability.config.path".to_string(),
                            format!(
                                "characters that match the pattern `{}` are invalid",
                                LOG_PATH_BAD_RE.as_str()
                            ),
                        ));
                    }

                    ExtensionServiceObservabilityConfigType::Logging(
                        ExtensionServiceObservabilityConfigTypeLogging { path: c.path },
                    )
                }
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use ::rpc::forge::dpu_extension_service_observability_config::Config;
    use ::rpc::forge::{self as rpc};

    use super::*;

    #[test]
    fn test_observability_config_from_rpc() {
        // Try a bad name
        ExtensionServiceObservabilityConfig::try_from(
            rpc::DpuExtensionServiceObservabilityConfig {
                name: Some("a".repeat(1024)),
                config: Some(Config::Logging(
                    rpc::DpuExtensionServiceObservabilityConfigLogging {
                        path: "/dev/null".to_string(),
                    },
                )),
            },
        )
        .unwrap_err();

        // Try a missing config
        ExtensionServiceObservabilityConfig::try_from(
            rpc::DpuExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: None,
            },
        )
        .unwrap_err();

        // Try a bad log path size
        ExtensionServiceObservabilityConfig::try_from(
            rpc::DpuExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: Some(Config::Logging(
                    rpc::DpuExtensionServiceObservabilityConfigLogging {
                        path: "/dev/null".repeat(1024),
                    },
                )),
            },
        )
        .unwrap_err();

        // Try a bad log path
        ExtensionServiceObservabilityConfig::try_from(
            rpc::DpuExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: Some(Config::Logging(
                    rpc::DpuExtensionServiceObservabilityConfigLogging {
                        path: "/dev/null$$$$$$".repeat(1024),
                    },
                )),
            },
        )
        .unwrap_err();

        // Try a bad endpoint
        ExtensionServiceObservabilityConfig::try_from(
            rpc::DpuExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: Some(Config::Prometheus(
                    rpc::DpuExtensionServiceObservabilityConfigPrometheus {
                        endpoint: "localhost".repeat(1024),
                        scrape_interval_seconds: 30,
                    },
                )),
            },
        )
        .unwrap_err();

        // Try another bad endpoint using bad characters
        ExtensionServiceObservabilityConfig::try_from(
            rpc::DpuExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: Some(Config::Prometheus(
                    rpc::DpuExtensionServiceObservabilityConfigPrometheus {
                        endpoint: "/this/is/not/valid".repeat(1024),
                        scrape_interval_seconds: 30,
                    },
                )),
            },
        )
        .unwrap_err();

        // Try a good prom config
        assert_eq!(
            ExtensionServiceObservabilityConfig::try_from(
                rpc::DpuExtensionServiceObservabilityConfig {
                    name: Some("a".repeat(10)),
                    config: Some(Config::Prometheus(
                        rpc::DpuExtensionServiceObservabilityConfigPrometheus {
                            endpoint: "localhost:8080".to_string(),
                            scrape_interval_seconds: 30,
                        },
                    )),
                }
            )
            .unwrap(),
            ExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: ExtensionServiceObservabilityConfigType::Prometheus(
                    ExtensionServiceObservabilityConfigTypePrometheus {
                        endpoint: "localhost:8080".to_string(),
                        scrape_interval_seconds: 30
                    }
                )
            }
        );

        // Try a good logging config
        assert_eq!(
            ExtensionServiceObservabilityConfig::try_from(
                rpc::DpuExtensionServiceObservabilityConfig {
                    name: Some("a".repeat(10)),
                    config: Some(Config::Logging(
                        rpc::DpuExtensionServiceObservabilityConfigLogging {
                            path: "/dev/null@home".to_string(),
                        },
                    )),
                }
            )
            .unwrap(),
            ExtensionServiceObservabilityConfig {
                name: Some("a".repeat(10)),
                config: ExtensionServiceObservabilityConfigType::Logging(
                    ExtensionServiceObservabilityConfigTypeLogging {
                        path: "/dev/null@home".to_string(),
                    }
                )
            }
        );
    }
}
