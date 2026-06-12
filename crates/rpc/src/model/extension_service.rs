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

use model::extension_service::{
    ExtensionServiceObservability, ExtensionServiceObservabilityConfig,
    ExtensionServiceObservabilityConfigType, ExtensionServiceObservabilityConfigTypeLogging,
    ExtensionServiceObservabilityConfigTypePrometheus, ExtensionServiceSnapshot,
    ExtensionServiceType, ExtensionServiceVersionInfo,
};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::errors::RpcDataConversionError;
use crate::forge as rpc;

const MAX_OBSERVABILITY_CONFIG_NAME: usize = 64;
const MAX_OBSERVABILITY_PROPERTY_LEN: usize = 128;

static PROM_ENDPOINT_BAD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-zA-Z0-9:\-]+").unwrap());
static LOG_PATH_BAD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^a-zA-Z0-9\-\_\/\.\@]+").unwrap());

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
    use carbide_test_support::{Case, Check, Outcome::*, check_cases, check_values};
    use carbide_uuid::extension_service::ExtensionServiceId;
    use chrono::{TimeZone, Utc};
    use config_version::ConfigVersion;
    use uuid::Uuid;

    use super::*;
    use crate::forge::dpu_extension_service_observability_config::Config;
    use crate::forge::{self as rpc};

    /// Build a domain observability config carrying a prometheus variant.
    fn prom_config(
        name: Option<&str>,
        endpoint: &str,
        scrape: u32,
    ) -> ExtensionServiceObservabilityConfig {
        ExtensionServiceObservabilityConfig {
            name: name.map(str::to_string),
            config: ExtensionServiceObservabilityConfigType::Prometheus(
                ExtensionServiceObservabilityConfigTypePrometheus {
                    scrape_interval_seconds: scrape,
                    endpoint: endpoint.to_string(),
                },
            ),
        }
    }

    /// Build a domain observability config carrying a logging variant.
    fn log_config(name: Option<&str>, path: &str) -> ExtensionServiceObservabilityConfig {
        ExtensionServiceObservabilityConfig {
            name: name.map(str::to_string),
            config: ExtensionServiceObservabilityConfigType::Logging(
                ExtensionServiceObservabilityConfigTypeLogging {
                    path: path.to_string(),
                },
            ),
        }
    }

    /// Build an rpc observability config wrapping a prometheus oneof variant.
    fn rpc_prom(
        name: Option<&str>,
        endpoint: &str,
        scrape: u32,
    ) -> rpc::DpuExtensionServiceObservabilityConfig {
        rpc::DpuExtensionServiceObservabilityConfig {
            name: name.map(str::to_string),
            config: Some(Config::Prometheus(
                rpc::DpuExtensionServiceObservabilityConfigPrometheus {
                    endpoint: endpoint.to_string(),
                    scrape_interval_seconds: scrape,
                },
            )),
        }
    }

    /// Build an rpc observability config wrapping a logging oneof variant.
    fn rpc_log(name: Option<&str>, path: &str) -> rpc::DpuExtensionServiceObservabilityConfig {
        rpc::DpuExtensionServiceObservabilityConfig {
            name: name.map(str::to_string),
            config: Some(Config::Logging(
                rpc::DpuExtensionServiceObservabilityConfigLogging {
                    path: path.to_string(),
                },
            )),
        }
    }

    #[test]
    fn service_type_to_rpc_round_trips_each_arm() {
        check_values(
            [Check {
                scenario: "kubernetes pod maps to rpc kubernetes pod",
                input: ExtensionServiceType::KubernetesPod,
                expect: rpc::DpuExtensionServiceType::KubernetesPod,
            }],
            rpc::DpuExtensionServiceType::from,
        );
    }

    #[test]
    fn service_type_from_rpc_round_trips_each_arm() {
        check_values(
            [Check {
                scenario: "rpc kubernetes pod maps to domain kubernetes pod",
                input: rpc::DpuExtensionServiceType::KubernetesPod,
                expect: ExtensionServiceType::KubernetesPod,
            }],
            ExtensionServiceType::from,
        );
    }

    #[test]
    fn observability_config_to_rpc_maps_each_variant() {
        check_values(
            [
                Check {
                    scenario: "prometheus variant with a name",
                    input: prom_config(Some("scrape"), "localhost:8080", 30),
                    expect: rpc_prom(Some("scrape"), "localhost:8080", 30),
                },
                Check {
                    scenario: "prometheus variant without a name",
                    input: prom_config(None, "localhost:9090", 15),
                    expect: rpc_prom(None, "localhost:9090", 15),
                },
                Check {
                    scenario: "logging variant with a name",
                    input: log_config(Some("logs"), "/dev/null"),
                    expect: rpc_log(Some("logs"), "/dev/null"),
                },
                Check {
                    scenario: "logging variant without a name",
                    input: log_config(None, "/var/log/app.log"),
                    expect: rpc_log(None, "/var/log/app.log"),
                },
            ],
            rpc::DpuExtensionServiceObservabilityConfig::from,
        );
    }

    #[test]
    fn observability_to_rpc_maps_every_config() {
        check_values(
            [
                Check {
                    scenario: "empty config list",
                    input: ExtensionServiceObservability { configs: vec![] },
                    expect: rpc::DpuExtensionServiceObservability { configs: vec![] },
                },
                Check {
                    scenario: "mixed prometheus and logging configs",
                    input: ExtensionServiceObservability {
                        configs: vec![
                            prom_config(Some("a"), "host:80", 5),
                            log_config(None, "/tmp/x"),
                        ],
                    },
                    expect: rpc::DpuExtensionServiceObservability {
                        configs: vec![rpc_prom(Some("a"), "host:80", 5), rpc_log(None, "/tmp/x")],
                    },
                },
            ],
            rpc::DpuExtensionServiceObservability::from,
        );
    }

    #[test]
    fn observability_config_from_rpc_covers_ok_and_error_arms() {
        check_cases(
            [
                Case {
                    scenario: "valid prometheus config",
                    input: rpc_prom(Some("a"), "localhost:8080", 30),
                    expect: Yields(prom_config(Some("a"), "localhost:8080", 30)),
                },
                Case {
                    scenario: "valid prometheus config without a name",
                    input: rpc_prom(None, "localhost:8080", 30),
                    expect: Yields(prom_config(None, "localhost:8080", 30)),
                },
                Case {
                    scenario: "valid logging config with @ and . characters",
                    input: rpc_log(Some("a"), "/dev/null@home"),
                    expect: Yields(log_config(Some("a"), "/dev/null@home")),
                },
                Case {
                    scenario: "valid logging config without a name",
                    input: rpc_log(None, "/dev/null"),
                    expect: Yields(log_config(None, "/dev/null")),
                },
                Case {
                    scenario: "missing config oneof",
                    input: rpc::DpuExtensionServiceObservabilityConfig {
                        name: Some("a".repeat(10)),
                        config: None,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "name exceeds the max length",
                    input: rpc_log(Some(&"a".repeat(MAX_OBSERVABILITY_CONFIG_NAME + 1)), "/dev/null"),
                    expect: Fails,
                },
                Case {
                    scenario: "name exactly at the max length is allowed",
                    input: rpc_log(Some(&"a".repeat(MAX_OBSERVABILITY_CONFIG_NAME)), "/dev/null"),
                    expect: Yields(log_config(
                        Some(&"a".repeat(MAX_OBSERVABILITY_CONFIG_NAME)),
                        "/dev/null",
                    )),
                },
                Case {
                    scenario: "prometheus endpoint exceeds the max length",
                    input: rpc_prom(Some("a"), &"localhost".repeat(1024), 30),
                    expect: Fails,
                },
                Case {
                    scenario: "prometheus endpoint has invalid characters",
                    input: rpc_prom(Some("a"), "/this/is/not/valid", 30),
                    expect: Fails,
                },
                Case {
                    scenario: "logging path exceeds the max length",
                    input: rpc_log(Some("a"), &"/dev/null".repeat(1024)),
                    expect: Fails,
                },
                Case {
                    scenario: "logging path has invalid characters",
                    input: rpc_log(Some("a"), "/dev/null$$$"),
                    expect: Fails,
                },
            ],
            |c| ExtensionServiceObservabilityConfig::try_from(c).map_err(drop),
        );
    }

    #[test]
    fn observability_from_rpc_propagates_inner_errors() {
        check_cases(
            [
                Case {
                    scenario: "all inner configs valid",
                    input: rpc::DpuExtensionServiceObservability {
                        configs: vec![rpc_prom(None, "host:80", 5), rpc_log(None, "/tmp/x")],
                    },
                    expect: Yields(ExtensionServiceObservability {
                        configs: vec![prom_config(None, "host:80", 5), log_config(None, "/tmp/x")],
                    }),
                },
                Case {
                    scenario: "empty config list yields empty observability",
                    input: rpc::DpuExtensionServiceObservability { configs: vec![] },
                    expect: Yields(ExtensionServiceObservability { configs: vec![] }),
                },
                Case {
                    scenario: "one invalid inner config fails the whole conversion",
                    input: rpc::DpuExtensionServiceObservability {
                        configs: vec![rpc_prom(None, "host:80", 5), rpc_log(None, "/dev/null$$$")],
                    },
                    expect: Fails,
                },
            ],
            |o| ExtensionServiceObservability::try_from(o).map_err(drop),
        );
    }

    #[test]
    fn version_info_to_rpc_maps_fields_and_optional_observability() {
        let created = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let version = ConfigVersion::new(7);
        let with_obs = ExtensionServiceVersionInfo {
            service_id: ExtensionServiceId::from(Uuid::nil()),
            version,
            created,
            data: "yaml".to_string(),
            observability: Some(ExtensionServiceObservability {
                configs: vec![log_config(None, "/tmp/x")],
            }),
            has_credential: true,
            deleted: None,
        };
        let without_obs = ExtensionServiceVersionInfo {
            observability: None,
            has_credential: false,
            ..with_obs.clone()
        };

        check_values(
            [
                Check {
                    scenario: "observability present is carried through",
                    input: with_obs,
                    expect: (true, true, "yaml".to_string()),
                },
                Check {
                    scenario: "observability absent yields none",
                    input: without_obs,
                    expect: (false, false, "yaml".to_string()),
                },
            ],
            |v| {
                let rpc = rpc::DpuExtensionServiceVersionInfo::from(v);
                (rpc.observability.is_some(), rpc.has_credential, rpc.data)
            },
        );
    }

    #[test]
    fn snapshot_to_rpc_maps_fields_and_optional_latest_version() {
        let created = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let updated = Utc.with_ymd_and_hms(2026, 2, 3, 4, 5, 6).unwrap();
        let service_id = ExtensionServiceId::from(Uuid::nil());
        let tenant = "org".parse().unwrap();
        let latest = ExtensionServiceVersionInfo {
            service_id,
            version: ConfigVersion::new(2),
            created,
            data: "data".to_string(),
            observability: None,
            has_credential: false,
            deleted: None,
        };
        let with_latest = ExtensionServiceSnapshot {
            service_id,
            service_type: ExtensionServiceType::KubernetesPod,
            service_name: "svc".to_string(),
            tenant_organization_id: tenant,
            version_ctr: 3,
            latest_version: Some(latest),
            active_versions: vec![ConfigVersion::new(1), ConfigVersion::new(2)],
            description: "desc".to_string(),
            created,
            updated,
            deleted: None,
        };
        let without_latest = ExtensionServiceSnapshot {
            latest_version: None,
            active_versions: vec![],
            ..with_latest.clone()
        };

        check_values(
            [
                Check {
                    scenario: "latest version present, two active versions",
                    input: with_latest,
                    expect: (true, 2usize, "svc".to_string()),
                },
                Check {
                    scenario: "latest version absent, no active versions",
                    input: without_latest,
                    expect: (false, 0usize, "svc".to_string()),
                },
            ],
            |s| {
                let rpc = rpc::DpuExtensionService::from(s);
                (
                    rpc.latest_version_info.is_some(),
                    rpc.active_versions.len(),
                    rpc.service_name,
                )
            },
        );
    }
}
