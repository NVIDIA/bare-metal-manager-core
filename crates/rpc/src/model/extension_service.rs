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
    use carbide_test_support::Outcome::{FailsWith, Yields};
    use carbide_test_support::scenarios;

    use super::*;
    use crate::forge::dpu_extension_service_observability_config::Config;
    use crate::forge::{self as rpc};

    fn observability_config(
        name: Option<String>,
        config: Option<Config>,
    ) -> rpc::DpuExtensionServiceObservabilityConfig {
        rpc::DpuExtensionServiceObservabilityConfig { name, config }
    }

    fn logging(path: impl Into<String>) -> Config {
        Config::Logging(rpc::DpuExtensionServiceObservabilityConfigLogging { path: path.into() })
    }

    fn prometheus(endpoint: impl Into<String>) -> Config {
        Config::Prometheus(rpc::DpuExtensionServiceObservabilityConfigPrometheus {
            endpoint: endpoint.into(),
            scrape_interval_seconds: 30,
        })
    }

    #[test]
    fn observability_config_from_rpc() {
        let max_name = Some("a".repeat(MAX_OBSERVABILITY_CONFIG_NAME));
        let max_endpoint = format!(
            "localhost:8080{}",
            "a".repeat(MAX_OBSERVABILITY_PROPERTY_LEN - "localhost:8080".len()),
        );
        let max_path = format!(
            "/dev/null@home{}",
            "/".repeat(MAX_OBSERVABILITY_PROPERTY_LEN - "/dev/null@home".len()),
        );
        scenarios!(run = |input| {
            ExtensionServiceObservabilityConfig::try_from(input).map_err(|error| error.to_string())
        };
            "invalid config" {
                observability_config(None, None) => FailsWith(
                    "argument DpuExtensionServiceObservability.config is missing".to_string(),
                ),
            }

            "invalid name" {
                observability_config(
                    Some("a".repeat(MAX_OBSERVABILITY_CONFIG_NAME + 1)),
                    Some(logging("/dev/null")),
                ) => FailsWith(
                    "invalid value length exceeds 64 for DpuExtensionServiceObservability.name"
                        .to_string(),
                ),
            }

            "invalid logging path" {
                observability_config(
                    max_name.clone(),
                    Some(logging("a".repeat(MAX_OBSERVABILITY_PROPERTY_LEN + 1))),
                ) => FailsWith(
                    "invalid value length exceeds 128 for DpuExtensionServiceObservability.config.path"
                        .to_string(),
                ),
                observability_config(
                    max_name.clone(),
                    Some(logging("/dev/null$")),
                ) => FailsWith(
                    r"invalid value characters that match the pattern `[^a-zA-Z0-9\-\_\/\.\@]+` are invalid for DpuExtensionServiceObservability.config.path"
                        .to_string(),
                ),
            }

            "invalid Prometheus endpoint" {
                observability_config(
                    max_name.clone(),
                    Some(prometheus("a".repeat(MAX_OBSERVABILITY_PROPERTY_LEN + 1))),
                ) => FailsWith(
                    "invalid value length exceeds 128 for DpuExtensionServiceObservability.config.endpoint"
                        .to_string(),
                ),
                observability_config(
                    max_name.clone(),
                    Some(prometheus("localhost/metrics")),
                ) => FailsWith(
                    r"invalid value characters that match the pattern `[^a-zA-Z0-9:\-]+` are invalid for DpuExtensionServiceObservability.config.endpoint"
                        .to_string(),
                ),
            }

            "valid config" {
                observability_config(
                    max_name.clone(),
                    Some(prometheus(max_endpoint.clone())),
                ) => Yields(ExtensionServiceObservabilityConfig {
                    name: max_name,
                    config: ExtensionServiceObservabilityConfigType::Prometheus(
                        ExtensionServiceObservabilityConfigTypePrometheus {
                            endpoint: max_endpoint,
                            scrape_interval_seconds: 30,
                        },
                    ),
                }),
                observability_config(
                    None,
                    Some(logging(max_path.clone())),
                ) => Yields(ExtensionServiceObservabilityConfig {
                    name: None,
                    config: ExtensionServiceObservabilityConfigType::Logging(
                        ExtensionServiceObservabilityConfigTypeLogging {
                            path: max_path,
                        },
                    ),
                }),
            },
        );
    }
}
