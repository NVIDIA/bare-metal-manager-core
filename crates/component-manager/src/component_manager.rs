// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use librms::RmsApi;
use sqlx::PgPool;

use crate::config::ComponentManagerConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::NvSwitchManager;
use crate::power_shelf_manager::PowerShelfManager;

/// Holds the configured backend implementations for each component type.
#[derive(Debug, Clone)]
pub struct ComponentManager {
    pub nv_switch: Arc<dyn NvSwitchManager>,
    pub power_shelf: Arc<dyn PowerShelfManager>,
}

impl ComponentManager {
    pub fn new(
        nv_switch: Arc<dyn NvSwitchManager>,
        power_shelf: Arc<dyn PowerShelfManager>,
    ) -> Self {
        Self {
            nv_switch,
            power_shelf,
        }
    }
}

/// Build `ComponentManager` from configuration.
///
/// The factory inspects `config.nv_switch_backend` and `config.power_shelf_backend`
/// to decide which concrete implementation to instantiate. Unknown backend names
/// return an error.
pub async fn build_component_manager(
    config: &ComponentManagerConfig,
    rms_client: Option<Arc<dyn RmsApi>>,
    db: Option<PgPool>,
) -> Result<ComponentManager, ComponentManagerError> {
    let nv_switch: Arc<dyn NvSwitchManager> = match config.nv_switch_backend.as_str() {
        "nsm" => {
            let endpoint = config.nsm.as_ref().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "nv_switch_backend is 'nsm' but [component_manager.nsm] config is missing"
                        .into(),
                )
            })?;
            Arc::new(
                crate::nsm::NsmSwitchBackend::connect(&endpoint.url, endpoint.tls.as_ref()).await?,
            )
        }
        "rms" => {
            let client = rms_client.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "nv_switch_backend is 'rms' but RMS client is not configured".into(),
                )
            })?;
            let db = db.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "nv_switch_backend is 'rms' but database pool is not configured".into(),
                )
            })?;
            Arc::new(crate::rms::RmsBackend::new(client, db))
        }
        "mock" => Arc::new(crate::mock::MockNvSwitchManager),
        other => {
            return Err(ComponentManagerError::InvalidArgument(format!(
                "unknown nv_switch_backend: {other}"
            )));
        }
    };

    let power_shelf: Arc<dyn PowerShelfManager> = match config.power_shelf_backend.as_str() {
        "psm" => {
            let endpoint = config.psm.as_ref().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "power_shelf_backend is 'psm' but [component_manager.psm] config is missing"
                        .into(),
                )
            })?;
            Arc::new(
                crate::psm::PsmPowerShelfBackend::connect(&endpoint.url, endpoint.tls.as_ref())
                    .await?,
            )
        }
        "rms" => {
            let client = rms_client.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "power_shelf_backend is 'rms' but RMS client is not configured".into(),
                )
            })?;
            let db = db.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "power_shelf_backend is 'rms' but database pool is not configured".into(),
                )
            })?;
            Arc::new(crate::rms::RmsBackend::new(client, db))
        }
        "mock" => Arc::new(crate::mock::MockPowerShelfManager),
        other => {
            return Err(ComponentManagerError::InvalidArgument(format!(
                "unknown power_shelf_backend: {other}"
            )));
        }
    };

    Ok(ComponentManager::new(nv_switch, power_shelf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ComponentManagerConfig;

    #[tokio::test]
    async fn build_with_mock_backends() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "mock".into(),
            power_shelf_backend: "mock".into(),
            nsm: None,
            psm: None,
        };
        let cm = build_component_manager(&config, None, None).await.unwrap();
        assert_eq!(cm.nv_switch.name(), "mock-nsm");
        assert_eq!(cm.power_shelf.name(), "mock-psm");
    }

    #[tokio::test]
    async fn build_rejects_unknown_nv_switch_backend() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "bogus".into(),
            power_shelf_backend: "mock".into(),
            nsm: None,
            psm: None,
        };
        let err = build_component_manager(&config, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ComponentManagerError::InvalidArgument(msg) if msg.contains("bogus"))
        );
    }

    #[tokio::test]
    async fn build_rejects_unknown_power_shelf_backend() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "mock".into(),
            power_shelf_backend: "bogus".into(),
            nsm: None,
            psm: None,
        };
        let err = build_component_manager(&config, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ComponentManagerError::InvalidArgument(msg) if msg.contains("bogus"))
        );
    }

    #[tokio::test]
    async fn build_nsm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "nsm".into(),
            power_shelf_backend: "mock".into(),
            nsm: None,
            psm: None,
        };
        let err = build_component_manager(&config, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn build_psm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "mock".into(),
            power_shelf_backend: "psm".into(),
            nsm: None,
            psm: None,
        };
        let err = build_component_manager(&config, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }
}
