// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use carbide_redfish::libredfish::RedfishClientPool;
use librms::RmsApi;
use sqlx::PgPool;

use crate::compute_tray_manager::{Backend, ComputeTrayManager};
use crate::config::ComponentManagerConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::NvSwitchManager;
use crate::power_shelf_manager::PowerShelfManager;

/// Holds the configured backend implementations for each component type.
#[derive(Debug, Clone)]
pub struct ComponentManager {
    // The HAL configured for nv-switch power and f/w control
    pub nv_switch: Arc<dyn NvSwitchManager>,
    // The HAL configured for powershelf power and f/w control
    pub power_shelf: Arc<dyn PowerShelfManager>,
    // The HAL configured for compute power and f/w control
    pub compute_tray: Arc<dyn ComputeTrayManager>,
    // if true, the component management interface will route through the state controller for switch power and f/w control.
    // the expectation is that the state controller will then call the configured HAL for switches (RMS or NSM)
    // if false, the component management interface will directly dispatch to the configured HAL for switches, bypassing the state controller
    pub nv_switch_use_state_controller: bool,
    // if true, the component management interface will route through the state controller for powershelf power and f/w control.
    // the expectation is that the state controller will then call the configured HAL for powershelves (RMS or PSM)
    // if false, the component management interface will directly dispatch to the configured HAL for powershelves, bypassing the state controller
    pub power_shelf_use_state_controller: bool,
    // if true, the component management interface will route through the state controller for compute tray power and f/w control.
    // the expectation is that the state controller will then call the configured HAL for compute tray
    // if false, the component management interface will directly dispatch to the configured HAL for compute trays, bypassing the state controller
    pub compute_tray_use_state_controller: bool,
}

impl ComponentManager {
    pub fn new(
        nv_switch: Arc<dyn NvSwitchManager>,
        power_shelf: Arc<dyn PowerShelfManager>,
        compute_tray: Arc<dyn ComputeTrayManager>,
        nv_switch_use_state_controller: bool,
        power_shelf_use_state_controller: bool,
        compute_tray_use_state_controller: bool,
    ) -> Self {
        Self {
            nv_switch,
            power_shelf,
            compute_tray,
            nv_switch_use_state_controller,
            power_shelf_use_state_controller,
            compute_tray_use_state_controller,
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
    redfish_pool: Option<Arc<dyn RedfishClientPool>>,
) -> Result<ComponentManager, ComponentManagerError> {
    let nv_switch: Arc<dyn NvSwitchManager> = match config.nv_switch_backend.as_str() {
        crate::nsm::NsmSwitchBackend::BACKEND_NAME => {
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

    let compute_tray: Arc<dyn ComputeTrayManager> = match config.compute_tray_backend {
        // TODO: implement ComputeTrayManager for RmsBackend
        Backend::Rms => {
            return Err(ComponentManagerError::InvalidArgument(
                "compute_tray_backend 'rms' is not yet supported".into(),
            ));
        }
        Backend::Core => {
            let pool = redfish_pool.ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "compute_tray_backend is 'core' but Redfish client pool is not configured"
                        .into(),
                )
            })?;
            Arc::new(crate::core_compute_manager::CoreComputeTrayManager::new(
                pool,
            ))
        }
        Backend::Mock => Arc::new(crate::mock::MockComputeTrayManager),
    };

    Ok(ComponentManager::new(
        nv_switch,
        power_shelf,
        compute_tray,
        config.nv_switch_use_state_controller,
        config.power_shelf_use_state_controller,
        config.compute_tray_use_state_controller,
    ))
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
            compute_tray_backend: Backend::Mock,
            ..Default::default()
        };
        let cm = build_component_manager(&config, None, None, None)
            .await
            .unwrap();
        assert_eq!(cm.nv_switch.name(), "mock-nsm");
        assert_eq!(cm.power_shelf.name(), "mock-psm");
        assert_eq!(cm.compute_tray.name(), "mock-ctm");
    }

    #[tokio::test]
    async fn build_rejects_unknown_nv_switch_backend() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "bogus".into(),
            power_shelf_backend: "mock".into(),
            compute_tray_backend: Backend::Mock,
            ..Default::default()
        };
        let err = build_component_manager(&config, None, None, None)
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
            compute_tray_backend: Backend::Mock,
            ..Default::default()
        };
        let err = build_component_manager(&config, None, None, None)
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
            compute_tray_backend: Backend::Mock,
            ..Default::default()
        };
        let err = build_component_manager(&config, None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn build_psm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: "mock".into(),
            power_shelf_backend: "psm".into(),
            compute_tray_backend: Backend::Mock,
            ..Default::default()
        };
        let err = build_component_manager(&config, None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }
}
