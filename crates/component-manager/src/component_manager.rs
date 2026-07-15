// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use carbide_redfish::libredfish::RedfishClientPool;
use librms::RmsApi;
use model::rack_type::RackProfileConfig;
use sqlx::PgPool;

use crate::compute_tray_manager::{Backend as ComputeBackend, ComputeTrayManager};
use crate::config::ComponentManagerConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    Backend as NvSwitchBackend, ConfigureSwitchCertificateJobStatus, NvSwitchManager,
    SwitchEndpoint,
};
use crate::power_shelf_manager::{Backend as PowerShelfBackend, PowerShelfManager};
use crate::rms::{RmsSwitchSystemImageStatusApi, validate_rms_backend_rack_profiles};

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
    pub async fn configure_switch_certificate(
        &self,
        endpoint: &SwitchEndpoint,
        domain_name: Option<&str>,
        services: Option<&[i32]>,
    ) -> Result<String, ComponentManagerError> {
        self.nv_switch
            .configure_switch_certificate(endpoint, domain_name, services)
            .await
    }

    pub async fn get_configure_switch_certificate_job_status(
        &self,
        job_id: &str,
    ) -> Result<ConfigureSwitchCertificateJobStatus, ComponentManagerError> {
        self.nv_switch
            .get_configure_switch_certificate_job_status(job_id)
            .await
    }

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
/// The factory inspects the configured nv-switch, power-shelf, and compute-tray
/// backend selectors to decide which concrete implementations to instantiate.
/// Unknown backend names are rejected at config-deserialization time by the
/// backend enums. When any backend uses RMS, `rack_profiles` must contain enough
/// product-family and vendor data to resolve RMS node types before startup
/// continues.
pub async fn build_component_manager(
    config: &ComponentManagerConfig,
    rack_profiles: RackProfileConfig,
    rms_client: Option<Arc<dyn RmsApi>>,
    rms_switch_system_image_client: Option<Arc<dyn RmsSwitchSystemImageStatusApi>>,
    db: Option<PgPool>,
    redfish_pool: Option<Arc<dyn RedfishClientPool>>,
) -> Result<ComponentManager, ComponentManagerError> {
    validate_rms_backend_rack_profiles(config, &rack_profiles)?;

    let rack_profiles = Arc::new(rack_profiles);

    let nv_switch: Arc<dyn NvSwitchManager> = match config.nv_switch_backend {
        NvSwitchBackend::Nsm => {
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
        NvSwitchBackend::Rms => {
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
            Arc::new(crate::rms::RmsBackend::new(
                client,
                rms_switch_system_image_client.clone(),
                db,
                rack_profiles.clone(),
                config.nvos_password_rotation_enabled,
            ))
        }
        NvSwitchBackend::Mock => Arc::new(crate::mock::MockNvSwitchManager::default()),
    };

    let power_shelf: Arc<dyn PowerShelfManager> = match config.power_shelf_backend {
        PowerShelfBackend::Psm => {
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
        PowerShelfBackend::Rms => {
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
            Arc::new(crate::rms::RmsBackend::new(
                client,
                rms_switch_system_image_client.clone(),
                db,
                rack_profiles.clone(),
                config.nvos_password_rotation_enabled,
            ))
        }
        PowerShelfBackend::Mock => Arc::new(crate::mock::MockPowerShelfManager),
    };

    let compute_tray: Arc<dyn ComputeTrayManager> = match config.compute_tray_backend {
        ComputeBackend::Rms => {
            let client = rms_client.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "compute_tray_backend is 'rms' but RMS client is not configured".into(),
                )
            })?;
            let db = db.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "compute_tray_backend is 'rms' but database pool is not configured".into(),
                )
            })?;
            Arc::new(crate::rms::RmsBackend::new(
                client,
                rms_switch_system_image_client.clone(),
                db,
                rack_profiles.clone(),
                config.nvos_password_rotation_enabled,
            ))
        }
        ComputeBackend::Core => {
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
        ComputeBackend::Mock => Arc::new(crate::mock::MockComputeTrayManager),
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
    use model::rack_type::{
        RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
        RackHardwareTopology, RackProductFamily, RackProfile,
    };

    use super::*;
    use crate::config::ComponentManagerConfig;

    fn rms_rack_profiles(profile: RackProfile) -> RackProfileConfig {
        RackProfileConfig {
            rack_profiles: [("NVL72".to_string(), profile)].into_iter().collect(),
        }
    }

    fn rms_rack_profile() -> RackProfile {
        RackProfile {
            product_family: Some(RackProductFamily::Gb200),
            rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
            rack_capabilities: RackCapabilitiesSet {
                compute: RackCapabilityCompute {
                    vendor: Some("NVIDIA".to_string()),
                    ..Default::default()
                },
                switch: RackCapabilitySwitch {
                    vendor: Some("NVIDIA".to_string()),
                    ..Default::default()
                },
                power_shelf: RackCapabilityPowerShelf {
                    vendor: Some("LiteOn".to_string()),
                    ..Default::default()
                },
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn build_with_mock_backends() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let cm = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap();

        assert_eq!(cm.nv_switch.name(), "mock-nsm");
        assert_eq!(cm.power_shelf.name(), "mock-psm");
        assert_eq!(cm.compute_tray.name(), "mock-ctm");
    }

    #[test]
    fn deserialize_rejects_unknown_backend_names() {
        use serde::Deserialize;
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error as DeError, StrDeserializer};

        let de: StrDeserializer<DeError> = "bogus".into_deserializer();
        assert!(NvSwitchBackend::deserialize(de).is_err());
        let de: StrDeserializer<DeError> = "bogus".into_deserializer();
        assert!(PowerShelfBackend::deserialize(de).is_err());
        let de: StrDeserializer<DeError> = "bogus".into_deserializer();
        assert!(ComputeBackend::deserialize(de).is_err());
    }

    #[tokio::test]
    async fn build_nsm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Nsm,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let err = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap_err();

        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn build_psm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Psm,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let err = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap_err();

        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }

    // A config that explicitly selects working switch/power-shelf backends but
    // leaves `compute_tray_backend` at its default (now `Rms`) must not be able
    // to silently come up half-configured: RMS validation rejects missing rack
    // profile config before any partial component manager can be built. This
    // keeps the default flip to RMS a deliberate, visible choice.
    #[tokio::test]
    async fn rms_compute_tray_default_requires_rack_profiles() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Mock,
            // compute_tray_backend intentionally left at its default.
            ..Default::default()
        };

        assert_eq!(config.compute_tray_backend, ComputeBackend::Rms);

        let err = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ComponentManagerError::InvalidArgument(msg)
                if msg.contains("rack_profiles must contain at least one profile")
        ));
    }

    #[tokio::test]
    async fn build_requires_rack_profiles_for_rms_backend() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Rms,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let result =
            build_component_manager(&config, Default::default(), None, None, None, None).await;
        let Err(error) = result else {
            panic!("missing RMS rack profiles should be rejected");
        };

        assert_eq!(
            error.to_string(),
            "invalid argument: rack_profiles must contain at least one profile when component_manager uses an RMS backend"
        );
    }

    #[tokio::test]
    async fn build_requires_vendor_for_rms_backend_role() {
        let mut profile = rms_rack_profile();
        profile.rack_capabilities.power_shelf.vendor = None;

        let rack_profiles = rms_rack_profiles(profile);
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Rms,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let result = build_component_manager(&config, rack_profiles, None, None, None, None).await;
        let Err(error) = result else {
            panic!("missing RMS vendor should be rejected");
        };

        assert_eq!(
            error.to_string(),
            "invalid argument: rack profile NVL72 rack_capabilities.power_shelf.vendor is required when power_shelf_backend is 'rms'"
        );
    }

    #[tokio::test]
    async fn build_validates_rms_backend_vendor_value() {
        let mut profile = rms_rack_profile();
        profile.rack_capabilities.switch.vendor = Some("Other".to_string());

        let rack_profiles = rms_rack_profiles(profile);
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Rms,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let result = build_component_manager(&config, rack_profiles, None, None, None, None).await;
        let Err(error) = result else {
            panic!("unsupported RMS vendor should be rejected");
        };

        assert_eq!(
            error.to_string(),
            "invalid argument: rack profile NVL72 cannot resolve RMS switch node type: RMS does not support switch vendor Other"
        );
    }
}
