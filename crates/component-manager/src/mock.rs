// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use model::component_manager::{
    ComputeTrayComponent, ConfigureSwitchCertificateState, FirmwareState, NvSwitchComponent,
    PowerAction, PowerShelfComponent,
};

use crate::compute_tray_manager::{
    Backend, ComputeTrayEndpoint, ComputeTrayFirmwareUpdateStatus, ComputeTrayManager,
    ComputeTrayResult,
};
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    ConfigureSwitchCertificateJobStatus, NvSwitchManager, SwitchComponentResult, SwitchEndpoint,
    SwitchFirmwareUpdateStatus, SwitchPowerStateResult, SwitchSlotAndTrayResult,
};
use crate::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfFirmwareVersions, PowerShelfManager, PowerShelfPowerStateResult,
};
use crate::types::FirmwareUpdateOptions;

#[derive(Debug, Clone, Default)]
pub struct MockNvSwitchManager {
    certificate_job_status: Option<ConfigureSwitchCertificateJobStatus>,
}

impl MockNvSwitchManager {
    pub fn with_certificate_job_status(
        mut self,
        status: ConfigureSwitchCertificateJobStatus,
    ) -> Self {
        self.certificate_job_status = Some(status);
        self
    }
}

#[async_trait::async_trait]
impl NvSwitchManager for MockNvSwitchManager {
    fn name(&self) -> &str {
        "mock-nsm"
    }

    async fn power_control(
        &self,
        endpoints: &[SwitchEndpoint],
        _action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| SwitchComponentResult {
                bmc_mac: ep.bmc_mac,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        _bundle_version: &str,
        _components: &[NvSwitchComponent],
        _options: &FirmwareUpdateOptions,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| SwitchComponentResult {
                bmc_mac: ep.bmc_mac,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| SwitchFirmwareUpdateStatus {
                bmc_mac: ep.bmc_mac,
                state: FirmwareState::Completed,
                target_version: "mock-1.0.0".into(),
                error: None,
            })
            .collect())
    }

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
        Ok(vec!["mock-1.0.0".into(), "mock-2.0.0".into()])
    }

    async fn get_slot_and_tray(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchSlotAndTrayResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| SwitchSlotAndTrayResult {
                bmc_mac: ep.bmc_mac,
                slot_number: None,
                tray_index: None,
                error: None,
            })
            .collect())
    }

    async fn get_power_state(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchPowerStateResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| SwitchPowerStateResult {
                bmc_mac: ep.bmc_mac,
                power_state: None,
                error: None,
            })
            .collect())
    }
    async fn configure_switch_certificate(
        &self,
        _endpoint: &SwitchEndpoint,
        _domain_name: Option<&str>,
        _services: Option<&[i32]>,
    ) -> Result<String, ComponentManagerError> {
        Ok("mock-switch-cert-job".to_string())
    }

    async fn get_configure_switch_certificate_job_status(
        &self,
        _job_id: &str,
    ) -> Result<ConfigureSwitchCertificateJobStatus, ComponentManagerError> {
        Ok(self
            .certificate_job_status
            .clone()
            .unwrap_or(ConfigureSwitchCertificateJobStatus {
                state: ConfigureSwitchCertificateState::Completed,
                error: None,
            }))
    }
}

#[derive(Debug, Default)]
pub struct MockPowerShelfManager;

#[async_trait::async_trait]
impl PowerShelfManager for MockPowerShelfManager {
    fn name(&self) -> &str {
        "mock-psm"
    }

    async fn power_control(
        &self,
        endpoints: &[PowerShelfEndpoint],
        _action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| PowerShelfComponentResult {
                pmc_mac: ep.pmc_mac,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn update_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
        _target_version: &str,
        _components: &[PowerShelfComponent],
        _options: &FirmwareUpdateOptions,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| PowerShelfComponentResult {
                pmc_mac: ep.pmc_mac,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| PowerShelfFirmwareUpdateStatus {
                pmc_mac: ep.pmc_mac,
                state: FirmwareState::Completed,
                target_version: "mock-1.0.0".into(),
                error: None,
            })
            .collect())
    }

    async fn list_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareVersions>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| PowerShelfFirmwareVersions {
                pmc_mac: ep.pmc_mac,
                versions: vec!["mock-1.0.0".into(), "mock-2.0.0".into()],
                error: None,
            })
            .collect())
    }

    async fn get_power_state(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfPowerStateResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| PowerShelfPowerStateResult {
                pmc_mac: ep.pmc_mac,
                power_state: None,
                error: None,
            })
            .collect())
    }
}

#[derive(Debug, Default)]
pub struct MockComputeTrayManager;

#[async_trait::async_trait]
impl ComputeTrayManager for MockComputeTrayManager {
    fn name(&self) -> &str {
        "mock-ctm"
    }

    fn backend(&self) -> Backend {
        Backend::Mock
    }

    async fn power_control(
        &self,
        endpoints: &[ComputeTrayEndpoint],
        _action: PowerAction,
    ) -> Result<Vec<ComputeTrayResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| ComputeTrayResult {
                bmc_ip: ep.bmc_ip,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn update_firmware(
        &self,
        endpoints: &[ComputeTrayEndpoint],
        _target_version: &str,
        _components: &[ComputeTrayComponent],
        _options: &FirmwareUpdateOptions,
    ) -> Result<Vec<ComputeTrayResult>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| ComputeTrayResult {
                bmc_ip: ep.bmc_ip,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        endpoints: &[ComputeTrayEndpoint],
    ) -> Result<Vec<ComputeTrayFirmwareUpdateStatus>, ComponentManagerError> {
        Ok(endpoints
            .iter()
            .map(|ep| ComputeTrayFirmwareUpdateStatus {
                bmc_ip: ep.bmc_ip,
                state: FirmwareState::Completed,
                target_version: "mock-1.0.0".into(),
                error: None,
            })
            .collect())
    }

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
        Ok(vec!["mock-1.0.0".into(), "mock-2.0.0".into()])
    }
}
