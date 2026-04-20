// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use model::component_manager::{
    FirmwareState, NvSwitchComponent, PowerAction, PowerShelfComponent,
};

use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    NvSwitchManager, SwitchComponentResult, SwitchEndpoint, SwitchFirmwareUpdateStatus,
};
use crate::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfFirmwareVersions, PowerShelfManager,
};

#[derive(Debug, Default)]
pub struct MockNvSwitchManager;

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
}
