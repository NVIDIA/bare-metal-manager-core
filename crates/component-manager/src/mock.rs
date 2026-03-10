// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::DispatchError;
use crate::nv_switch_manager::{
    FirmwareState as SwFwState, NvSwitchManager, SwitchComponentResult,
    SwitchFirmwareUpdateStatus,
};
use crate::power_shelf_manager::{
    FirmwareState as PsFwState, PowerShelfComponentResult, PowerShelfFirmwareUpdateStatus,
    PowerShelfManager,
};

#[derive(Debug, Default)]
pub struct MockNvSwitchManager;

#[async_trait::async_trait]
impl NvSwitchManager for MockNvSwitchManager {
    fn name(&self) -> &str {
        "mock-nsm"
    }

    async fn queue_firmware_updates(
        &self,
        ids: &[String],
        _bundle_version: &str,
        _components: &[String],
    ) -> Result<Vec<SwitchComponentResult>, DispatchError> {
        Ok(ids
            .iter()
            .map(|id| SwitchComponentResult {
                switch_id: id.clone(),
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        ids: &[String],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, DispatchError> {
        Ok(ids
            .iter()
            .map(|id| SwitchFirmwareUpdateStatus {
                switch_id: id.clone(),
                state: SwFwState::Completed,
                target_version: "mock-1.0.0".into(),
                error: None,
            })
            .collect())
    }

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, DispatchError> {
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

    async fn update_firmware(
        &self,
        ids: &[String],
        _target_version: &str,
        _components: &[String],
    ) -> Result<Vec<PowerShelfComponentResult>, DispatchError> {
        Ok(ids
            .iter()
            .map(|id| PowerShelfComponentResult {
                power_shelf_id: id.clone(),
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        ids: &[String],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, DispatchError> {
        Ok(ids
            .iter()
            .map(|id| PowerShelfFirmwareUpdateStatus {
                power_shelf_id: id.clone(),
                state: PsFwState::Completed,
                target_version: "mock-1.0.0".into(),
                error: None,
            })
            .collect())
    }

    async fn list_firmware(&self) -> Result<Vec<String>, DispatchError> {
        Ok(vec!["mock-1.0.0".into(), "mock-2.0.0".into()])
    }
}
