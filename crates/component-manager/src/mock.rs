// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::switch::SwitchId;

use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    FirmwareState as SwFwState, NvSwitchManager, SwitchComponentResult, SwitchFirmwareUpdateStatus,
};
use crate::power_shelf_manager::{
    FirmwareState as PsFwState, PowerShelfComponentResult, PowerShelfFirmwareUpdateStatus,
    PowerShelfManager,
};
use crate::types::PowerAction;

#[derive(Debug, Default)]
pub struct MockNvSwitchManager;

#[async_trait::async_trait]
impl NvSwitchManager for MockNvSwitchManager {
    fn name(&self) -> &str {
        "mock-nsm"
    }

    async fn power_control(
        &self,
        ids: &[SwitchId],
        _action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        Ok(ids
            .iter()
            .map(|id| SwitchComponentResult {
                switch_id: *id,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn queue_firmware_updates(
        &self,
        ids: &[SwitchId],
        _bundle_version: &str,
        _components: &[String],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        Ok(ids
            .iter()
            .map(|id| SwitchComponentResult {
                switch_id: *id,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        ids: &[SwitchId],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        Ok(ids
            .iter()
            .map(|id| SwitchFirmwareUpdateStatus {
                switch_id: *id,
                state: SwFwState::Completed,
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
        ids: &[PowerShelfId],
        _action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        Ok(ids
            .iter()
            .map(|id| PowerShelfComponentResult {
                power_shelf_id: *id,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn update_firmware(
        &self,
        ids: &[PowerShelfId],
        _target_version: &str,
        _components: &[String],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        Ok(ids
            .iter()
            .map(|id| PowerShelfComponentResult {
                power_shelf_id: *id,
                success: true,
                error: None,
            })
            .collect())
    }

    async fn get_firmware_status(
        &self,
        ids: &[PowerShelfId],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
        Ok(ids
            .iter()
            .map(|id| PowerShelfFirmwareUpdateStatus {
                power_shelf_id: *id,
                state: PsFwState::Completed,
                target_version: "mock-1.0.0".into(),
                error: None,
            })
            .collect())
    }

    async fn list_firmware(
        &self,
        _ids: &[PowerShelfId],
    ) -> Result<Vec<String>, ComponentManagerError> {
        Ok(vec!["mock-1.0.0".into(), "mock-2.0.0".into()])
    }
}
