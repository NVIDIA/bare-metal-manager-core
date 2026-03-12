// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use carbide_uuid::power_shelf::PowerShelfId;

use crate::error::ComponentManagerError;
use crate::types::PowerAction;

#[derive(Debug, Clone)]
pub struct PowerShelfComponentResult {
    pub power_shelf_id: PowerShelfId,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PowerShelfFirmwareUpdateStatus {
    pub power_shelf_id: PowerShelfId,
    pub state: FirmwareState,
    pub target_version: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareState {
    Unknown,
    Queued,
    InProgress,
    Verifying,
    Completed,
    Failed,
    Cancelled,
}

/// Backend trait for power shelf management operations.
///
/// Implementations translate between core domain types and the backend-specific
/// wire protocol (e.g. PSM gRPC). Inventory is resolved in core via
/// ID -> BMC IP and `FindExploredEndpointsByIds`; this trait does not expose
/// inventory queries.
#[async_trait::async_trait]
pub trait PowerShelfManager: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;

    async fn power_control(
        &self,
        ids: &[PowerShelfId],
        action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError>;

    async fn update_firmware(
        &self,
        ids: &[PowerShelfId],
        target_version: &str,
        components: &[String],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError>;

    async fn get_firmware_status(
        &self,
        ids: &[PowerShelfId],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError>;

    async fn list_firmware(
        &self,
        ids: &[PowerShelfId],
    ) -> Result<Vec<String>, ComponentManagerError>;
}
