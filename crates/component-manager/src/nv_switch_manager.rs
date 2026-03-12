// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use carbide_uuid::switch::SwitchId;

use crate::error::ComponentManagerError;
use crate::types::PowerAction;

#[derive(Debug, Clone)]
pub struct SwitchComponentResult {
    pub switch_id: SwitchId,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwitchFirmwareUpdateStatus {
    pub switch_id: SwitchId,
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

/// Backend trait for NV-Switch management operations.
///
/// Implementations translate between core domain types and the backend-specific
/// wire protocol (e.g. NSM gRPC). Inventory is resolved in core via
/// ID -> BMC IP and `FindExploredEndpointsByIds`; this trait does not expose
/// inventory queries.
#[async_trait::async_trait]
pub trait NvSwitchManager: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;

    async fn power_control(
        &self,
        ids: &[SwitchId],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError>;

    async fn queue_firmware_updates(
        &self,
        ids: &[SwitchId],
        bundle_version: &str,
        components: &[String],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError>;

    async fn get_firmware_status(
        &self,
        ids: &[SwitchId],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError>;

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError>;
}
