// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::net::IpAddr;

use carbide_secrets::credentials::Credentials;
use model::component_manager::{ComputeTrayComponent, FirmwareState, PowerAction};

use crate::error::ComponentManagerError;
use crate::types::FirmwareUpdateOptions;

/// Physical network identifiers for a compute tray, used to register with and
/// operate against the backend service (CTM).
#[derive(Debug, Clone)]
pub struct ComputeTrayEndpoint {
    pub vendor: ComputeTrayVendor,
    pub bmc_ip: IpAddr,
    pub bmc_credentials: Credentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeTrayVendor {
    Unknown,
    Dell,
    Hpe,
    Lenovo,
    Supermicro,
    Nvidia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeTrayModel {
    Unknown,
    Viking,
    GB200,
    GB300,
}

#[derive(Debug, Clone)]
pub struct ComputeTrayResult {
    pub bmc_ip: IpAddr,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ComputeTrayFirmwareUpdateStatus {
    pub bmc_ip: IpAddr,
    pub state: FirmwareState,
    pub target_version: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Core,
    #[default]
    Rms,
    Mock,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rms => f.write_str("rms"),
            Self::Core => f.write_str("core"),
            Self::Mock => f.write_str("mock"),
        }
    }
}

/// Backend trait for compute tray management operations.
///
/// Implementations receive physical endpoint information (BMC IP/MAC + vendor)
/// and handle registration with the backend service internally. Results are
/// keyed by `bmc_ip`.
#[async_trait::async_trait]
pub trait ComputeTrayManager: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;

    fn backend(&self) -> Backend;

    async fn power_control(
        &self,
        endpoints: &[ComputeTrayEndpoint],
        action: PowerAction,
    ) -> Result<Vec<ComputeTrayResult>, ComponentManagerError>;

    async fn update_firmware(
        &self,
        endpoints: &[ComputeTrayEndpoint],
        target_version: &str,
        components: &[ComputeTrayComponent],
        options: &FirmwareUpdateOptions,
    ) -> Result<Vec<ComputeTrayResult>, ComponentManagerError>;

    async fn get_firmware_status(
        &self,
        endpoints: &[ComputeTrayEndpoint],
    ) -> Result<Vec<ComputeTrayFirmwareUpdateStatus>, ComponentManagerError>;

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError>;
}
