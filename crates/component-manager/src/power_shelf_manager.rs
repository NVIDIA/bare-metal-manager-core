// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::net::IpAddr;

use mac_address::MacAddress;
use model::component_manager::{FirmwareState, PowerAction, PowerShelfComponent};

use crate::error::ComponentManagerError;

/// Physical network identifiers for a power shelf, used to register with and
/// operate against the backend service (PSM).
#[derive(Debug, Clone)]
pub struct PowerShelfEndpoint {
    pub pmc_ip: IpAddr,
    pub pmc_mac: MacAddress,
    pub pmc_vendor: PowerShelfVendor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerShelfVendor {
    Unknown,
    Liteon,
}

impl PowerShelfVendor {
    pub const DEFAULT: Self = Self::Liteon;
}

#[derive(Debug, Clone)]
pub struct PowerShelfComponentResult {
    pub pmc_mac: MacAddress,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PowerShelfFirmwareUpdateStatus {
    pub pmc_mac: MacAddress,
    pub state: FirmwareState,
    pub target_version: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PowerShelfFirmwareVersions {
    pub pmc_mac: MacAddress,
    pub versions: Vec<String>,
    pub error: Option<String>,
}

/// Backend trait for power shelf management operations.
///
/// Implementations receive physical endpoint information (PMC IP/MAC + vendor)
/// and handle registration with the backend service internally. Results are
/// keyed by `pmc_mac`.
#[async_trait::async_trait]
pub trait PowerShelfManager: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;

    async fn power_control(
        &self,
        endpoints: &[PowerShelfEndpoint],
        action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError>;

    async fn update_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
        target_version: &str,
        components: &[PowerShelfComponent],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError>;

    async fn get_firmware_status(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError>;

    async fn list_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareVersions>, ComponentManagerError>;
}
