// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::net::IpAddr;

use mac_address::MacAddress;
use model::component_manager::{FirmwareState, NvSwitchComponent, PowerAction};

use crate::error::ComponentManagerError;

/// Physical network identifiers for an NV-Switch, used to register with and
/// operate against the backend service (NSM).
#[derive(Debug, Clone)]
pub struct SwitchEndpoint {
    pub bmc_ip: IpAddr,
    pub bmc_mac: MacAddress,
    pub nvos_ip: IpAddr,
    pub nvos_mac: MacAddress,
}

#[derive(Debug, Clone)]
pub struct SwitchComponentResult {
    pub bmc_mac: MacAddress,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwitchFirmwareUpdateStatus {
    pub bmc_mac: MacAddress,
    pub state: FirmwareState,
    pub target_version: String,
    pub error: Option<String>,
}

/// Backend trait for NV-Switch management operations.
///
/// Implementations receive physical endpoint information (BMC + NVOS IPs/MACs)
/// and handle registration with the backend service internally. The
/// service-generated UUID is used for the actual operation and never exposed
/// to the caller; results are keyed by `bmc_mac`.
#[async_trait::async_trait]
pub trait NvSwitchManager: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;

    async fn power_control(
        &self,
        endpoints: &[SwitchEndpoint],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError>;

    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        bundle_version: &str,
        components: &[NvSwitchComponent],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError>;

    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError>;

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError>;
}
