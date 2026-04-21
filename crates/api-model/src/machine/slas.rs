/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! SLAs for Machine State Machine Controller

use std::time::Duration;

pub const DPUDISCOVERING: Duration = Duration::from_secs(30 * 60);

// DPUInit any substate other than INIT
// WaitingForPlatformPowercycle WaitingForPlatformConfiguration WaitingForNetworkConfig WaitingForNetworkInstall
pub const DPUINIT_NOTINIT: Duration = Duration::from_secs(30 * 60);

// HostInit state, any substate other than Init and  WaitingForDiscovery
// EnableIpmiOverLan WaitingForPlatformConfiguration PollingBiosSetup UefiSetup Discovered Lockdown PollingLockdownStatus MachineValidating
pub const HOST_INIT: Duration = Duration::from_secs(30 * 60);

pub const WAITING_FOR_CLEANUP: Duration = Duration::from_secs(30 * 60);

pub const CREATED: Duration = Duration::from_secs(30 * 60);

pub const FORCE_DELETION: Duration = Duration::from_secs(30 * 60);

pub const DPU_REPROVISION: Duration = Duration::from_secs(30 * 60);

pub const HOST_REPROVISION: Duration = Duration::from_secs(40 * 60);

pub const MEASUREMENT_WAIT_FOR_MEASUREMENT: Duration = Duration::from_secs(30 * 60);

pub const BOM_VALIDATION: Duration = Duration::from_secs(5 * 60);

// ASSIGNED state, any substate other than Ready and BootingWithDiscoveryImage
// Init WaitingForNetworkConfig WaitingForStorageConfig WaitingForRebootToReady SwitchToAdminNetwork WaitingForNetworkReconfig DPUReprovision Failed
pub const ASSIGNED: Duration = Duration::from_secs(30 * 60);

// ASSIGNED state, HostPlatformConfiguration substate
pub const ASSIGNED_HOST_PLATFORM_CONFIGURATION: Duration = Duration::from_secs(90 * 60);
pub const VALIDATION: Duration = Duration::from_secs(30 * 60);

/// Configuration for machine state SLA durations.
#[derive(Clone, Debug, PartialEq)]
pub struct MachineSlaConfig {
    /// SLA for the Assigned/BootingWithDiscoveryImage state.
    pub assigned_booting_with_discovery_image: Duration,
}

impl Default for MachineSlaConfig {
    fn default() -> Self {
        // Default failure_retry_time is 30 minutes.
        Self::new(chrono::Duration::minutes(30))
    }
}

impl MachineSlaConfig {
    pub fn new(failure_retry_time: chrono::Duration) -> Self {
        let failure_retry_time = failure_retry_time
            .to_std()
            .unwrap_or(Duration::from_secs(30 * 60));
        Self {
            // Set to 1.1 * failure_retry_time so the SLA fires
            // shortly after the retry would have triggered.
            assigned_booting_with_discovery_image: failure_retry_time * 11 / 10,
        }
    }
}
