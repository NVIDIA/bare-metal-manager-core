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
pub const VALIDATION: Duration = Duration::from_secs(30 * 60);
