/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
