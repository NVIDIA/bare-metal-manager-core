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
//! These SLAs are in seconds

pub const DPUDISCOVERING: u64 = 30 * 60;

// DPUInit any substate other than INIT
// WaitingForPlatformPowercycle WaitingForPlatformConfiguration WaitingForNetworkConfig WaitingForNetworkInstall
pub const DPUINIT_NOTINIT: u64 = 30 * 60;

// HostInit state, any substate other than Init and  WaitingForDiscovery
// EnableIpmiOverLan WaitingForPlatformConfiguration UefiSetup Discovered WaitingForLockdown MachineValidating
pub const HOST_INIT: u64 = 30 * 60;

pub const WAITING_FOR_CLEANUP: u64 = 30 * 60;

pub const CREATED: u64 = 30 * 60;

pub const FORCE_DELETION: u64 = 30 * 60;

pub const DPU_REPROVISION: u64 = 30 * 60;

pub const HOST_REPROVISION: u64 = 40 * 60;

pub const MEASUREMENT_WAIT_FOR_MEASUREMENT: u64 = 30 * 60;

pub const BOM_VALIDATION: u64 = 5 * 60;

// ASSIGNED state, any substate other than Ready and BootingWithDiscoveryImage
// Init WaitingForNetworkConfig WaitingForStorageConfig WaitingForRebootToReady SwitchToAdminNetwork WaitingForNetworkReconfig DPUReprovision Failed
pub const ASSIGNED: u64 = 30 * 60;
