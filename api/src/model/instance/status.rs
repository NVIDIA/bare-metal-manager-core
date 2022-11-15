/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

pub mod network;
pub mod tenant;

/// Instance status
///
/// This represents the actual status of an Instance
#[derive(Debug, Clone)]
pub struct InstanceStatus {
    /// Status that is related to the tenant of the instance.
    /// In case no tenant has been assigned to this instance, the field would be absent.
    pub tenant: Option<tenant::InstanceTenantStatus>,

    /// Status of the networking subsystem of an instance
    pub network: network::InstanceNetworkStatus,

    /// Whether all configurations related to an instance are in-sync.
    /// This is a logical AND for the settings of all sub-configurations.
    /// At this time it equals `InstanceNetworkStatus::configs_synced`,
    /// but might in the future also include readiness for other subsystems.
    pub configs_synced: SyncState,
}

/// Whether user configurations have been applied
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// All configuration changes that users requested have been applied
    Synced,
    // At least one configuration change to an active instance has not yet been processed
    Pending,
}
