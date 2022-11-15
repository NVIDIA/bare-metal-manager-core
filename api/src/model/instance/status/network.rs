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

use std::net::IpAddr;

use mac_address::MacAddress;

use crate::model::instance::{config::network::InterfaceFunctionId, status::SyncState};

/// Status of the networking subsystem of an instance
///
/// The status report is only valid against one particular version of
/// [`InstanceInterfaceConfig`]. It can not be interpreted without it, since
/// e.g. the amount and configuration of network interfaces can change between
/// configs.
///
/// Since the user can change the configuration at any point in time for an instance,
/// we can not directly store this status in the database - it might not match
/// the newest config anymore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceNetworkStatus {
    /// Status for each configured interface
    ///
    /// Each entry in this status array maps to it's corresponding entry in the
    /// Config section. E.g. `instance.status.network.interface_status[1]`
    /// would map to `instance.config.network.interface_configs[1]`.
    pub interfaces: Vec<InstanceInterfaceStatus>,

    /// Whether all desired network changes that the user has applied have taken effect
    /// This includes:
    /// - Whether `InstanceNetworkConfig` is of exactly the same version as the
    ///   version the user desires.
    /// - Whether the version of each security policy that is either directly referenced
    ///   as part of an `InstanceInterfaceConfig` or indirectly referenced via the
    ///   the security policies that are applied to the VPC or NetworkSegment
    ///   is exactly the same version as the version the user desires.
    ///
    /// Note for the implementation: We need to monitor all these config versions
    /// on the feedback path from DPU to carbide in order to know whether the
    /// changes have indeed taken effect.
    /// TODO: Do we also want to show all applied versios here, or just track them
    /// internally? Probably not helpfor for tenants at all - but it could be helpful
    /// for the Forge operating team to debug settings that to do do not go in-sync
    /// without having to attach to the database.
    pub configs_synced: SyncState,
}

/// The actual status of a single network interface of an instance
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceInterfaceStatus {
    /// The function ID that is assigned to this interface
    pub function_id: InterfaceFunctionId,

    /// The MAC address which has been assigned to this interface
    /// The list will be empty if interface configuration hasn't been completed
    /// and therefore the address is unknown.
    pub mac_address: Option<MacAddress>,

    /// The list of IP addresses that had been assigned to this interface,
    /// based on the requested subnet.
    /// The list will be empty if interface configuration hasn't been completed
    pub addresses: Vec<IpAddr>,
}
