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
pub mod address_selection_strategy;
pub mod auth;
pub mod constants;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod domain;
pub mod dpu_machine;
pub mod instance;
pub mod instance_address;
pub mod instance_type;
pub mod ipmi;
pub mod machine;
pub mod machine_event;
pub mod machine_interface;
pub mod machine_interface_address;
pub mod machine_topology;
pub mod migrations;
pub mod network_prefix;
pub mod network_segment;
pub mod resource_record;
pub mod tags;
pub mod vpc;
pub mod vpc_resource_leaf;

///
/// A parameter to find() to filter machines by Uuid;
///
pub enum UuidKeyedObjectFilter<'a> {
    /// Don't filter by uuid
    All,

    /// Filter by a list of uuids
    List(&'a [uuid::Uuid]),

    /// Retrieve a single machine
    One(uuid::Uuid),
}
