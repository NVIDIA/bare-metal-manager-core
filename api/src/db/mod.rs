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
pub mod address_selection_strategy;
pub mod bmc_machine;
pub mod bmc_metadata;
pub mod constants;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod domain;
pub mod dpu_agent_upgrade_policy;
pub mod dpu_machine;
pub mod host_machine;
pub mod ib_subnet;
pub mod instance;
pub mod instance_address;
pub mod instance_type;
pub mod machine;
pub mod machine_boot_override;
pub mod machine_interface;
pub mod machine_interface_address;
pub mod machine_state_history;
pub mod machine_topology;
pub mod migrations;
pub mod network_devices;
pub mod network_prefix;
pub mod network_segment;
pub mod network_segment_state_history;
pub mod resource_pool;
pub mod resource_record;
pub mod tenant;
pub mod vpc;

use std::error::Error;
use std::fmt::{Display, Formatter};

///
/// A parameter to find() to filter resources by Uuid;
///
pub enum UuidKeyedObjectFilter<'a> {
    /// Don't filter by uuid
    All,

    /// Filter by a list of uuids
    List(&'a [uuid::Uuid]),

    /// Retrieve a single resource
    One(uuid::Uuid),
}

/// A parameter to find() to filter resources based on a certain ID
pub enum ObjectFilter<'a, ID> {
    /// Don't filter. Return all objects
    All,

    /// Filter by a list of uuids
    /// The filter will return any objects whose ID is included in the list.
    /// If the list is empty, the filter will return no objects.
    List(&'a [ID]),

    /// Retrieve a single objects
    One(ID),
}

///
/// Wraps a sqlx::Error and records location and query
///
#[derive(Debug)]
pub struct DatabaseError {
    file: &'static str,
    line: u32,
    query: &'static str,
    pub source: sqlx::Error,
}

impl DatabaseError {
    pub fn new(
        file: &'static str,
        line: u32,
        query: &'static str,
        source: sqlx::Error,
    ) -> DatabaseError {
        DatabaseError {
            file,
            line,
            query,
            source,
        }
    }
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Database Error: {} file={} line={} query={}.",
            self.source, self.file, self.line, self.query,
        )
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
