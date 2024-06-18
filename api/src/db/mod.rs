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
pub mod attestation;
pub mod bmc_metadata;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod domain;
pub mod dpu_agent_upgrade_policy;
pub mod dpu_machine;
pub mod dpu_machine_update;
pub mod expected_machine;
pub mod explored_endpoints;
pub mod explored_managed_host;
pub mod host_machine;
pub mod ib_partition;
pub mod instance;
pub mod instance_address;
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
pub mod route_servers;
pub mod site_exploration_report;
pub mod tenant;
pub mod vpc;

use std::error::Error;
use std::fmt::{Display, Formatter};

// Max values we can bind to a Postgres SQL statement;
pub const BIND_LIMIT: usize = 65535;

///
/// A parameter to find() to filter resources by Uuid;
///
#[derive(Clone)]
pub enum UuidKeyedObjectFilter<'a> {
    /// Don't filter by uuid
    All,

    /// Filter by a list of uuids
    List(&'a [uuid::Uuid]),

    /// Retrieve a single resource
    One(uuid::Uuid),
}

/// A parameter to find() to filter resources based on an implied ID column
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

/// A parameter to find_by() to filter resources based on a specified column
pub enum ObjectColumnFilter<'a, C: ColumnInfo<ColumnType = T>, T> {
    /// Don't filter. Return all objects
    All,

    /// Filter where column = ANY([T])
    ///
    /// The filter will return any objects where the value of the column C is
    /// included in this list [T]. If the list is empty, the filter will return no
    /// objects.
    List(C, &'a [T]),

    /// Retrieve a single object where the value of the column C is equal to T
    One(C, T),
}

pub trait ColumnInfo: Clone {
    type ColumnType: sqlx::Type<sqlx::Postgres>;
    fn column_name(&self) -> String;
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

/// DbPrimaryUuid is a trait intended for primary keys which
/// derive the sqlx UUID type. The intent is the db_primary_uuid_name
/// function should return the name of the column for the primary
/// UUID-typed key, which allows dynamic compositon of a SQL query.
///
/// This was originally introduced as part of the measured boot
/// generics (and lived in src/measured_boot/), but moved here.
pub trait DbPrimaryUuid {
    fn db_primary_uuid_name() -> &'static str;
}

/// DbTable is a trait intended for table records which derive
/// sqlx FromRow. The intent here is db_table_name() will return
/// the actual name of the table the records are in, allowing for
/// dynamic composition of an SQL query for that table.
///
/// This was originally introduced as part of the measured boot
/// generics (and lived in src/measured_boot/), but moved here.
pub trait DbTable {
    fn db_table_name() -> &'static str;
}
