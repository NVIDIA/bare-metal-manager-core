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
pub mod attestation;
pub mod bmc_metadata;
pub mod desired_firmware;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod domain;
pub mod dpa_interface;
pub mod dpa_interface_state_history;
pub mod dpu_agent_upgrade_policy;
pub mod dpu_machine_update;
pub mod dpu_remediation;
pub mod expected_machine;
pub mod explored_endpoints;
pub mod explored_managed_host;
pub mod forge_version;
pub mod host_machine_update;
pub mod ib_partition;
pub mod instance;
pub mod instance_address;
pub mod instance_network_config;
pub mod instance_type;
pub mod machine;
pub mod machine_boot_override;
pub mod machine_health_history;
pub mod machine_interface;
pub mod machine_interface_address;
pub mod machine_state_history;
pub mod machine_topology;
pub mod machine_validation;
pub mod machine_validation_config;
pub mod machine_validation_result;
pub mod machine_validation_suites;
pub mod managed_host;
pub mod measured_boot;
pub mod migrations;
pub mod network_devices;
pub mod network_prefix;
pub mod network_security_group;
pub mod network_segment;
pub mod network_segment_state_history;
pub mod os_image;
pub mod power_options;
pub mod predicted_machine_interface;
pub mod queries;
pub mod redfish_actions;
pub mod resource_pool;
pub mod resource_record;
pub mod route_servers;
pub mod site_exploration_report;
pub mod sku;
pub mod storage_cluster;
pub mod storage_pool;
pub mod storage_volume;
pub mod tenant;
pub mod tenant_keyset;
pub mod trim_table;
pub mod vpc;
pub mod vpc_dpu_loopback;
pub mod vpc_peering;
pub mod vpc_prefix;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::panic::Location;

use sqlx::Postgres;

use crate::CarbideError;

// Max values we can bind to a Postgres SQL statement;
pub const BIND_LIMIT: usize = 65535;

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
#[derive(Clone)]
pub enum ObjectColumnFilter<'a, C: ColumnInfo<'a>> {
    /// Don't filter. Return all objects
    All,

    /// Filter where column = ANY([T])
    ///
    /// The filter will return any objects where the value of the column C is
    /// included in this list [T]. If the list is empty, the filter will return no
    /// objects.
    List(C, &'a [C::ColumnType]),

    /// Retrieve a single object where the value of the column C is equal to T
    One(C, &'a C::ColumnType),
}

/// Newtype wrapper around sqlx::QueryBuilder that allows passing an ObjectColumnFilter to build the WHERE clause
pub struct FilterableQueryBuilder<'q>(sqlx::QueryBuilder<'q, Postgres>);

impl<'q> FilterableQueryBuilder<'q> {
    pub fn new(init: impl Into<String>) -> Self {
        FilterableQueryBuilder(sqlx::QueryBuilder::new(init))
    }

    /// Push a WHERE clause to this query builder that matches the given filter, optionally using
    /// the given relation to qualify the column names
    pub fn filter_relation<'a, C: ColumnInfo<'q>>(
        mut self,
        filter: &ObjectColumnFilter<'q, C>,
        relation: Option<&str>,
    ) -> sqlx::QueryBuilder<'q, Postgres> {
        match filter {
            ObjectColumnFilter::All => self.0.push(" WHERE true".to_string()),
            ObjectColumnFilter::List(column, list) => {
                if let Some(relation) = relation {
                    self.0
                        .push(format!(" WHERE {}.{}=ANY(", relation, column.column_name()))
                        .push_bind(*list)
                        .push(")")
                } else {
                    self.0
                        .push(format!(" WHERE {}=ANY(", column.column_name()))
                        .push_bind(*list)
                        .push(")")
                }
            }
            ObjectColumnFilter::One(column, id) => {
                if let Some(relation) = relation {
                    self.0
                        .push(format!(" WHERE {}.{}=", relation, column.column_name()))
                        .push_bind(*id)
                } else {
                    self.0
                        .push(format!(" WHERE {}=", column.column_name()))
                        .push_bind(*id)
                }
            }
        };

        self.0
    }

    /// Push a WHERE clause to this query builder that matches the given filter.
    pub fn filter<'a, C: ColumnInfo<'q>>(
        self,
        filter: &ObjectColumnFilter<'q, C>,
    ) -> sqlx::QueryBuilder<'q, Postgres> {
        self.filter_relation(filter, None)
    }
}

#[test]
fn test_filter_relation() {
    use crate::db::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};

    #[derive(Copy, Clone)]
    struct IdColumn;
    impl ColumnInfo<'_> for IdColumn {
        type TableType = ();
        type ColumnType = i32;
        fn column_name(&self) -> &'static str {
            "id"
        }
    }

    let query = FilterableQueryBuilder::new("SELECT * from table1 t")
        .filter_relation(&ObjectColumnFilter::One(IdColumn, &1), Some("t"));
    assert_eq!(query.sql(), "SELECT * from table1 t WHERE t.id=$1");
}

#[test]
fn test_filter() {
    use crate::db::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};

    #[derive(Copy, Clone)]
    struct IdColumn;
    impl ColumnInfo<'_> for IdColumn {
        type TableType = ();
        type ColumnType = i32;
        fn column_name(&self) -> &'static str {
            "id"
        }
    }

    let query = FilterableQueryBuilder::new("SELECT * from table1")
        .filter(&ObjectColumnFilter::One(IdColumn, &1));
    assert_eq!(query.sql(), "SELECT * from table1 WHERE id=$1");
}

/// Metadata about a particular column that can be filtered by in a typical `find_by` function
///
/// This conveys metadata such as the name of the column and the type of data it returns, so that we
/// can write generic functions to build SQL queries from given search criteria, while maintaining
/// type safety.
pub trait ColumnInfo<'a>: Clone + Copy {
    /// TableType has no requirements, it is here to allow `find_by` functions to constrain what
    /// columns can be searched by, via type bounds. For example, this will fail to compile:
    ///
    /// ```ignore
    /// use crate::db::{ColumnInfo, ObjectColumnFilter};
    ///
    /// struct GoodTable; // Marker type, can be otherwise unused
    /// struct BadTable; // Marker type, can be otherwise unused
    ///
    /// #[derive(Copy, Clone)]
    /// struct GoodColumn;
    /// impl <'a> ColumnInfo<'a> for GoodColumn {
    ///     type TableType = GoodTable;
    ///     type ColumnType = &'a str;
    ///     fn column_name(&self) -> &'static str { "id" }
    /// }
    ///
    /// #[derive(Copy, Clone)]
    /// struct BadColumn;
    /// impl <'a> ColumnInfo<'a> for BadColumn {
    ///     type TableType = BadTable;
    ///     type ColumnType = &'a str;
    ///     fn column_name(&self) -> &'static str { "id" }
    /// }
    ///
    /// fn find_by<'a, C: ColumnInfo<'a, TableType=GoodTable>>(
    ///     filter: ObjectColumnFilter<'a, C>
    /// ) {}
    ///
    /// find_by(ObjectColumnFilter::One(BadColumn, &"hello")) // error[E0271]: type mismatch resolving `<BadColumn as ColumnInfo<'_>>::TableType == GoodTable`
    /// ```
    type TableType;
    type ColumnType: sqlx::Type<sqlx::Postgres>
        + Send
        + Sync
        + sqlx::Encode<'a, sqlx::Postgres>
        + sqlx::postgres::PgHasArrayType;
    fn column_name(&self) -> &'static str;
}

///
/// Wraps a sqlx::Error and records location and query
///
#[derive(Debug)]
pub struct DatabaseError {
    file: &'static str,
    line: u32,
    query: String,
    pub source: sqlx::Error,
}

impl DatabaseError {
    #[track_caller]
    pub fn new(op_name: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError {
            file: loc.file(),
            line: loc.line(),
            query: op_name.to_string(),
            source,
        }
    }

    #[track_caller]
    pub fn txn_begin(name: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError {
            file: loc.file(),
            line: loc.line(),
            query: format!("begin {name}"),
            source,
        }
    }

    #[track_caller]
    pub fn txn_commit(name: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError {
            file: loc.file(),
            line: loc.line(),
            query: format!("commit {name}"),
            source,
        }
    }

    #[track_caller]
    pub fn txn_rollback(name: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError {
            file: loc.file(),
            line: loc.line(),
            query: format!("rollback {name}"),
            source,
        }
    }

    #[track_caller]
    pub fn query(query: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError {
            file: loc.file(),
            line: loc.line(),
            query: query.to_string(),
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

impl From<DatabaseError> for tonic::Status {
    fn from(from: DatabaseError) -> Self {
        CarbideError::from(from).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_new() {
        const OP_NAME: &str = "something people want to say";
        let err = DatabaseError::new(OP_NAME, sqlx::Error::protocol("some error"));
        assert_eq!(err.line, line!() - 1);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(OP_NAME))
    }

    #[test]
    fn test_database_error_txn_begin() {
        const DB_TXN_NAME: &str = "test txn";
        let err = DatabaseError::txn_begin(DB_TXN_NAME, sqlx::Error::protocol("some error"));
        assert_eq!(err.line, line!() - 1);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(&format!("begin {DB_TXN_NAME}")))
    }

    #[test]
    fn test_database_error_txn_commit() {
        const DB_TXN_NAME: &str = "test txn";
        let err = DatabaseError::txn_commit(DB_TXN_NAME, sqlx::Error::protocol("some error"));
        assert_eq!(err.line, line!() - 1);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(&format!("commit {DB_TXN_NAME}")))
    }

    #[test]
    fn test_database_error_txn_rollback() {
        const DB_TXN_NAME: &str = "test txn";
        let err = DatabaseError::txn_rollback(DB_TXN_NAME, sqlx::Error::protocol("some error"));
        assert_eq!(err.line, line!() - 1);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(&format!("rollback {DB_TXN_NAME}")))
    }

    #[test]
    fn test_database_error_query() {
        const DB_QUERY: &str = "SELECT * from some_table;";
        let err = DatabaseError::query(DB_QUERY, sqlx::Error::protocol("some error"));
        assert_eq!(err.line, line!() - 1);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(DB_QUERY));
    }
}
