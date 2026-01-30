/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// Allow txn_without_commit in tests
#![cfg_attr(test, allow(txn_without_commit))]

pub mod attestation;
pub mod bmc_metadata;
pub mod carbide_version;
pub mod desired_firmware;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod dns;
pub mod dpa_interface;
pub mod dpa_interface_state_history;
pub mod dpu_agent_upgrade_policy;
pub mod dpu_machine_update;
pub mod dpu_remediation;
pub mod expected_machine;
pub mod expected_power_shelf;
pub mod expected_switch;
pub mod explored_endpoints;
pub mod explored_managed_host;
pub mod extension_service;
pub mod host_machine_update;
pub mod ib_partition;
pub mod instance;
pub mod instance_address;
pub mod instance_network_config;
pub mod instance_type;
pub mod ip_allocator;
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
pub mod nvl_logical_partition;
pub mod nvl_partition;
pub mod os_image;
pub mod power_options;
pub mod power_shelf;
pub mod power_shelf_state_history;
pub mod predicted_machine_interface;
pub mod queries;
pub mod rack;
pub mod rack_firmware;
pub mod rack_state_history;
pub mod redfish_actions;
pub mod resource_pool;
pub mod route_servers;
pub mod site_exploration_report;
pub mod sku;
pub mod switch;
pub mod switch_state_history;
pub mod tenant;
pub mod tenant_keyset;
pub mod trim_table;
pub mod vpc;
pub mod vpc_dpu_loopback;
pub mod vpc_peering;
pub mod vpc_prefix;
pub mod work_lock_manager;

use std::backtrace::{Backtrace, BacktraceStatus};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ops::{Deref, DerefMut};
use std::panic::Location;
use std::pin::Pin;

#[cfg(test)]
pub(crate) use carbide_macros::sqlx_test;
use mac_address::MacAddress;
use model::ConfigValidationError;
use model::hardware_info::HardwareInfoError;
use model::tenant::TenantError;
use rpc::errors::RpcDataConversionError;
use sqlx::{Acquire, PgPool, PgTransaction, Postgres};
use tonic::Status;

use crate::ip_allocator::DhcpError;
use crate::resource_pool::ResourcePoolDatabaseError;

// Max values we can bind to a Postgres SQL statement... half the stated value of 65536, since in
// practice, 65535 query parameters seems to freeze up my postgres server in testing.
pub const BIND_LIMIT: usize = 32768;

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
    use crate::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};

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
    use crate::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};

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
    /// use crate::{ColumnInfo, ObjectColumnFilter};
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
pub struct AnnotatedSqlxError {
    file: &'static str,
    line: u32,
    query: String,
    pub source: sqlx::Error,
}

impl AnnotatedSqlxError {
    #[track_caller]
    pub fn new(op_name: &str, source: sqlx::Error) -> Self {
        let loc = Location::caller();
        AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: op_name.to_string(),
            source,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("Generic error from report: {0}")]
    GenericErrorFromReport(#[from] eyre::ErrReport),
    #[error(transparent)]
    Sqlx(#[from] AnnotatedSqlxError),
    #[error("{kind} not found: {id}")]
    NotFoundError {
        /// The type of the resource that was not found (e.g. Machine)
        kind: &'static str,
        /// The ID of the resource that was not found
        id: String,
    },
    #[error("Internal error: {message}")]
    Internal { message: String },
    #[error("Unable to parse string into IP Address: {0}")]
    AddressParseError(#[from] std::net::AddrParseError),
    #[error("Unable to parse string into IP Network: {0}")]
    NetworkParseError(#[from] ipnetwork::IpNetworkError),
    #[error("{kind} already exists: {id}")]
    AlreadyFoundError {
        /// The type of the resource that already exists (e.g. Machine)
        kind: &'static str,
        /// The ID of the resource that already exists.
        id: String,
    },
    #[error("Argument is invalid: {0}")]
    InvalidArgument(String),
    #[error("Can not convert between RPC data model and internal data model - {0}")]
    RpcDataConversionError(#[from] RpcDataConversionError),
    #[error("Duplicate MAC address for expected host BMC interface: {0}")]
    ExpectedHostDuplicateMacAddress(MacAddress),
    #[error("Argument is missing in input: {0}")]
    MissingArgument(&'static str),
    #[error("Uuid type conversion error: {0}")]
    UuidConversionError(#[from] uuid::Error),
    #[error("RPC Uuid type conversion error: {0}")]
    RpcUuidConversionError(#[from] carbide_uuid::UuidConversionError),
    #[error(
        "An object of type {0} was intended to be modified did not have the expected version {1}"
    )]
    ConcurrentModificationError(&'static str, String),
    #[error("{0}")]
    FailedPrecondition(String),
    #[error("All Network Segments are not allocated yet.")]
    NetworkSegmentNotAllocated,
    #[error("Find one returned no results but should return one for uuid - {0}")]
    FindOneReturnedNoResultsError(uuid::Uuid),
    #[error("Find one returned many results but should return one for uuid - {0}")]
    FindOneReturnedManyResultsError(uuid::Uuid),
    #[error("Resource {0} is empty")]
    ResourceExhausted(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(#[from] ConfigValidationError),
    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] model::resource_pool::ResourcePoolError),
    #[error("Only one interface per machine can be marked as primary")]
    OnePrimaryInterface,
    #[error("Duplicate MAC address for network: {0}")]
    NetworkSegmentDuplicateMacAddress(MacAddress),
    #[error("Admin network is not configured.")]
    AdminNetworkNotConfigured,
    #[error("Network has attached VPC or Subdomain : {0}")]
    NetworkSegmentDelete(String),
    #[error("Tenant handling error: {0}")]
    TenantError(#[from] TenantError),
    #[error("Hardware info error: {0}")]
    HardwareInfoError(#[from] HardwareInfoError),
    #[error("The function is not implemented")]
    NotImplemented,
    #[error("Error in DHCP allocation/handling: {0}")]
    DhcpError(#[from] DhcpError),
    #[error("Maximum one association per interface")]
    MaxOneInterfaceAssociation,
}

impl DatabaseError {
    /// Returns true if the database error wrapps a sqlx::Error::RowNotFound, or if it's our own DatabaseError::NotFoundError
    pub fn is_not_found(&self) -> bool {
        match self {
            DatabaseError::Sqlx(e) => matches!(e.source, sqlx::Error::RowNotFound),
            DatabaseError::NotFoundError { .. } => true,
            _ => false,
        }
    }

    pub fn with_op_name(self, op_name: &str) -> Self {
        match self {
            DatabaseError::Sqlx(e) => DatabaseError::new(op_name, e.source),
            _ => self,
        }
    }
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;

impl DatabaseError {
    #[track_caller]
    pub fn new(op_name: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError::Sqlx(AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: op_name.to_string(),
            source,
        })
    }

    fn txn_begin(source: sqlx::Error, loc: &'static Location<'static>) -> DatabaseError {
        DatabaseError::Sqlx(AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: "transaction begin".into(),
            source,
        })
    }

    fn txn_commit(source: sqlx::Error, loc: &'static Location<'static>) -> DatabaseError {
        DatabaseError::Sqlx(AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: "transaction commit".into(),
            source,
        })
    }

    fn txn_rollback(source: sqlx::Error, loc: &'static Location<'static>) -> DatabaseError {
        DatabaseError::Sqlx(AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: "transaction rollback".into(),
            source,
        })
    }

    #[track_caller]
    pub fn acquire(source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError::Sqlx(AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: "acquire connection".into(),
            source,
        })
    }

    #[track_caller]
    pub fn query(query: &str, source: sqlx::Error) -> DatabaseError {
        let loc = Location::caller();
        DatabaseError::Sqlx(AnnotatedSqlxError {
            file: loc.file(),
            line: loc.line(),
            query: query.to_string(),
            source,
        })
    }

    /// Creates a `Internal` error with the given error message
    pub fn internal(message: String) -> Self {
        DatabaseError::Internal { message }
    }
}

impl Display for AnnotatedSqlxError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Database Error: {} file={} line={} query={}.",
            self.source, self.file, self.line, self.query,
        )
    }
}

impl Error for AnnotatedSqlxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl From<DatabaseError> for tonic::Status {
    fn from(from: DatabaseError) -> Self {
        // If env RUST_BACKTRACE is set extract handler and err location
        // If it's not set `Backtrace::capture()` is very cheap to call
        let b = Backtrace::capture();
        let printed = if b.status() == BacktraceStatus::Captured {
            let b_str = b.to_string();
            let f = b_str
                .lines()
                .skip(1)
                .skip_while(|l| !l.contains("carbide"))
                .take(2)
                .collect::<Vec<&str>>();
            if f.len() == 2 {
                let handler = f[0].trim();
                let location = f[1].trim().replace("at ", "");
                tracing::error!("{from} location={location} handler='{handler}'");
                true
            } else {
                false
            }
        } else {
            false
        };

        if !printed {
            match from {
                DatabaseError::NotImplemented => {}
                _ => tracing::error!("{from}"),
            }
        }

        match &from {
            DatabaseError::AddressParseError(e) => Status::invalid_argument(e.to_string()),
            error @ DatabaseError::AlreadyFoundError { .. } => {
                Status::failed_precondition(error.to_string())
            }
            error @ DatabaseError::ConcurrentModificationError(_, _) => {
                Status::failed_precondition(error.to_string())
            }
            error @ DatabaseError::ExpectedHostDuplicateMacAddress(_) => {
                Status::failed_precondition(error.to_string())
            }
            error @ DatabaseError::FailedPrecondition(_) => {
                Status::failed_precondition(error.to_string())
            }
            error @ DatabaseError::Internal { .. } => Status::internal(error.to_string()),
            DatabaseError::InvalidArgument(msg) => Status::invalid_argument(msg),
            DatabaseError::InvalidConfiguration(e) => Status::invalid_argument(e.to_string()),
            DatabaseError::MissingArgument(msg) => Status::invalid_argument(*msg),
            DatabaseError::NetworkParseError(e) => Status::invalid_argument(e.to_string()),
            DatabaseError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
            DatabaseError::NotFoundError { kind, id } => {
                Status::not_found(format!("{kind} not found: {id}"))
            }
            DatabaseError::ResourceExhausted(kind) => Status::resource_exhausted(kind),
            DatabaseError::RpcDataConversionError(e) => Status::invalid_argument(e.to_string()),
            error @ DatabaseError::RpcUuidConversionError(_) => {
                Status::invalid_argument(error.to_string())
            }
            error @ DatabaseError::UuidConversionError(_) => {
                Status::invalid_argument(error.to_string())
            }
            other => Status::internal(other.to_string()),
        }
    }
}

// MARK: - Custom DatabaseError From<> impls to flatten error variants

impl From<ResourcePoolDatabaseError> for DatabaseError {
    fn from(from: ResourcePoolDatabaseError) -> Self {
        match from {
            ResourcePoolDatabaseError::ResourcePool(e) => DatabaseError::ResourcePoolError(e),
            ResourcePoolDatabaseError::Database(e) => *e,
        }
    }
}
impl From<::measured_boot::Error> for DatabaseError {
    fn from(value: ::measured_boot::Error) -> Self {
        DatabaseError::internal(value.to_string())
    }
}

pub struct Transaction<'a> {
    inner: sqlx::PgTransaction<'a>,
}

impl<'a> AsMut<sqlx::PgTransaction<'a>> for Transaction<'a> {
    #[inline]
    fn as_mut(&mut self) -> &mut sqlx::PgTransaction<'a> {
        &mut self.inner
    }
}

impl<'a> Transaction<'a> {
    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub fn begin(pool: &'a sqlx::PgPool) -> impl Future<Output = Result<Self, DatabaseError>> {
        let loc = Location::caller();
        async move {
            pool.begin()
                .await
                .map_err(|e| DatabaseError::txn_begin(e, loc))
                .map(|inner| Self { inner })
        }
    }

    pub async fn begin_with_location(
        pool: &sqlx::PgPool,
        loc: &'static Location<'static>,
    ) -> Result<Self, DatabaseError> {
        pool.begin()
            .await
            .map_err(|e| DatabaseError::txn_begin(e, loc))
            .map(|inner| Self { inner })
    }

    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub fn begin_inner(
        conn: &'a mut sqlx::PgConnection,
    ) -> Pin<Box<dyn Future<Output = Result<Self, DatabaseError>> + Send + 'a>> {
        let loc = Location::caller();
        Box::pin(async move {
            conn.begin()
                .await
                .map_err(|e| DatabaseError::txn_begin(e, loc))
                .map(|inner| Self { inner })
        })
    }

    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub fn commit(self) -> Pin<Box<dyn Future<Output = Result<(), DatabaseError>> + Send + 'a>> {
        let loc = Location::caller();
        Box::pin(async move {
            self.inner
                .commit()
                .await
                .map_err(|e| DatabaseError::txn_commit(e, loc))
        })
    }

    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    pub fn rollback(self) -> Pin<Box<dyn Future<Output = Result<(), DatabaseError>> + Send + 'a>> {
        let loc = Location::caller();
        Box::pin(async move {
            self.inner
                .rollback()
                .await
                .map_err(|e| DatabaseError::txn_rollback(e, loc))
        })
    }

    pub fn as_pgconn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.inner
    }
}

impl<'a> Deref for Transaction<'a> {
    type Target = sqlx::PgTransaction<'a>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Transaction<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Provides an easy way to auto-commit a transaction if no error is thrown.
pub trait WithTransaction {
    #[track_caller]
    fn with_txn<'pool, T, E>(
        &'pool self,
        f: impl for<'txn> FnOnce(
            &'txn mut PgTransaction<'pool>,
        ) -> futures::future::BoxFuture<'txn, Result<T, E>>
        + Send,
    ) -> impl Future<Output = DatabaseResult<Result<T, E>>> + Send
    where
        T: Send,
        E: Send;
}

impl WithTransaction for PgPool {
    #[track_caller]
    fn with_txn<'pool, T, E>(
        &'pool self,
        f: impl for<'txn> FnOnce(
            &'txn mut PgTransaction<'pool>,
        ) -> futures::future::BoxFuture<'txn, Result<T, E>>
        + Send,
    ) -> impl Future<Output = DatabaseResult<Result<T, E>>>
    where
        T: Send,
        E: Send,
    {
        let caller = Location::caller();
        async move {
            let mut t = self
                .begin()
                .await
                .map_err(|e| DatabaseError::txn_begin(e, caller))?;
            match f(&mut t).await {
                Ok(output) => {
                    t.commit()
                        .await
                        .map_err(|e| DatabaseError::txn_commit(e, caller))?;
                    Ok(Ok(output))
                }
                Err(e) => {
                    t.rollback().await.ok();
                    Ok(Err(e))
                }
            }
        }
    }
}

#[cfg(test)]
#[ctor::ctor]
fn setup_test_logging() {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::filter::EnvFilter;
    use tracing_subscriber::fmt::TestWriter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::util::SubscriberInitExt;

    // This duplicates code from api-test-helper, but we don't want to take a dependency on that.
    // Copy/pasting is fine.
    if let Err(e) = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_writer(TestWriter::new),
        )
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("sqlx=warn".parse().unwrap())
                .add_directive("tower=warn".parse().unwrap())
                .add_directive("rustify=off".parse().unwrap())
                .add_directive("rustls=warn".parse().unwrap())
                .add_directive("hyper=warn".parse().unwrap())
                .add_directive("h2=warn".parse().unwrap())
                // Silence permissive mode related messages
                .add_directive("carbide::auth=error".parse().unwrap()),
        )
        .try_init()
    {
        // Note: Resist the temptation to ignore this error. We really should only have one place in
        // the test binary that initializes logging.
        panic!(
            "Failed to initialize trace logging for api-db tests. It's possible some earlier \
            code path has already set a global default log subscriber: {e}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_new() {
        const OP_NAME: &str = "something people want to say";
        let DatabaseError::Sqlx(err) =
            DatabaseError::new(OP_NAME, sqlx::Error::protocol("some error"))
        else {
            unreachable!()
        };
        assert_eq!(err.line, line!() - 4);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(OP_NAME))
    }

    #[test]
    fn test_database_error_query() {
        const DB_QUERY: &str = "SELECT * from some_table;";
        let DatabaseError::Sqlx(err) =
            DatabaseError::query(DB_QUERY, sqlx::Error::protocol("some error"))
        else {
            unreachable!()
        };
        assert_eq!(err.line, line!() - 4);
        assert_eq!(err.file, file!());
        assert!(format!("{err}").contains(DB_QUERY));
    }
}
