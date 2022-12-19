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

use dhcp::allocation::DhcpError;
use mac_address::MacAddress;
use model::{
    config_version::{ConfigVersion, ParseConfigVersionError},
    ConfigValidationError, RpcDataConversionError,
};
use rust_fsm::TransitionImpossibleError;
use sqlx::postgres::PgDatabaseError;
use state_controller::snapshot_loader::SnapshotLoaderError;
use tonic::Status;

#[cfg(test)]
use ::rstest_reuse;

pub mod api;
mod auth;
pub mod bg;
pub mod cfg;
pub mod credentials;
pub mod db;
mod dhcp;
mod human_hash;
pub mod instance;
pub mod ipmi;
pub mod kubernetes;
pub mod model;
pub mod state_controller;
pub mod vpc_resources;

/// Special user-defined code for PostgreSQL level state transition violation
///
/// This error code is generated when we attempt to move a machine to a new desired state that is
/// an invalid transition (e.g. transitioning from `adopted` to `allocated` is impossible because
/// it requires hardware testing and validation first)
///
const SQL_STATE_TRANSITION_VIOLATION_CODE: &str = "T0100";

/// Represents various Errors that can occur throughout the system.
///
/// CarbideError is a way to represent and enrich lower-level errors with specific business logic
/// that can be handled (e.g. MachineStateTransitionViolation).
///
/// It uses `thiserror` to adapt lower-level errors to this type.
///
/// # Examples
/// ```
/// let error = carbide::CarbideError::GenericError(String::from("unable to yeet foo into the sun"));
///
/// assert_eq!(error.to_string(), "Generic error: unable to yeet foo into the sun");
/// ```
///
#[derive(thiserror::Error, Debug)]
pub enum CarbideError {
    #[error("Unable to parse string into IP Network: {0}")]
    NetworkParseError(#[from] ipnetwork::IpNetworkError),

    #[error("Unable to parse string into IP Address: {0}")]
    AddressParseError(#[from] std::net::AddrParseError),

    #[error("Unable to parse string into Mac Address: {0}")]
    MacAddressParseError(#[from] mac_address::MacParseError),

    #[error("Uuid type conversion error: {0}")]
    UuidConversionError(#[from] uuid::Error),

    #[error("Uuid was not found: {0}")]
    NotFoundError(uuid::Uuid),

    #[error("Argument is missing in input: {0}")]
    MissingArgument(&'static str),

    #[error("Arguemnt is invalid: {0}")]
    InvalidArgument(String),

    #[error("Database Query Error: {0}")]
    DatabaseError(sqlx::Error),

    #[error("Could not transition across states in the state machine: {0}")]
    InvalidState(TransitionImpossibleError),

    #[error("Invalid machine state transition: {0}")]
    MachineStateTransitionViolation(String, Option<String>),

    #[error("Database type conversion error")]
    DatabaseTypeConversionError(String),

    #[error("Database migration error: {0}")]
    DatabaseMigrationError(#[from] sqlx::migrate::MigrateError),

    #[error("Multiple network segments defined for relay address: {0}")]
    MultipleNetworkSegmentsForRelay(IpAddr),

    #[error("No network segment defined for relay address: {0}")]
    NoNetworkSegmentsForRelay(IpAddr),

    #[error("Unable to generate ephemeral hostname from uuid: {0}")]
    HostnameGenerationError(String),

    #[error("Attempted to retrieve the next IP from a network segment without a subnet for that address family: {0}")]
    NetworkSegmentMissingAddressFamilyError(String),

    #[error("Duplicate MAC address for network: {0}")]
    NetworkSegmentDuplicateMacAddress(MacAddress),

    #[error("Attempted to retrieve the next IP from a network segment exhausted of IP space: {0}")]
    NetworkSegmentsExhausted(String),

    #[error("Network has attached VPC or Subdomain : {0}")]
    NetworkSegmentDelete(String),

    #[error("A machine that was just created, failed to return any rows: {0}")]
    DatabaseInconsistencyOnMachineCreate(uuid::Uuid),

    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("A unique identifier was specified for a new object.  When creating a new object of type {0}, do not specify an identifier")]
    IdentifierSpecifiedForNewObject(String),

    #[error("A unique identifier was not specified for an existing object.  Please specify an identifier")]
    IdentifierNotSpecifiedForObject(),

    #[error("The Domain named {0} already exists. Domain names must be unique")]
    DuplicateDomain(String),

    #[error("The Domain name {0} contains illegal characters")]
    InvalidDomainName(String),

    #[error("The domain name object {0} does not exist")]
    UnknownDomain(uuid::Uuid),

    #[error("Only one interface per machine can be marked as primary")]
    OnePrimaryInterface,

    #[error("Duplicate record for {0} that should be unique: {1}")]
    DuplicateRecordIdentifier(&'static str, uuid::Uuid),

    #[error("Find one returned no results but should return one for uuid - {0}")]
    FindOneReturnedNoResultsError(uuid::Uuid),

    #[error("Find one returned many results but should return one for uuid - {0}")]
    FindOneReturnedManyResultsError(uuid::Uuid),

    #[error("JSON Parse failure - {0}")]
    JSONParseError(#[from] serde_json::Error),

    #[error("Kubernetes Client Error - {0}")]
    KubeClientError(kube::Error),

    #[error("Tokio Timeout Error - {0}")]
    TokioTimeoutError(String),

    #[error("Tokio Task Join Error {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("Kube Runtime Wait Error - {0}")]
    KubeWaitError(#[from] kube::runtime::wait::Error),

    #[error("Multiple IP assigned by DHCP - {0}")]
    DHCPMultipleIPAssigned(String),

    #[error("Invalid value received in Enum - {0}")]
    InvalidValueInEnum(String),

    #[error("Can not convert between RPC data model and internal data model - {0}")]
    RpcDataConversionError(#[from] RpcDataConversionError),

    #[error("Invalid configuration version - {0}")]
    InvalidConfigurationVersion(#[from] ParseConfigVersionError),

    #[error("Failed to load machine or instance snapshot: {0}")]
    SnapshotLoaderError(#[from] SnapshotLoaderError),

    // TODO: Or VersionMismatchError? Or ObjectNotFoundOrModifiedError?
    #[error(
        "An object of type {0} was intended to be modified did not have the expected version {1}"
    )]
    ConcurrentModificationError(&'static str, ConfigVersion),

    #[error("The function is not implemented")]
    NotImplemented,

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(#[from] ConfigValidationError),

    #[error("Error in DHCP allocation/handling: {0}")]
    DhcpError(#[from] DhcpError),
}

impl From<CarbideError> for tonic::Status {
    fn from(from: CarbideError) -> Self {
        // TODO: There's many more mapped to `Status::internal` which are likely
        // user errors instead
        match from {
            CarbideError::InvalidArgument(msg) => Status::invalid_argument(msg),
            CarbideError::InvalidConfiguration(e) => Status::invalid_argument(e.to_string()),
            CarbideError::MissingArgument(msg) => Status::invalid_argument(msg),
            CarbideError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
            error @ CarbideError::ConcurrentModificationError(_, _) => {
                Status::failed_precondition(error.to_string())
            }
            other => Status::internal(other.to_string()),
        }
    }
}

/// Converts a kube::Error to a CarbideError
///
/// https://docs.rs/kube/latest/kube/error/enum.Error.html
/// kube::error::Error contains all possible errors when working with kube_client
///
impl From<kube::Error> for CarbideError {
    fn from(err: kube::Error) -> CarbideError {
        Self::KubeClientError(err)
    }
}

/// Convert a sqlx::Error to a CarbideError
///
/// This conversion will intercept an SQL State code of T0100 to catch the invalid state change of
/// a machine instead of just returning a raw SqlError.  This requires not deriving `from` for the
/// enum variant.
///
impl From<sqlx::Error> for CarbideError {
    fn from(error: sqlx::Error) -> CarbideError {
        log::info!("Error: {:?}", error);

        if let Some(sql_error) = error.as_database_error() {
            let postgres_error: &PgDatabaseError = sql_error.downcast_ref();
            if postgres_error.code() == SQL_STATE_TRANSITION_VIOLATION_CODE {
                return Self::MachineStateTransitionViolation(
                    postgres_error.message().to_string(),
                    postgres_error.hint().map(String::from),
                );
            }
        }
        Self::DatabaseError(error)
    }
}

/// Result type for the return type of Carbide functions
///
/// Wraps `CarbideError` into `CarbideResult<T>`
///
/// # Examples
/// ```
/// use carbide::{CarbideError, CarbideResult};
///
/// pub fn do_something() -> CarbideResult<u8> {
///   Err(CarbideError::GenericError(String::from("can't make u8")))
/// }
/// assert!(matches!(do_something(), Err(CarbideError::GenericError(_))));
/// ```
pub type CarbideResult<T> = Result<T, CarbideError>;

//pub fn network_to_host_ipv4(src: IpNetwork) -> CarbideResult<Ipv4Addr> {
//    match src {
//        IpNetwork::V4(network) => Ok(network.ip()),
//        IpNetwork::V6(network) => Err(CarbideError::GenericError(format!(
//            "IP address field in address_ipv4 ({}) is not an IPv4 subnet",
//            network
//        ))),
//    }
//}
//
//pub fn network_to_host_ipv6(src: IpNetwork) -> CarbideResult<Ipv6Addr> {
//    match src {
//        IpNetwork::V6(network) => Ok(network.ip()),
//        IpNetwork::V4(network) => Err(CarbideError::GenericError(format!(
//            "IP address field in address_ipv4 ({}) is not an IPv4 subnet",
//            network
//        ))),
//    }
//}
