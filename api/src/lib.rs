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
use std::backtrace::{Backtrace, BacktraceStatus};
use std::net::IpAddr;

#[cfg(test)]
use ::rstest_reuse;
use dhcp::allocation::DhcpError;
use kubernetes::VpcApiError;
use mac_address::MacAddress;
use model::hardware_info::HardwareInfoError;
use model::machine::machine_id::MachineId;
use model::{
    config_version::{ConfigVersion, ParseConfigVersionError},
    ConfigValidationError, RpcDataConversionError,
};
use reachability::ReachabilityError;
use rust_fsm::TransitionImpossibleError;
use state_controller::snapshot_loader::SnapshotLoaderError;
use tonic::Status;

pub mod api;
pub mod auth;
pub mod bg;
pub mod cfg;
pub mod credentials;
pub mod db;
mod dhcp;
pub mod ethernet_virtualization;
mod human_hash;
pub mod instance;
pub mod ipmi;
mod ipxe;
pub mod kubernetes;
pub mod logging;
pub mod model;
pub mod reachability;
pub mod redfish;
pub mod resource_pool;
pub mod state_controller;
pub mod vpc_resources;

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

    #[error("{kind} not found: {id}")]
    NotFoundError {
        /// The type of the resource that was not found (e.g. Machine)
        kind: &'static str,
        /// The ID of the resource that was not found
        id: String,
    },

    #[error("Argument is missing in input: {0}")]
    MissingArgument(&'static str),

    #[error("Argument is invalid: {0}")]
    InvalidArgument(String),

    // OLD, use DBError instead
    #[error("Database Error: {2}. context={0}, query={1}.")]
    DatabaseError(&'static str, &'static str, #[source] sqlx::Error),

    // NEW
    #[error("{0}")]
    DBError(#[from] db::DatabaseError),

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

    #[error("Admin network is not configured.")]
    AdminNetworkNotConfigured,

    #[error("Network has attached VPC or Subdomain : {0}")]
    NetworkSegmentDelete(String),

    #[error("A machine that was just created, failed to return any rows: {0}")]
    DatabaseInconsistencyOnMachineCreate(MachineId),

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

    #[error("DPU Reachability Error: {0}")]
    ReachabilityError(#[from] ReachabilityError),

    #[error("More than one leaf exist referring to the same loopback IP: {0}")]
    DuplicateLoopbackIPError(IpAddr),

    #[error("Failed interaction with VPC: {0}")]
    VpcApiError(#[from] VpcApiError),

    #[error("Error in libredfish: {0}")]
    RedfishError(#[from] libredfish::RedfishError),

    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] resource_pool::ResourcePoolError),

    #[error("Hardware info error: {0}")]
    HardwareInfoError(#[from] HardwareInfoError),
}

impl From<CarbideError> for tonic::Status {
    fn from(from: CarbideError) -> Self {
        // If env RUST_BACKTRACE is set extract handler and err location
        // If it's not set `Backtrace::capture()` is very cheap to call
        let mut printed = false;
        let b = Backtrace::capture();
        if b.status() == BacktraceStatus::Captured {
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
                log::error!("{from} location={location} handler='{handler}'");
                printed = true;
            }
        }
        if !printed {
            match from {
                CarbideError::NotImplemented => {}
                _ => log::error!("{from}"),
            }
        }

        // TODO: There's many more mapped to `Status::internal` which are likely
        // user errors instead
        match &from {
            CarbideError::InvalidArgument(msg) => Status::invalid_argument(msg),
            CarbideError::InvalidConfiguration(e) => Status::invalid_argument(e.to_string()),
            CarbideError::MissingArgument(msg) => Status::invalid_argument(*msg),
            CarbideError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
            CarbideError::NotFoundError { kind, id } => {
                Status::not_found(format!("missing {kind} {id}"))
            }
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
