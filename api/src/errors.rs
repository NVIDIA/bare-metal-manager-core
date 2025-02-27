/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{
    backtrace::{Backtrace, BacktraceStatus},
    net::IpAddr,
};

use crate::dhcp::allocation::DhcpError;
use crate::model::{
    ConfigValidationError, hardware_info::HardwareInfoError, network_devices::LldpError,
    tenant::TenantError,
};
use crate::{db, resource_pool};
use ::rpc::errors::RpcDataConversionError;
use config_version::ConfigVersionParseError;
use forge_uuid::machine::MachineId;
use mac_address::MacAddress;
use tonic::Status;

/// Represents various Errors that can occur throughout the system.
///
/// CarbideError is a way to represent and enrich lower-level errors with specific business logic
/// that can be handled.
///
/// It uses `thiserror` to adapt lower-level errors to this type.
#[derive(thiserror::Error, Debug)]
pub enum CarbideError {
    #[error("Generic error from report: {0}")]
    GenericErrorFromReport(#[from] eyre::ErrReport),

    #[error("Unable to parse string into IP Network: {0}")]
    NetworkParseError(#[from] ipnetwork::IpNetworkError),

    #[error("Unable to parse string into IP Address: {0}")]
    AddressParseError(#[from] std::net::AddrParseError),

    #[error("Unable to parse string into Mac Address: {0}")]
    MacAddressParseError(#[from] mac_address::MacParseError),

    #[error("Uuid type conversion error: {0}")]
    UuidConversionError(#[from] uuid::Error),

    #[error("{kind} already exists: {id}")]
    AlreadyFoundError {
        /// The type of the resource that already exists (e.g. Machine)
        kind: &'static str,
        /// The ID of the resource that already exists.
        id: String,
    },

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

    #[error("{0}")]
    DBError(#[from] db::DatabaseError),

    #[error("Database type conversion error")]
    DatabaseTypeConversionError(String),

    #[error("Database migration error: {0}")]
    DatabaseMigrationError(#[from] sqlx::migrate::MigrateError),

    #[error("Duplicate MAC address for network: {0}")]
    NetworkSegmentDuplicateMacAddress(MacAddress),

    #[error("Duplicate MAC address for expected host BMC interface: {0}")]
    ExpectedHostDuplicateMacAddress(MacAddress),

    #[error("Admin network is not configured.")]
    AdminNetworkNotConfigured,

    #[error("All Network Segments are not allocated yet.")]
    NetworkSegmentNotAllocated,

    #[error("Network has attached VPC or Subdomain : {0}")]
    NetworkSegmentDelete(String),

    #[error(
        "A unique identifier was specified for a new object.  When creating a new object of type {0}, do not specify an identifier"
    )]
    IdentifierSpecifiedForNewObject(String),

    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Only one interface per machine can be marked as primary")]
    OnePrimaryInterface,

    #[error("Find one returned no results but should return one for uuid - {0}")]
    FindOneReturnedNoResultsError(uuid::Uuid),

    #[error("Find one returned many results but should return one for uuid - {0}")]
    FindOneReturnedManyResultsError(uuid::Uuid),

    #[error("JSON Parse failure - {0}")]
    JSONParseError(#[from] serde_json::Error),

    #[error("Tokio Task Join Error {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("Can not convert between RPC data model and internal data model - {0}")]
    RpcDataConversionError(#[from] RpcDataConversionError),

    #[error("Invalid configuration version - {0}")]
    InvalidConfigurationVersion(#[from] ConfigVersionParseError),

    // TODO: Or VersionMismatchError? Or ObjectNotFoundOrModifiedError?
    #[error(
        "An object of type {0} was intended to be modified did not have the expected version {1}"
    )]
    ConcurrentModificationError(&'static str, String),

    #[error("The function is not implemented")]
    NotImplemented,

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(#[from] ConfigValidationError),

    #[error("Error in DHCP allocation/handling: {0}")]
    DhcpError(#[from] DhcpError),

    #[error("Error in libredfish: {0}")]
    RedfishError(#[from] libredfish::RedfishError),

    #[error("Error in libnvmesh: {0}")]
    NvmeshApiError(#[from] libnvmesh::NvmeshApiError),

    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] resource_pool::ResourcePoolError),

    #[error("Hardware info error: {0}")]
    HardwareInfoError(#[from] HardwareInfoError),

    #[error("Failed to call IBFabricManager: {0}")]
    IBFabricError(String),

    #[error("Failed to generate client certificate: {0}")]
    ClientCertificateError(String),

    #[error("DPU reprovisioning is already started: {0}")]
    DpuReprovisioningInProgress(String),

    #[error("Tenant handling error: {0}")]
    TenantError(#[from] TenantError),

    #[error("Machine is in maintenance mode. Cannot allocate instance on it.")]
    MaintenanceMode,

    #[error("Resource {0} is empty")]
    ResourceExhausted(String),

    #[error("Host is not available for allocation due to health probe alert")]
    UnhealthyHost,

    #[error("Lldp handling error: {0}")]
    LldpError(#[from] LldpError),

    #[error("DPU {0} is missing from host snapshot")]
    MissingDpu(MachineId),

    #[error("Attest Quote Error: {0}")]
    AttestQuoteError(String),

    #[error("Attest Bind Key Error: {0}")]
    AttestBindKeyError(String),

    #[error("Explored machine at {0} has no DPUs")]
    NoDpusInMachine(IpAddr),

    #[error("{requested_ip} resolves to {found_mac} not {requested_mac}")]
    BmcMacIpMismatch {
        /// The BMC endpoint IP requested by the caller
        requested_ip: String,
        /// The BMC MAC address requested by the caller
        requested_mac: String,
        /// The actual BMC MAC address found associated with the endpoint IP
        found_mac: String,
    },

    #[error("{0}")]
    FailedPrecondition(String),
}

impl CarbideError {
    /// Creates a `Internal` error with the given error message
    pub fn internal(message: String) -> Self {
        CarbideError::Internal { message }
    }
}

#[test]
fn test_carbide_error() {
    let error = crate::CarbideError::internal(String::from("unable to yeet foo into the sun"));
    assert_eq!(
        error.to_string(),
        "Internal error: unable to yeet foo into the sun"
    );
}

impl From<::measured_boot::Error> for CarbideError {
    fn from(value: ::measured_boot::Error) -> Self {
        CarbideError::internal(value.to_string())
    }
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
                tracing::error!("{from} location={location} handler='{handler}'");
                printed = true;
            }
        }
        if !printed {
            match from {
                CarbideError::NotImplemented => {}
                _ => tracing::error!("{from}"),
            }
        }

        // TODO: There's many more mapped to `Status::internal` which are likely
        // user errors instead
        match &from {
            e @ CarbideError::Internal { .. } => Status::internal(e.to_string()),
            CarbideError::InvalidArgument(msg) => Status::invalid_argument(msg),
            CarbideError::InvalidConfiguration(e) => Status::invalid_argument(e.to_string()),
            CarbideError::RpcDataConversionError(e) => Status::invalid_argument(e.to_string()),
            CarbideError::MissingArgument(msg) => Status::invalid_argument(*msg),
            CarbideError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
            CarbideError::NotFoundError { kind, id } => {
                Status::not_found(format!("{kind} not found: {id}"))
            }
            CarbideError::MaintenanceMode => {
                Status::failed_precondition("MaintenanceMode".to_string())
            }
            e @ CarbideError::BmcMacIpMismatch { .. } => Status::invalid_argument(e.to_string()),
            CarbideError::UnhealthyHost => Status::failed_precondition(from.to_string()),
            CarbideError::ResourceExhausted(kind) => Status::resource_exhausted(kind),
            error @ CarbideError::ConcurrentModificationError(_, _) => {
                Status::failed_precondition(error.to_string())
            }
            error @ CarbideError::FailedPrecondition(_) => {
                Status::failed_precondition(error.to_string())
            }
            other => Status::internal(other.to_string()),
        }
    }
}

/// Result type for the return type of Carbide functions
///
/// Wraps `CarbideError` into `CarbideResult<T>`
pub type CarbideResult<T> = Result<T, CarbideError>;

#[test]
fn test_carbide_result() {
    use crate::{CarbideError, CarbideResult};

    pub fn do_something() -> CarbideResult<u8> {
        Err(CarbideError::internal(String::from("can't make u8")))
    }
    assert!(matches!(do_something(), Err(CarbideError::Internal { .. })));
}
