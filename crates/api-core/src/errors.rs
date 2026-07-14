/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::backtrace::{Backtrace, BacktraceStatus};

use ::rpc::errors::RpcDataConversionError;
use carbide_ib_fabric::errors::IbError;
use carbide_redfish::libredfish::RedfishClientCreationError;
use carbide_redfish::libredfish::dpu_bios::is_dpu_bios_attributes_not_ready;
use carbide_uuid::machine::MachineId;
use config_version::ConfigVersionParseError;
use db::ip_allocator::DhcpError;
use db::machine_interface_address::AddressAlreadyInUseError;
use db::resource_pool::ResourcePoolDatabaseError;
use db::{AnnotatedSqlxError, DatabaseError};
use librms::RackManagerError;
use mac_address::MacAddress;
use model::errors::{ErrorCode, ErrorSubsystem, ModelError, OperatorError, OperatorErrorSchema};
use model::hardware_info::HardwareInfoError;
use model::network_devices::LldpError;
use model::site_explorer::EndpointExplorationError;
use model::tenant::TenantError;
use model::vpc::VpcCapabilityError;
use model::{ConfigValidationError, resource_pool};
use tonic::Status;
use tonic::metadata::MetadataValue;

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

    #[error("RPC Uuid type conversion error: {0}")]
    RpcUuidConversionError(#[from] carbide_uuid::UuidConversionError),

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

    #[error("Argument is invalid: {0}")]
    VpcCapability(#[from] VpcCapabilityError),

    #[error(transparent)]
    AddressAlreadyInUse(#[from] AddressAlreadyInUseError),

    #[error("{0}")]
    DBError(#[from] AnnotatedSqlxError),

    #[error("Database type conversion error")]
    DatabaseTypeConversionError(String),

    #[error("Database migration error: {0}")]
    DatabaseMigrationError(#[from] sqlx::migrate::MigrateError),

    #[error("Duplicate MAC address for network: {0}")]
    NetworkSegmentDuplicateMacAddress(MacAddress),

    #[error("Duplicate MAC address for expected host BMC interface: {0}")]
    ExpectedHostDuplicateMacAddress(MacAddress),

    #[error("NVOS MAC address is already claimed by another expected switch: {0}")]
    ExpectedSwitchDuplicateNvosMacAddress(MacAddress),

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

    #[error("Could not create connection to Redfish API to {machine_id}, check logs")]
    RedfishClientCreation {
        inner: Box<RedfishClientCreationError>,
        machine_id: MachineId,
    },

    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] resource_pool::ResourcePoolError),

    #[error("Resource pool database error: {0}")]
    ResourcePoolDatabaseError(#[from] ResourcePoolDatabaseError),

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

    #[error("Failed to map device to dpu: {0}")]
    DpuMappingError(String),

    #[error("Client certificate presented has missing information: {0}.")]
    ClientCertificateMissingInformation(String),

    #[error("Rack Manager Service error: {0}")]
    RackManagerError(#[from] RackManagerError),

    #[error("Maximum one association per interface")]
    MaxOneInterfaceAssociation,

    #[error("DPF error: {0}")]
    DpfError(#[from] carbide_dpf::DpfError),

    #[error("Service unavailable: {0}")]
    UnavailableError(String),

    #[error("Permission denied: {0}")]
    PermissionDeniedError(String),

    #[error("{0}")]
    AlreadyInProgress(String),

    #[error("Attestation Error: {0}")]
    AttestationError(String),
}

impl From<libnmxc::NmxcError> for CarbideError {
    fn from(e: libnmxc::NmxcError) -> Self {
        match e {
            libnmxc::NmxcError::Status(s) => CarbideError::internal(s.to_string()),
            other => CarbideError::internal(other.to_string()),
        }
    }
}

impl From<ModelError> for CarbideError {
    fn from(e: ModelError) -> Self {
        match e {
            ModelError::DpuMappingError(e) => Self::DpuMappingError(e),
            ModelError::MissingDpu(e) => Self::MissingDpu(e),
            ModelError::DatabaseTypeConversionError(e) => Self::DatabaseTypeConversionError(e),
            ModelError::MissingArgument(e) => Self::MissingArgument(e),
            ModelError::HardwareInfo(e) => Self::HardwareInfoError(e),
            ModelError::InvalidArgument(e) => Self::InvalidArgument(e),
        }
    }
}

impl From<DatabaseError> for CarbideError {
    fn from(e: DatabaseError) -> Self {
        use CarbideError::*;
        match e {
            DatabaseError::AddressAlreadyInUse(e) => AddressAlreadyInUse(e),
            DatabaseError::AddressParseError(e) => AddressParseError(e),
            DatabaseError::AdminNetworkNotConfigured => AdminNetworkNotConfigured,
            DatabaseError::AlreadyFoundError { kind, id } => AlreadyFoundError { kind, id },
            DatabaseError::ConcurrentModificationError(type_str, msg) => {
                ConcurrentModificationError(type_str, msg)
            }
            DatabaseError::DhcpError(e) => DhcpError(e),
            DatabaseError::ExpectedHostDuplicateMacAddress(e) => ExpectedHostDuplicateMacAddress(e),
            DatabaseError::ExpectedSwitchDuplicateNvosMacAddress(e) => {
                ExpectedSwitchDuplicateNvosMacAddress(e)
            }
            DatabaseError::FailedPrecondition(e) => FailedPrecondition(e),
            DatabaseError::FindOneReturnedManyResultsError(e) => FindOneReturnedManyResultsError(e),
            DatabaseError::FindOneReturnedNoResultsError(e) => FindOneReturnedNoResultsError(e),
            DatabaseError::GenericErrorFromReport(e) => GenericErrorFromReport(e),
            DatabaseError::HardwareInfoError(e) => HardwareInfoError(e),
            DatabaseError::Internal { message } => Internal { message },
            DatabaseError::InvalidArgument(e) => InvalidArgument(e),
            DatabaseError::InvalidConfiguration(e) => InvalidConfiguration(e),
            DatabaseError::MissingArgument(e) => MissingArgument(e),
            // A corrupted/absent site-wide rotation invariant is an internal
            // state error, not a client-correctable one.
            DatabaseError::MissingSitewideRotationTarget(credential_type) => Internal {
                message: format!(
                    "no site-wide rotation target for credential type: {credential_type:?}"
                ),
            },
            DatabaseError::NetworkParseError(e) => NetworkParseError(e),
            DatabaseError::NetworkSegmentDelete(e) => NetworkSegmentDelete(e),
            DatabaseError::NetworkSegmentDuplicateMacAddress(e) => {
                NetworkSegmentDuplicateMacAddress(e)
            }
            DatabaseError::NetworkSegmentNotAllocated => NetworkSegmentNotAllocated,
            DatabaseError::NotFoundError { kind, id } => NotFoundError { kind, id },
            DatabaseError::NotImplemented => NotImplemented,
            DatabaseError::OnePrimaryInterface => OnePrimaryInterface,
            DatabaseError::ResourceExhausted(e) => ResourceExhausted(e),
            DatabaseError::ResourcePoolError(e) => ResourcePoolError(e),
            DatabaseError::RpcUuidConversionError(e) => RpcUuidConversionError(e),
            DatabaseError::Sqlx(e) => DBError(e),
            DatabaseError::TenantError(e) => TenantError(e),
            DatabaseError::UuidConversionError(e) => UuidConversionError(e),
            DatabaseError::MaxOneInterfaceAssociation => MaxOneInterfaceAssociation,
            DatabaseError::TryAgain => Internal {
                message: DatabaseError::TryAgain.to_string(),
            },
        }
    }
}

impl From<IbError> for CarbideError {
    fn from(e: IbError) -> Self {
        match e {
            IbError::DatabaseError(e) => e.into(),
            IbError::ModelError(e) => e.into(),
            IbError::IBFabricError(msg) => Self::IBFabricError(msg),
            IbError::NotFoundError { kind, id } => Self::NotFoundError { kind, id },
            IbError::InvalidArgument(e) => Self::InvalidArgument(e),
            IbError::NotImplemented => Self::NotImplemented,
            IbError::Internal { message } => Self::Internal { message },
        }
    }
}

impl CarbideError {
    /// Creates a `Internal` error with the given error message
    pub fn internal(message: String) -> Self {
        CarbideError::Internal { message }
    }
}

impl OperatorError for CarbideError {
    fn operator_error_code(&self) -> ErrorCode {
        use ErrorSubsystem::{Api, Redfish};
        match self {
            CarbideError::InvalidArgument(_)
            | CarbideError::VpcCapability(_)
            | CarbideError::InvalidConfiguration(_)
            | CarbideError::RpcDataConversionError(_)
            | CarbideError::MissingArgument(_)
            | CarbideError::NetworkSegmentDelete(_)
            | CarbideError::BmcMacIpMismatch { .. } => ErrorCode::nico(Api, 400),
            CarbideError::ClientCertificateMissingInformation(_) => ErrorCode::nico(Api, 401),
            CarbideError::PermissionDeniedError(_) => ErrorCode::nico(Api, 403),
            CarbideError::NotFoundError { .. } => ErrorCode::nico(Api, 404),
            CarbideError::AlreadyFoundError { .. } | CarbideError::AlreadyInProgress(_) => {
                ErrorCode::nico(Api, 409)
            }
            CarbideError::MaintenanceMode
            | CarbideError::UnhealthyHost
            | CarbideError::ConcurrentModificationError(_, _)
            | CarbideError::FailedPrecondition(_)
            | CarbideError::ExpectedSwitchDuplicateNvosMacAddress(_)
            | CarbideError::AddressAlreadyInUse(_) => ErrorCode::nico(Api, 412),
            CarbideError::ResourceExhausted(_) | CarbideError::DhcpError(_) => {
                ErrorCode::nico(Api, 429)
            }
            CarbideError::UnavailableError(_) => ErrorCode::nico(Api, 503),
            CarbideError::RedfishError(error) if is_dpu_bios_attributes_not_ready(error) => {
                EndpointExplorationError::INVALID_DPU_REDFISH_BIOS_RESPONSE_CODE
            }
            CarbideError::RedfishError(_) | CarbideError::RedfishClientCreation { .. } => {
                ErrorCode::nico(Redfish, 500)
            }
            _ => ErrorCode::nico(Api, 500),
        }
    }

    fn operator_mitigation(&self) -> Option<&'static str> {
        match self {
            CarbideError::RedfishError(error) if is_dpu_bios_attributes_not_ready(error) => {
                Some(EndpointExplorationError::INVALID_DPU_REDFISH_BIOS_RESPONSE_MITIGATION)
            }
            CarbideError::RedfishError(_) | CarbideError::RedfishClientCreation { .. } => {
                Some("Check BMC reachability, credentials, and Redfish service health.")
            }
            CarbideError::UnavailableError(_) => Some(
                "A dependent NICo service is temporarily unavailable. Retry the same request \
                 once it recovers: re-run the Admin CLI command, REST API call, or client \
                 integration that failed, backing off briefly between attempts.",
            ),
            CarbideError::ResourceExhausted(_) | CarbideError::DhcpError(_) => {
                Some("Check configured resource pools and available capacity.")
            }
            _ => None,
        }
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
    fn from(value: measured_boot::Error) -> Self {
        CarbideError::internal(value.to_string())
    }
}

impl From<CarbideError> for tonic::Status {
    fn from(from: CarbideError) -> Self {
        let schema = from.operator_error_schema();
        log_carbide_error(&from, &schema);

        let status = status_from_carbide_error(&from);
        status_with_operator_error_schema(status, &schema)
    }
}

fn log_carbide_error(error: &CarbideError, schema: &OperatorErrorSchema) {
    if matches!(error, CarbideError::NotImplemented) {
        return;
    }

    if let Some((handler, location)) = carbide_backtrace_location() {
        tracing::error!(
            error = %error,
            error_code = %schema.error_code,
            mitigation = %schema.mitigation_for_log(),
            text = %schema.text,
            location = %location,
            handler = %handler,
            "Request failed"
        );
    } else {
        tracing::error!(
            error = %error,
            error_code = %schema.error_code,
            mitigation = %schema.mitigation_for_log(),
            text = %schema.text,
            "Request failed"
        );
    }
}

fn carbide_backtrace_location() -> Option<(String, String)> {
    // If env RUST_BACKTRACE is set extract handler and err location.
    // If it's not set, `Backtrace::capture()` is very cheap to call.
    let backtrace = Backtrace::capture();
    if backtrace.status() != BacktraceStatus::Captured {
        return None;
    }

    let rendered = backtrace.to_string();
    parse_carbide_backtrace_location(&rendered)
        .map(|(handler, location)| (handler.to_owned(), location.to_owned()))
}

fn parse_carbide_backtrace_location(backtrace: &str) -> Option<(&str, &str)> {
    const ERROR_MODULE_PATH: &str = "crates/api-core/src/errors.rs:";
    const ERROR_MODULE_SYMBOL: &str = "carbide_api_core::errors";

    let mut lines = backtrace.lines().peekable();
    while let Some(handler) = lines.next() {
        let handler = handler.trim();
        let Some(location) = lines
            .peek()
            .and_then(|line| line.trim().strip_prefix("at "))
        else {
            continue;
        };
        lines.next();

        // Conversion frames can be sourced from this module or from core while
        // still naming CarbideError in the symbol. Neither identifies the RPC handler.
        if !handler.contains("carbide")
            || handler.contains(ERROR_MODULE_SYMBOL)
            || location.contains(ERROR_MODULE_PATH)
        {
            continue;
        }

        return Some((handler, location));
    }

    None
}

fn status_from_carbide_error(error: &CarbideError) -> Status {
    // TODO: There's many more mapped to `Status::internal` which are likely
    // user errors instead
    match error {
        e @ CarbideError::Internal { .. } => Status::internal(e.to_string()),
        CarbideError::InvalidArgument(msg) => Status::invalid_argument(msg),
        error @ CarbideError::VpcCapability(_) => Status::invalid_argument(error.to_string()),
        CarbideError::InvalidConfiguration(e) => Status::invalid_argument(e.to_string()),
        CarbideError::RpcDataConversionError(e) => Status::invalid_argument(e.to_string()),
        e @ CarbideError::DhcpError(_) => Status::resource_exhausted(e.to_string()),
        CarbideError::MissingArgument(msg) => Status::invalid_argument(*msg),
        CarbideError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
        CarbideError::NotFoundError { kind, id } => {
            Status::not_found(format!("{kind} not found: {id}"))
        }
        CarbideError::AlreadyFoundError { kind, id } => {
            Status::already_exists(format!("{kind} already exists: {id}"))
        }
        CarbideError::MaintenanceMode => Status::failed_precondition("MaintenanceMode".to_string()),
        e @ CarbideError::BmcMacIpMismatch { .. } => Status::invalid_argument(e.to_string()),
        CarbideError::UnhealthyHost => Status::failed_precondition(error.to_string()),
        CarbideError::ResourceExhausted(kind) => Status::resource_exhausted(kind),
        error @ CarbideError::ConcurrentModificationError(_, _) => {
            Status::failed_precondition(error.to_string())
        }
        error @ CarbideError::FailedPrecondition(_) => {
            Status::failed_precondition(error.to_string())
        }
        error @ CarbideError::ExpectedSwitchDuplicateNvosMacAddress(_) => {
            Status::failed_precondition(error.to_string())
        }
        error @ CarbideError::AddressAlreadyInUse(_) => {
            Status::failed_precondition(error.to_string())
        }
        error @ CarbideError::ClientCertificateMissingInformation(_) => {
            Status::unauthenticated(error.to_string())
        }
        CarbideError::UnavailableError(msg) => Status::unavailable(msg),
        CarbideError::PermissionDeniedError(msg) => Status::permission_denied(msg),
        CarbideError::AlreadyInProgress(msg) => Status::already_exists(msg),
        other => Status::internal(other.to_string()),
    }
}

fn status_with_operator_error_schema(mut status: Status, schema: &OperatorErrorSchema) -> Status {
    insert_ascii_metadata(
        &mut status,
        "nico-error-code",
        &schema.error_code.to_string(),
    );
    insert_ascii_metadata(&mut status, "nico-error-text", &schema.text);
    if let Some(mitigation) = &schema.mitigation {
        insert_ascii_metadata(&mut status, "nico-error-mitigation", mitigation);
    }

    status
}

fn insert_ascii_metadata(status: &mut Status, key: &'static str, value: &str) {
    match MetadataValue::try_from(value) {
        Ok(value) => {
            status.metadata_mut().insert(key, value);
        }
        Err(error) => {
            tracing::warn!(
                metadata_key = key,
                error = %error,
                "Operator error metadata was rejected because it contains non-ASCII content"
            );
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

#[test]
fn test_dhcp_error_maps_to_resource_exhausted_status() {
    let err = CarbideError::DhcpError(DhcpError::PrefixExhausted(
        "10.217.5.160".parse().expect("valid IP"),
    ));
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

#[test]
fn test_unavailable_error_maps_to_unavailable_status() {
    let err = CarbideError::UnavailableError("service down".into());
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

#[test]
fn unavailable_error_schema_describes_who_should_retry() {
    let schema = CarbideError::UnavailableError("service down".into()).operator_error_schema();

    let mitigation = schema.mitigation.expect("has a mitigation");
    assert!(mitigation.contains("Admin CLI"));
    assert!(mitigation.contains("REST API"));
}

#[test]
fn backtrace_location_skips_error_conversion_frames() {
    use carbide_test_support::value_scenarios;

    const WITH_OUTER_HANDLER: &str = r#"
   3: carbide_api_core::errors::carbide_backtrace_location
             at ./crates/api-core/src/errors.rs:461:13
   4: carbide_api_core::errors::log_carbide_error
             at /workspace/infra-controller/crates/api-core/src/errors.rs:437:9
   5: <tonic::status::Status as core::convert::From<carbide_api_core::errors::CarbideError>>::from
             at ./crates/api-core/src/errors.rs:425:9
   6: <carbide_api_core::errors::CarbideError as core::convert::Into<tonic::status::Status>>::into
             at /rustc/library/core/src/convert/mod.rs:761:9
   7: carbide_api_core::handlers::machine::create_machine
             at ./crates/api-core/src/handlers/machine.rs:412:24
"#;
    const ERROR_FRAMES_ONLY: &str = r#"
   3: carbide_api_core::errors::carbide_backtrace_location
             at ./crates/api-core/src/errors.rs:461:13
   4: carbide_api_core::errors::log_carbide_error
             at ./crates/api-core/src/errors.rs:437:9
   5: <tonic::status::Status as core::convert::From<carbide_api_core::errors::CarbideError>>::from
             at ./crates/api-core/src/errors.rs:425:9
"#;

    value_scenarios!(
        run = parse_carbide_backtrace_location;
        "frame selection" {
            WITH_OUTER_HANDLER => Some((
                "7: carbide_api_core::handlers::machine::create_machine",
                "./crates/api-core/src/handlers/machine.rs:412:24",
            )),
            ERROR_FRAMES_ONLY => None,
        }
    );
}

#[test]
fn invalid_argument_status_includes_operator_schema_metadata() {
    let err = CarbideError::InvalidArgument("bad input".into());
    let status: tonic::Status = err.into();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        status
            .metadata()
            .get("nico-error-code")
            .expect("metadata should include operator error code")
            .to_str()
            .expect("operator error code should be ASCII"),
        "NICO-API-400"
    );
    assert_eq!(
        status
            .metadata()
            .get("nico-error-text")
            .expect("metadata should include operator error text")
            .to_str()
            .expect("operator error text should be ASCII"),
        "Argument is invalid: bad input"
    );
}

#[test]
fn dpu_bios_redfish_error_uses_dpu_operator_schema() {
    let err = CarbideError::RedfishError(libredfish::RedfishError::MissingKey {
        key: "HostPrivilegeLevel".to_string(),
        url: "Systems/{}/Bios".to_string(),
    });

    let schema = err.operator_error_schema();

    assert_eq!(
        schema.error_code,
        EndpointExplorationError::INVALID_DPU_REDFISH_BIOS_RESPONSE_CODE
    );
    assert_eq!(
        schema.mitigation.as_deref(),
        Some(EndpointExplorationError::INVALID_DPU_REDFISH_BIOS_RESPONSE_MITIGATION)
    );
}

#[test]
fn test_permission_denied_error_maps_to_permission_denied_status() {
    let err = CarbideError::PermissionDeniedError("not allowed".into());
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[test]
fn test_address_already_in_use_maps_to_failed_precondition_status() {
    use std::str::FromStr;
    let err = CarbideError::AddressAlreadyInUse(AddressAlreadyInUseError(
        "10.0.0.1".parse().unwrap(),
        MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
        uuid::Uuid::new_v4().into(),
        uuid::Uuid::new_v4().into(),
    ));
    let status: tonic::Status = err.into();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}
