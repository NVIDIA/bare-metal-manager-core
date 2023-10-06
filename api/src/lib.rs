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
use std::{
    backtrace::{Backtrace, BacktraceStatus},
    net::IpAddr,
};

use dhcp::allocation::DhcpError;
use eyre::WrapErr;
use mac_address::MacAddress;
use model::{
    config_version::{ConfigVersion, ConfigVersionParseError},
    hardware_info::HardwareInfoError,
    machine::machine_id::MachineId,
    network_devices::LldpError,
    tenant::TenantError,
    ConfigValidationError, RpcDataConversionError,
};
use state_controller::snapshot_loader::SnapshotLoaderError;
use tonic::Status;
use tracing_subscriber::util::SubscriberInitExt;

use crate::logging::{
    metrics_endpoint::{run_metrics_endpoint, MetricsEndpointConfig},
    setup::setup_telemetry,
};

pub mod api;
pub mod auth;
pub mod cfg;
pub mod credentials;
pub mod db;
mod dhcp;
pub mod ethernet_virtualization;
mod human_hash;
pub mod ib;
pub mod instance;
mod ip_finder;
pub mod ipmitool;
mod ipxe;
pub mod logging;
pub mod model;
pub mod redfish;
pub mod resource_pool;
pub mod setup;
pub mod state_controller;

/// Represents various Errors that can occur throughout the system.
///
/// CarbideError is a way to represent and enrich lower-level errors with specific business logic
/// that can be handled.
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

    #[error("Database type conversion error")]
    DatabaseTypeConversionError(String),

    #[error("Database migration error: {0}")]
    DatabaseMigrationError(#[from] sqlx::migrate::MigrateError),

    #[error("Multiple network segments defined for relay address: {0}")]
    MultipleNetworkSegmentsForRelay(IpAddr),

    #[error("No network segment defined for relay address: {0}")]
    NoNetworkSegmentsForRelay(IpAddr),

    #[error("Duplicate MAC address for network: {0}")]
    NetworkSegmentDuplicateMacAddress(MacAddress),

    #[error("Attempted to retrieve the next IP from a network segment exhausted of IP space: {0}")]
    NetworkSegmentsExhausted(String),

    #[error("Prefix overlaps with an existing one")]
    NetworkSegmentPrefixOverlap,

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
    IdentifierNotSpecifiedForObject,

    #[error("The Domain name {0} contains illegal characters")]
    InvalidDomainName(String),

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

    #[error("Error in libredfish: {0}")]
    RedfishError(#[from] libredfish::RedfishError),

    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] resource_pool::ResourcePoolError),

    #[error("Hardware info error: {0}")]
    HardwareInfoError(#[from] HardwareInfoError),

    #[error("Failed to call IBFabricManager: {0}")]
    IBFabricError(String),

    #[error("Failed to generate client certificate: {0}")]
    ClientCertificateError(String),

    #[error("Tenant handling error: {0}")]
    TenantError(#[from] TenantError),

    #[error("Machine is in maintenance mode. Cannot allocate instance on it.")]
    MaintenanceMode,

    #[error("Resource {0} is empty")]
    ResourceExhausted(String),

    #[error("DPU has unhealthy network")]
    UnhealthyNetwork,

    #[error("Lldp handling error: {0}")]
    LldpError(#[from] LldpError),
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
            CarbideError::InvalidArgument(msg) => Status::invalid_argument(msg),
            CarbideError::InvalidConfiguration(e) => Status::invalid_argument(e.to_string()),
            CarbideError::MissingArgument(msg) => Status::invalid_argument(*msg),
            CarbideError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
            CarbideError::NotFoundError { kind, id } => {
                Status::not_found(format!("missing {kind} {id}"))
            }
            CarbideError::MaintenanceMode => {
                Status::failed_precondition("MaintenanceMode".to_string())
            }
            CarbideError::UnhealthyNetwork => Status::unavailable("Machine network not ready"),
            CarbideError::ResourceExhausted(kind) => Status::resource_exhausted(kind),
            CarbideError::NetworkSegmentPrefixOverlap => Status::invalid_argument(from.to_string()),
            error @ CarbideError::ConcurrentModificationError(_, _) => {
                Status::failed_precondition(error.to_string())
            }
            other => Status::internal(other.to_string()),
        }
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

pub async fn run(
    debug: u8,
    config_str: String,
    site_config_str: Option<String>,
    logging_subscriber: Option<impl SubscriberInitExt>,
) -> eyre::Result<()> {
    let carbide_config = setup::parse_carbide_config(config_str, site_config_str)?;
    let (prometheus_registry, meter) =
        setup_telemetry(debug, carbide_config.clone(), logging_subscriber)
            .await
            .wrap_err("setup_telemetry")?;

    // Redact credentials before printing the config
    let print_config = {
        let mut config = carbide_config.as_ref().clone();
        if let Some(host_index) = config.database_url.find('@') {
            let host = config.database_url.split_at(host_index).1;
            config.database_url = format!("postgres://redacted{}", host);
        }
        if config.ib_fabric_manager_token.is_some() {
            config.ib_fabric_manager_token = Some("redacted".to_string());
        }
        config
    };
    tracing::info!("Using configuration: {:#?}", print_config);

    // Spin up the webserver which servers `/metrics` requests
    if let Some(metrics_address) = carbide_config.metrics_endpoint {
        tokio::spawn(async move {
            if let Err(e) = run_metrics_endpoint(&MetricsEndpointConfig {
                address: metrics_address,
                registry: prometheus_registry,
            })
            .await
            {
                tracing::error!("Metrics endpoint failed with error: {}", e);
            }
        });
    }

    let forge_vault_client = setup::create_vault_client(meter.clone()).await?;

    let ipmi_tool = setup::create_ipmi_tool(forge_vault_client.clone(), &carbide_config);

    tracing::info!(
        address = carbide_config.listen.to_string(),
        build_version = forge_version::v!(build_version),
        build_date = forge_version::v!(build_date),
        rust_version = forge_version::v!(rust_version),
        "Start carbide-api",
    );

    api::Api::start(
        carbide_config,
        forge_vault_client.clone(),
        forge_vault_client,
        meter,
        ipmi_tool,
    )
    .await
}
