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
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use config_version::{ConfigVersion, ConfigVersionParseError};
use dhcp::allocation::DhcpError;
use eyre::WrapErr;
use logging::level_filter::ActiveLevel;
use mac_address::MacAddress;
use model::{
    hardware_info::HardwareInfoError, machine::machine_id::MachineId, network_devices::LldpError,
    tenant::TenantError, ConfigValidationError, RpcDataConversionError,
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
pub mod db_init;
mod dhcp;
pub mod ethernet_virtualization;
mod human_hash;
pub mod ib;
pub mod ib_fabric_monitor;
pub mod instance;
mod ip_finder;
pub mod ipmitool;
mod ipxe;
mod listener;
pub mod logging;
pub mod machine_update_manager;
pub mod model;
pub mod redfish;
pub mod resource_pool;
pub mod setup;
pub mod site_explorer;
pub mod state_controller;
pub mod web;

/// How often to check if the log filter (RUST_LOG) needs resetting
const LOG_FILTER_RESET_PERIOD: Duration = Duration::from_secs(15 * 60); // 1/4 hour

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

    #[error("DPU reprovisioning is already started: {0}")]
    DpuReprovisioningInProgress(String),

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
            CarbideError::RpcDataConversionError(e) => Status::invalid_argument(e.to_string()),
            CarbideError::MissingArgument(msg) => Status::invalid_argument(*msg),
            CarbideError::NetworkSegmentDelete(msg) => Status::invalid_argument(msg),
            CarbideError::NotFoundError { kind, id } => {
                Status::not_found(format!("{kind} not found: {id}"))
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
    let tconf = setup_telemetry(debug, logging_subscriber)
        .await
        .wrap_err("setup_telemetry")?;

    // Redact credentials before printing the config
    let print_config = {
        let mut config = carbide_config.as_ref().clone();
        if let Some(host_index) = config.database_url.find('@') {
            let host = config.database_url.split_at(host_index).1;
            config.database_url = format!("postgres://redacted{}", host);
        }
        config
    };

    tracing::info!("Using configuration: {:#?}", print_config);
    tracing::info!(
        "Tokio worker thread count: {} (num_cpus::get()={}, TOKIO_WORKER_THREADS={})",
        tokio::runtime::Handle::current().metrics().num_workers(),
        num_cpus::get(),
        std::env::var("TOKIO_WORKER_THREADS").unwrap_or_else(|_| "UNSET".to_string())
    );

    // Spin up the webserver which servers `/metrics` requests
    if let Some(metrics_address) = carbide_config.metrics_endpoint {
        tokio::task::Builder::new()
            .name("metrics_endpoint")
            .spawn(async move {
                if let Err(e) = run_metrics_endpoint(&MetricsEndpointConfig {
                    address: metrics_address,
                    registry: tconf.registry,
                })
                .await
                {
                    tracing::error!("Metrics endpoint failed with error: {}", e);
                }
            })?;
    }

    start_log_filter_reset_task(tconf.filter.clone(), LOG_FILTER_RESET_PERIOD);

    let forge_vault_client = setup::create_vault_client(tconf.meter.clone()).await?;

    let ipmi_tool = setup::create_ipmi_tool(forge_vault_client.clone(), &carbide_config);

    tracing::info!(
        address = carbide_config.listen.to_string(),
        build_version = forge_version::v!(build_version),
        build_date = forge_version::v!(build_date),
        rust_version = forge_version::v!(rust_version),
        "Start carbide-api",
    );

    setup::start_api(
        carbide_config,
        forge_vault_client.clone(),
        forge_vault_client,
        tconf.meter,
        tconf.filter,
        ipmi_tool,
    )
    .await
}

/// The background task that resets RUST_LOG to startup value when the override expires
/// Overrides are applied in `set_log_filter` RPC.
pub fn start_log_filter_reset_task(log_filter: Arc<ArcSwap<ActiveLevel>>, period: Duration) {
    let _ = tokio::task::Builder::new()
        .name("log_filter_reset")
        .spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                let f = log_filter.load();
                if f.has_expired() {
                    match f.reset_from() {
                        Ok(next_level) => {
                            log_filter.store(Arc::new(next_level));
                        }
                        Err(err) => {
                            tracing::error!("Failed resetting log level: {err}");
                        }
                    }
                }
            }
        })
        .map_err(|err| {
            tracing::error!("log_filter_reset task aborted: {err}");
        });
}
