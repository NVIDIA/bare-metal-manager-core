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

//! Contains fixtures that use the Carbide API for setting up

use std::{
    cell::RefCell,
    collections::HashMap,
    default::Default,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};

use crate::tests::common::{
    api_fixtures::{
        dpu::create_dpu_machine,
        endpoint_explorer::MockEndpointExplorer,
        host::create_host_machine,
        managed_host::{ManagedHostConfig, ManagedHostSim},
    },
    test_certificates::TestCertificateProvider,
    test_meter::TestMeter,
};
use crate::{
    api::Api,
    cfg::file::{
        default_max_find_by_ids, CarbideConfig, Firmware, FirmwareComponent, FirmwareComponentType,
        FirmwareEntry, FirmwareGlobal, HostHealthConfig, IBFabricConfig, IbFabricMonitorConfig,
        IbPartitionStateControllerConfig, MachineStateControllerConfig,
        MeasuredBootMetricsCollectorConfig, MultiDpuConfig, NetworkSegmentStateControllerConfig,
        StateControllerConfig,
    },
    db::machine::Machine,
    ethernet_virtualization::{EthVirtData, SiteFabricPrefixList},
    ib::{self, IBFabricManager, IBFabricManagerType},
    ipmitool::IPMIToolTestImpl,
    logging::level_filter::ActiveLevel,
    model::machine::{
        machine_id::try_parse_machine_id, FailureDetails, MachineLastRebootRequested,
        ManagedHostState,
    },
    redfish::RedfishSim,
    resource_pool::{self, common::CommonPools},
    site_explorer::SiteExplorer,
    state_controller::{
        controller::StateController,
        ib_partition::{handler::IBPartitionStateHandler, io::IBPartitionStateControllerIO},
        machine::{
            handler::{MachineStateHandler, ReachabilityParams},
            io::MachineStateControllerIO,
        },
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
        state_handler::{StateHandler, StateHandlerServices},
    },
};
use crate::{
    cfg::file::{HardwareHealthReportsConfig, MachineValidationConfig, SiteExplorerConfig},
    site_explorer::BmcEndpointExplorer,
    state_controller::machine::handler::MachineStateHandlerBuilder,
};
use crate::{
    state_controller::state_handler::{
        StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    },
    storage::{NvmeshClientPool, NvmeshSimClient},
};
use arc_swap::{ArcSwap, ArcSwapAny};
use chrono::{DateTime, Duration, Utc};
use forge_secrets::credentials::{
    CredentialKey, CredentialProvider, CredentialType, Credentials, TestCredentialProvider,
};
use forge_uuid::machine::MachineId;
use health_report::{HealthReport, OverrideMode};
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use measured_boot::pcr::PcrRegisterValue;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use regex::Regex;
use rpc::forge::{
    forge_server::Forge, HealthReportOverride, InsertHealthReportOverrideRequest,
    RemoveHealthReportOverrideRequest,
};
use sqlx::{postgres::PgConnectOptions, PgPool};
use tokio::sync::Mutex;
use tonic::Request;
use tracing_subscriber::EnvFilter;

pub mod dpu;
pub mod endpoint_explorer;
pub mod host;
pub mod ib_partition;
pub mod instance;
pub mod managed_host;
pub mod network_segment;
pub mod site_explorer;
pub mod tenant;
pub mod tpm_attestation;
pub mod vpc;

/// The datacenter-level DHCP relay that is assumed for all DPU discovery
///
/// For integration testing this must match a prefix defined in fixtures/create_network_segment.sql
/// In production the relay IP is a MetalLB VIP so isn't in a network segment.
pub const FIXTURE_DHCP_RELAY_ADDRESS: &str = "192.0.2.1";

pub const FIXTURE_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");
pub const FIXTURE_VPC_ID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");

// The site fabric prefixes list that the tests run with. Double check against
// the test logic before changing it, as at least one test relies on this list
// _excluding_ certain address space.
lazy_static! {
    pub static ref TEST_SITE_PREFIXES: Vec<IpNetwork> =
        vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap()];
}

#[derive(Clone, Debug, Default)]
pub struct TestEnvOverrides {
    pub allow_zero_dpu_hosts: Option<bool>,
    pub site_prefixes: Option<Vec<IpNetwork>>,
    pub config: Option<CarbideConfig>,
}

impl TestEnvOverrides {
    pub fn with_config(config: CarbideConfig) -> Self {
        Self {
            config: Some(config),
            ..Default::default()
        }
    }
}

pub struct TestEnv {
    pub api: Arc<Api>,
    pub config: Arc<CarbideConfig>,
    pub common_pools: Arc<CommonPools>,
    pub pool: PgPool,
    pub redfish_sim: Arc<RedfishSim>,
    pub nvmesh_sim: Arc<dyn NvmeshClientPool>,
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,
    pub ipmi_tool: Arc<IPMIToolTestImpl>,
    machine_state_controller: RefCell<StateController<MachineStateControllerIO>>,
    pub machine_state_handler: SwapHandler<MachineStateHandler>,
    network_segment_controller: RefCell<StateController<NetworkSegmentStateControllerIO>>,
    ib_partition_controller: RefCell<StateController<IBPartitionStateControllerIO>>,
    pub reachability_params: ReachabilityParams,
    pub test_meter: TestMeter,
    pub attestation_enabled: bool,
    pub site_explorer: SiteExplorer,
    pub endpoint_explorer: MockEndpointExplorer,
}

impl TestEnv {
    /// Creates an instance of StateHandlerServices that are suitable for this
    /// test environment
    pub fn state_handler_services(&self) -> StateHandlerServices {
        StateHandlerServices {
            pool: self.pool.clone(),
            redfish_client_pool: self.redfish_sim.clone(),
            nvmesh_client_pool: self.nvmesh_sim.clone(),
            ib_fabric_manager: self.ib_fabric_manager.clone(),
            meter: Some(self.test_meter.meter()),
            ib_pools: self.common_pools.infiniband.clone(),
            ipmi_tool: self.ipmi_tool.clone(),
            site_config: self.config.clone(),
        }
    }

    /// Generates a simulation for Host+DPU pair
    pub fn start_managed_host_sim(&self) -> ManagedHostSim {
        self.start_managed_host_sim_with_config(ManagedHostConfig::default())
    }

    pub fn start_managed_host_sim_with_config(&self, config: ManagedHostConfig) -> ManagedHostSim {
        // TODO: This will in the future also spin up redfish mocks for these components
        ManagedHostSim { config }
    }

    fn fill_machine_information(
        &self,
        state: &ManagedHostState,
        machine: &Machine,
    ) -> ManagedHostState {
        //This block is to fill data that is populated within statemachine
        match state.clone() {
            ManagedHostState::DpuDiscoveringState { .. } => state.clone(),
            ManagedHostState::DPUInit { .. } => state.clone(),
            ManagedHostState::HostInit { machine_state } => {
                let mc = match machine_state {
                    crate::model::machine::MachineState::Init => machine_state,
                    crate::model::machine::MachineState::WaitingForPlatformConfiguration => {
                        machine_state
                    }
                    crate::model::machine::MachineState::UefiSetup { .. } => machine_state,
                    crate::model::machine::MachineState::WaitingForDiscovery => machine_state,
                    crate::model::machine::MachineState::Discovered { .. } => machine_state,
                    crate::model::machine::MachineState::WaitingForLockdown { .. } => machine_state,
                    crate::model::machine::MachineState::Measuring { .. } => machine_state,
                    crate::model::machine::MachineState::MachineValidating {
                        context,
                        id: _,
                        completed,
                        total,
                        is_enabled,
                    } => {
                        let mut id = machine
                            .discovery_machine_validation_id()
                            .unwrap_or_default();
                        if context == "Cleanup" {
                            id = machine.cleanup_machine_validation_id().unwrap_or_default();
                        } else if context == "OnDemand" {
                            id = machine
                                .on_demand_machine_validation_id()
                                .unwrap_or_default();
                        }
                        crate::model::machine::MachineState::MachineValidating {
                            context,
                            id,
                            completed,
                            total,
                            is_enabled,
                        }
                    }
                    crate::model::machine::MachineState::EnableIpmiOverLan => machine_state,
                };
                ManagedHostState::HostInit { machine_state: mc }
            }
            ManagedHostState::Ready => state.clone(),
            ManagedHostState::Assigned { .. } => state.clone(),
            ManagedHostState::WaitingForCleanup { .. } => state.clone(),
            ManagedHostState::Created => state.clone(),
            ManagedHostState::ForceDeletion => state.clone(),
            ManagedHostState::Failed {
                details,
                machine_id,
                retry_count,
            } => ManagedHostState::Failed {
                details: FailureDetails {
                    cause: details.cause,
                    failed_at: machine.failure_details().failed_at,
                    source: details.source,
                },
                machine_id,
                retry_count,
            },
            ManagedHostState::DPUReprovision { .. } => state.clone(),
            ManagedHostState::Measuring { .. } => state.clone(),
            ManagedHostState::PostAssignedMeasuring { .. } => state.clone(),
            ManagedHostState::HostReprovision { .. } => state.clone(),
        }
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn run_machine_state_controller_iteration_until_state_matches(
        &self,
        host_machine_id: &MachineId,
        max_iterations: u32,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        expected_state: ManagedHostState,
    ) {
        for _ in 0..max_iterations {
            self.machine_state_controller
                .borrow_mut()
                .run_single_iteration()
                .await;

            let machine = Machine::find_one(
                txn,
                host_machine_id,
                crate::db::machine::MachineSearchConfig::default(),
            )
            .await
            .unwrap()
            .unwrap();

            let comparable_state = self.fill_machine_information(&expected_state, &machine);

            if machine.current_state() == comparable_state {
                return;
            }
        }

        let machine = Machine::find_one(
            txn,
            host_machine_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();

        panic!(
            "Expected Machine state to be {:?} after {max_iterations} iterations, but state is {:?}",
            expected_state.clone(),
            machine.current_state()
        );
    }

    /// Runs one iteration of the machine state controller handler
    //// with the services in this test environment
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn run_machine_state_controller_iteration(&self) {
        self.machine_state_controller
            .borrow_mut()
            .run_single_iteration()
            .await;
    }

    /// Runs one iteration of the network state controller handler with the services
    /// in this test environment
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn run_network_segment_controller_iteration(&self) {
        self.network_segment_controller
            .borrow_mut()
            .run_single_iteration()
            .await;
    }

    /// Runs one iteration of the IB partition state controller handler with the services
    /// in this test environment
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn run_ib_partition_controller_iteration(&self) {
        self.ib_partition_controller
            .borrow_mut()
            .run_single_iteration()
            .await;
    }

    pub async fn run_site_explorer_iteration(&self) {
        self.site_explorer.run_single_iteration().await.unwrap()
    }

    pub async fn override_machine_state_controller_handler(&self, handler: MachineStateHandler) {
        *self.machine_state_handler.inner.lock().await = handler;
    }

    // Returns all machines using FindMachines call.
    pub async fn find_machines(
        &self,
        id: Option<rpc::common::MachineId>,
        fqdn: Option<String>,
        include_dpus: bool,
    ) -> rpc::forge::MachineList {
        self.api
            .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
                search_config: Some(rpc::forge::MachineSearchConfig {
                    include_dpus,
                    include_history: true,
                    ..Default::default()
                }),
                id,
                fqdn,
            }))
            .await
            .unwrap()
            .into_inner()
    }

    // Returns all instances using FindInstances call.
    pub async fn find_instances(&self, id: Option<rpc::common::Uuid>) -> rpc::forge::InstanceList {
        self.api
            .find_instances(tonic::Request::new(rpc::forge::InstanceSearchQuery {
                id,
                label: None,
            }))
            .await
            .unwrap()
            .into_inner()
    }
}

fn dpu_fw_example() -> Firmware {
    Firmware {
        vendor: bmc_vendor::BMCVendor::Nvidia,
        model: "Bluefield 3 SmartNIC Main Card".to_string(),
        components: HashMap::from([(
            FirmwareComponentType::Bmc,
            FirmwareComponent {
                current_version_reported_as: Some(Regex::new(".*").unwrap()),
                preingest_upgrade_when_below: Some("BF-23.10".to_string()),
                known_firmware: vec![FirmwareEntry {
                    version: "BF-23.10".to_string(),
                    default: true,
                    filename: Some("/dev/null".to_string()),
                    url: Some("file://dev/null".to_string()),
                    checksum: None,
                    mandatory_upgrade_from_priority: None,
                    install_only_specified: false,
                }],
            },
        )]),
        ordering: vec![FirmwareComponentType::Bmc, FirmwareComponentType::Cec],
    }
}

fn host_firmware_example() -> Firmware {
    Firmware {
        vendor: bmc_vendor::BMCVendor::Dell,
        model: "PowerEdge R750".to_string(),
        components: HashMap::from([
            (
                FirmwareComponentType::Bmc,
                FirmwareComponent {
                    current_version_reported_as: Some(Regex::new("^Installed-.*__iDRAC.").unwrap()),
                    preingest_upgrade_when_below: Some("5".to_string()),
                    known_firmware: vec![
                        FirmwareEntry {
                            version: "6.1".to_string(),
                            default: false,
                            filename: Some("/dev/null".to_string()),
                            url: Some("file://dev/null".to_string()),
                            checksum: None,
                            mandatory_upgrade_from_priority: None,
                            install_only_specified: false,
                        },
                        FirmwareEntry {
                            version: "6.00.30.00".to_string(),
                            default: true,
                            filename: Some("/dev/null".to_string()),
                            url: Some("file://dev/null".to_string()),
                            checksum: None,
                            mandatory_upgrade_from_priority: None,
                            install_only_specified: false,
                        },
                        FirmwareEntry {
                            version: "5".to_string(),
                            default: false,
                            filename: Some("/dev/null".to_string()),
                            url: Some("file://dev/null".to_string()),
                            checksum: None,
                            mandatory_upgrade_from_priority: None,
                            install_only_specified: false,
                        },
                    ],
                },
            ),
            (
                FirmwareComponentType::Uefi,
                FirmwareComponent {
                    current_version_reported_as: Some(
                        Regex::new("^Current-.*__BIOS.Setup.").unwrap(),
                    ),
                    preingest_upgrade_when_below: Some("1.13.2".to_string()),
                    known_firmware: vec![FirmwareEntry {
                        version: "1.13.2".to_string(),
                        default: true,
                        filename: Some("/dev/null".to_string()),
                        url: Some("file://dev/null".to_string()),
                        checksum: None,
                        mandatory_upgrade_from_priority: None,
                        install_only_specified: false,
                    }],
                },
            ),
        ]),
        ordering: vec![FirmwareComponentType::Uefi, FirmwareComponentType::Bmc],
    }
}

pub fn get_config() -> CarbideConfig {
    CarbideConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1079),
        metrics_endpoint: None,
        database_url: "pgsql:://localhost".to_string(),
        max_database_connections: 1000,
        asn: 0,
        dhcp_servers: vec![],
        route_servers: vec![],
        enable_route_servers: false,
        deny_prefixes: vec![],
        site_fabric_prefixes: vec![],
        tls: Some(crate::cfg::file::TlsConfig {
            root_cafile_path: "Not a real path".to_string(),
            identity_pemfile_path: "Not a real pemfile".to_string(),
            identity_keyfile_path: "Not a real keyfile".to_string(),
            admin_root_cafile_path: "Not a real cafile".to_string(),
        }),
        auth: None,
        pools: None,
        networks: None,
        dpu_ipmi_tool_impl: None,
        dpu_ipmi_reboot_attempts: Some(0),
        initial_domain_name: Some("test.com".to_string()),
        initial_dpu_agent_upgrade_policy: None,
        dpu_nic_firmware_update_version: None,
        dpu_nic_firmware_initial_update_enabled: true,
        dpu_nic_firmware_reprovision_update_enabled: true,
        max_concurrent_machine_updates: Some(10),
        machine_update_run_interval: Some(1),
        site_explorer: SiteExplorerConfig {
            enabled: false,
            run_interval: std::time::Duration::from_secs(0),
            concurrent_explorations: 0,
            explorations_per_run: 0,
            create_machines: Arc::new(ArcSwap::new(Arc::new(false))),
            ..Default::default()
        },
        dpu_dhcp_server_enabled: false,
        nvue_enabled: true,
        attestation_enabled: false,
        ib_config: None,
        ib_fabrics: HashMap::new(),
        machine_state_controller: MachineStateControllerConfig {
            dpu_wait_time: Duration::seconds(1),
            power_down_wait: Duration::seconds(1),
            failure_retry_time: Duration::seconds(1),
            dpu_up_threshold: Duration::weeks(52),
            controller: StateControllerConfig::default(),
        },
        network_segment_state_controller: NetworkSegmentStateControllerConfig {
            network_segment_drain_time: Duration::seconds(2),
            controller: StateControllerConfig::default(),
        },
        ib_partition_state_controller: IbPartitionStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        ib_fabric_monitor: IbFabricMonitorConfig {
            enabled: true,
            run_interval: std::time::Duration::from_secs(10),
        },
        dpu_models: HashMap::from([("bluefield3".to_string(), dpu_fw_example())]),
        host_models: HashMap::from([("1".to_string(), host_firmware_example())]),
        firmware_global: FirmwareGlobal::test_default(),
        max_find_by_ids: default_max_find_by_ids(),
        min_dpu_functioning_links: None,
        multi_dpu: MultiDpuConfig::default(),
        dpu_network_monitor_pinger_type: None,
        host_health: HostHealthConfig::default(),
        internet_l3_vni: Some(1337),
        measured_boot_collector: MeasuredBootMetricsCollectorConfig {
            enabled: true,
            run_interval: std::time::Duration::from_secs(10),
        },
        machine_validation_config: MachineValidationConfig { enabled: true },
        bypass_rbac: false,
    }
}

/// crate::sqlx_test shares the pool with all testcases in a file. If there are many testcases in a file,
/// test cases will start getting PoolTimedOut error. To avoid it, each test case will be assigned
/// its own pool.
async fn create_pool(current_pool: sqlx::PgPool) -> sqlx::PgPool {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set.");
    let db_options = current_pool.connect_options();
    let db: &str = db_options
        .get_database()
        .expect("No database is set initially.");

    let db_url = format!("{}/{}", db_url, db);

    use sqlx::ConnectOptions;
    let connect_options = PgConnectOptions::from_str(&db_url)
        .unwrap()
        .log_statements("INFO".parse().unwrap());

    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect_with(connect_options)
        .await
        .expect("Pool creation failed.")
}

/// Creates an environment for unit-testing
///
/// This retuns the `Api` object instance which can be used to simulate calls against
/// the Forge site controller, as well as mocks for dependent services that
/// can be inspected and passed to other systems.
pub async fn create_test_env(db_pool: sqlx::PgPool) -> TestEnv {
    create_test_env_with_overrides(db_pool, Default::default()).await
}

pub async fn create_test_env_with_overrides(
    db_pool: sqlx::PgPool,
    overrides: TestEnvOverrides,
) -> TestEnv {
    let db_pool = create_pool(db_pool).await;
    let test_meter = TestMeter::default();
    let credential_provider = Arc::new(TestCredentialProvider::default());
    populate_default_credentials(credential_provider.as_ref()).await;
    let certificate_provider = Arc::new(TestCertificateProvider::new());
    let redfish_sim = Arc::new(RedfishSim::default());
    let nvmesh_sim: Arc<dyn NvmeshClientPool> = Arc::new(NvmeshSimClient::default());
    let config = Arc::new(overrides.config.unwrap_or(get_config()));

    let ib_config = config.ib_config.clone().unwrap_or_default();
    let ib_fabric_manager_impl = ib::create_ib_fabric_manager(
        credential_provider.clone(),
        ib::IBFabricManagerConfig {
            // The actual IP is not used and thereby does not matter
            endpoints: [(
                "default".to_string(),
                vec!["https://127.0.0.1:443".to_string()],
            )]
            .into_iter()
            .collect(),
            manager_type: IBFabricManagerType::Mock,
            max_partition_per_tenant: IBFabricConfig::default_max_partition_per_tenant(),
            mtu: ib_config.mtu,
            rate_limit: ib_config.rate_limit,
            service_level: ib_config.service_level,
        },
    )
    .unwrap();

    let ib_fabric_manager: Arc<dyn IBFabricManager> = Arc::new(ib_fabric_manager_impl);

    let site_fabric_prefixes = {
        let prefixes: Vec<IpNetwork> = overrides
            .site_prefixes
            .as_ref()
            .unwrap_or(&TEST_SITE_PREFIXES)
            .to_vec();
        SiteFabricPrefixList::from_ipnetwork_vec(prefixes)
    };

    let eth_virt_data = EthVirtData {
        asn: 65535,
        dhcp_servers: vec![FIXTURE_DHCP_RELAY_ADDRESS.to_string()],
        route_servers: vec![],
        route_servers_enabled: true,
        deny_prefixes: vec![],
        site_fabric_prefixes,
    };

    // Populate resource pools
    let mut txn = db_pool.begin().await.unwrap();
    resource_pool::define_all_from(&mut txn, &pool_defs())
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let common_pools = CommonPools::create(db_pool.clone(), ["default".to_string()].into())
        .await
        .expect("Creating pools should work");

    let dyn_settings = crate::dynamic_settings::DynamicSettings {
        log_filter: Arc::new(ArcSwap::from(Arc::new(ActiveLevel::new(
            EnvFilter::builder()
                .parse(std::env::var("RUST_LOG").unwrap_or("trace".to_string()))
                .unwrap(),
        )))),
        create_machines: config.site_explorer.create_machines.clone(),
        bmc_proxy: config.site_explorer.bmc_proxy.clone(),
    };

    let ipmi_tool = Arc::new(IPMIToolTestImpl {});

    let bmc_explorer = Arc::new(BmcEndpointExplorer::new(
        redfish_sim.clone(),
        ipmi_tool.clone(),
        credential_provider.clone(),
    ));

    let reachability_params = ReachabilityParams {
        dpu_wait_time: Duration::seconds(0),
        power_down_wait: Duration::seconds(0),
        failure_retry_time: Duration::seconds(0),
    };

    let api = Arc::new(Api::new(
        config.clone(),
        credential_provider.clone(),
        certificate_provider.clone(),
        db_pool.clone(),
        redfish_sim.clone(),
        nvmesh_sim.clone(),
        eth_virt_data.clone(),
        common_pools.clone(),
        ib_fabric_manager.clone(),
        dyn_settings,
        bmc_explorer,
    ));

    let attestation_enabled = config.attestation_enabled;
    let ipmi_tool = Arc::new(IPMIToolTestImpl {});

    let machine_swap = SwapHandler {
        inner: Arc::new(Mutex::new(
            MachineStateHandlerBuilder::builder()
                .hardware_models(config.get_firmware_config())
                .reachability_params(reachability_params)
                .attestation_enabled(attestation_enabled)
                .common_pools(common_pools.clone())
                .machine_validation_config(MachineValidationConfig {
                    enabled: config.machine_validation_config.enabled,
                })
                .build(),
        )),
    };

    let machine_controller = StateController::<MachineStateControllerIO>::builder()
        .database(db_pool.clone())
        .meter("forge_machines", test_meter.meter())
        .redfish_client_pool(redfish_sim.clone())
        .nvmesh_client_pool(nvmesh_sim.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .ib_pools(common_pools.infiniband.clone())
        .forge_api(api.clone())
        .ipmi_tool(ipmi_tool.clone())
        .site_config(config.clone())
        .state_handler(Arc::new(machine_swap.clone()))
        .io(Arc::new(MachineStateControllerIO {
            hardware_health: HardwareHealthReportsConfig::Enabled,
        }))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let ib_swap = SwapHandler {
        inner: Arc::new(Mutex::new(IBPartitionStateHandler::default())),
    };

    let ib_controller = StateController::builder()
        .database(db_pool.clone())
        .meter("forge_machines", test_meter.meter())
        .redfish_client_pool(redfish_sim.clone())
        .nvmesh_client_pool(nvmesh_sim.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .ib_pools(common_pools.infiniband.clone())
        .forge_api(api.clone())
        .ipmi_tool(ipmi_tool.clone())
        .site_config(config.clone())
        .state_handler(Arc::new(ib_swap.clone()))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let network_swap = SwapHandler {
        inner: Arc::new(Mutex::new(NetworkSegmentStateHandler::new(
            chrono::Duration::milliseconds(500),
            common_pools.ethernet.pool_vlan_id.clone(),
            common_pools.ethernet.pool_vni.clone(),
        ))),
    };

    let network_controller = StateController::builder()
        .database(db_pool.clone())
        .meter("forge_machines", test_meter.meter())
        .redfish_client_pool(redfish_sim.clone())
        .nvmesh_client_pool(nvmesh_sim.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .forge_api(api.clone())
        .ipmi_tool(ipmi_tool.clone())
        .site_config(config.clone())
        .state_handler(Arc::new(network_swap.clone()))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let fake_endpoint_explorer = MockEndpointExplorer {
        reports: Arc::new(std::sync::Mutex::new(Default::default())),
    };

    // The API server is launched with a disabled site-explorer config so that it doesn't launch one
    // on its own. TestEnv's site_explorer is a separate instance talking to the same database that
    // *is* enabled, so it gets a different config. The purpose is so that tests can manually run
    // site explorer iterations to seed data/etc.
    let site_explorer = SiteExplorer::new(
        db_pool.clone(),
        SiteExplorerConfig {
            enabled: true,
            // run_interval shouldn't matter, this should not be run(), we only trigger intervals manually.
            run_interval: Duration::seconds(0).to_std().unwrap(),
            concurrent_explorations: 100,
            explorations_per_run: 100,
            create_machines: Arc::new(ArcSwapAny::new(Arc::new(true))),
            machines_created_per_run: 1,
            override_target_ip: None,
            override_target_port: None,
            allow_zero_dpu_hosts: overrides.allow_zero_dpu_hosts.unwrap_or(false),
            bmc_proxy: Arc::new(Default::default()),
            allow_changing_bmc_proxy: None,
            reset_rate_limit: Duration::hours(1),
        },
        test_meter.meter(),
        Arc::new(fake_endpoint_explorer.clone()),
        Arc::new(config.get_firmware_config()),
        common_pools.clone(),
    );

    TestEnv {
        api,
        common_pools,
        config,
        pool: db_pool,
        redfish_sim,
        nvmesh_sim,
        ib_fabric_manager,
        ipmi_tool,
        machine_state_controller: RefCell::new(machine_controller),
        machine_state_handler: machine_swap,
        ib_partition_controller: RefCell::new(ib_controller),
        network_segment_controller: RefCell::new(network_controller),
        reachability_params,
        attestation_enabled,
        test_meter,
        site_explorer,
        endpoint_explorer: fake_endpoint_explorer,
    }
}

async fn populate_default_credentials(credential_provider: &dyn CredentialProvider) {
    credential_provider
        .set_credentials(
            CredentialKey::DpuRedfish {
                credential_type: CredentialType::DpuHardwareDefault,
            },
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "dpuredfish_dpuhardwaredefault".to_string(),
            },
        )
        .await
        .unwrap();
    credential_provider
        .set_credentials(
            CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "dpuredfish_sitedefault".to_string(),
            },
        )
        .await
        .unwrap();
    credential_provider
        .set_credentials(
            CredentialKey::HostRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "hostredfish_sitedefault".to_string(),
            },
        )
        .await
        .unwrap();
}

fn pool_defs() -> HashMap<String, resource_pool::ResourcePoolDef> {
    let mut defs = HashMap::new();
    defs.insert(
        "ib_fabrics.default.pkey".to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: "1".to_string(),
                end: "100".to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        resource_pool::common::LOOPBACK_IP.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Ipv4,
            // Must match a network_prefix in fixtures/create_network_segment.sql
            prefix: Some("172.20.0.0/24".to_string()),
            ranges: vec![],
        },
    );
    defs.insert(
        resource_pool::common::VNI.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: "10001".to_string(),
                end: "10005".to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        resource_pool::common::VLANID.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: "1".to_string(),
                end: "5".to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        resource_pool::common::VPC_VNI.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: "20001".to_string(),
                end: "20005".to_string(),
            }],
            prefix: None,
        },
    );
    defs
}

/// Emulates the `UpdateBmcMetaData` request of a DPU/Host
/// TODO: This request does not happen anymore in the site-explorer world
/// The method should be removed once tests are converted to site explorer
pub async fn update_bmc_metadata(
    env: &TestEnv,
    machine_id: rpc::common::MachineId,
    bmc_ip_address: &str,
    admin_user: String,
    bmc_mac_address: MacAddress,
    bmc_version: String,
    bmc_firmware_version: String,
) {
    let bmc_info = rpc::forge::BmcInfo {
        ip: Some(bmc_ip_address.to_owned()),
        port: None,
        mac: Some(bmc_mac_address.to_string()),
        version: Some(bmc_version),
        firmware_version: Some(bmc_firmware_version),
    };

    let _response = env
        .api
        .update_bmc_meta_data(Request::new(rpc::forge::BmcMetaDataUpdateRequest {
            machine_id: Some(machine_id),
            data: vec![rpc::forge::bmc_meta_data_update_request::DataItem {
                user: admin_user,
                password: "notforprod".to_string(),
                role: rpc::forge::UserRoles::Administrator as i32,
            }],
            request_type: rpc::forge::BmcRequestType::Redfish as i32,
            bmc_info: Some(bmc_info),
        }))
        .await
        .unwrap()
        .into_inner();
}

/// Emulates the `DiscoveryCompleted` request of a DPU/Host
pub async fn discovery_completed(env: &TestEnv, machine_id: rpc::common::MachineId) {
    let _response = env
        .api
        .discovery_completed(Request::new(rpc::forge::MachineDiscoveryCompletedRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
}

/// Fake an iteration of forge-dpu-agent requesting network config, applying it, and reporting back
/// Returns tuple of latest (machine_config_version, instance_network_config_version)
pub async fn network_configured(env: &TestEnv, dpu_machine_id: &MachineId) {
    network_configured_with_health(env, dpu_machine_id, None).await
}

/// Fake an iteration of forge-dpu-agent requesting network config, applying it, and reporting back.
/// When reporting back, the health reported by the DPU can be overrridden
pub async fn network_configured_with_health(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    dpu_health: Option<rpc::health::HealthReport>,
) {
    let network_config = env
        .api
        .get_managed_host_network_config(Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let instance_network_config_version =
        if network_config.instance_network_config_version.is_empty() {
            None
        } else {
            Some(network_config.instance_network_config_version.clone())
        };
    let instance: Option<rpc::Instance> = env
        .api
        .find_instance_by_machine_id(Request::new(dpu_machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop();
    let instance_config_version = if let Some(instance) = instance {
        // If an instance is reported via this API, the version should match what we
        // get via the GetManagedHostNetworkConfig API
        if !network_config.use_admin_network {
            assert_eq!(
                instance_network_config_version.as_ref().unwrap().as_str(),
                instance.network_config_version,
                "Different network config versions reported via FindInstanceByMachineId and GetManagedHostNetworkConfig"
            );
        }
        Some(instance.config_version.clone())
    } else {
        None
    };

    let interfaces = if network_config.use_admin_network {
        let iface = network_config
            .admin_interface
            .as_ref()
            .expect("use_admin_network true so admin_interface should be Some");
        vec![rpc::forge::InstanceInterfaceStatusObservation {
            function_type: iface.function_type,
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![iface.ip.clone()],
            prefixes: vec![iface.interface_prefix.clone()],
            gateways: vec![iface.gateway.clone()],
        }]
    } else {
        let mut interfaces = vec![];
        for iface in network_config.tenant_interfaces.iter() {
            interfaces.push(rpc::forge::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: iface.virtual_function_id,
                mac_address: None,
                addresses: vec![iface.ip.clone()],
                prefixes: vec![iface.interface_prefix.clone()],
                gateways: vec![iface.gateway.clone()],
            });
        }
        interfaces
    };

    let dpu_health = dpu_health.unwrap_or_else(|| rpc::health::HealthReport {
        source: "forge-dpu-agent".to_string(),
        observed_at: None,
        successes: vec![],
        alerts: vec![],
    });

    let status = rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(dpu_machine_id.to_string().into()),
        dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
        observed_at: Some(SystemTime::now().into()),
        dpu_health: Some(dpu_health),
        network_config_version: Some(network_config.managed_host_config_version.clone()),
        instance_id: network_config.instance_id.clone(),
        instance_config_version: instance_config_version.clone(),
        instance_network_config_version: instance_network_config_version.clone(),
        interfaces,
        network_config_error: None,
        client_certificate_expiry_unix_epoch_secs: None,
        fabric_interfaces: vec![],
        last_dhcp_requests: vec![],
    };
    tracing::trace!(
        "network_configured machine={} instance_network={} instance={}",
        status.network_config_version.as_ref().unwrap(),
        instance_network_config_version.clone().unwrap_or_default(),
        instance_config_version.clone().unwrap_or_default(),
    );
    let _ = env
        .api
        .record_dpu_network_status(Request::new(status))
        .await
        .unwrap();
}

/// Fake hardware health service reporting health
pub async fn simulate_hardware_health_report(
    env: &TestEnv,
    host_machine_id: &MachineId,
    health_report: health_report::HealthReport,
) {
    use rpc::forge::{forge_server::Forge, HardwareHealthReport};
    use tonic::Request;
    let _ = env
        .api
        .record_hardware_health_report(Request::new(HardwareHealthReport {
            machine_id: Some(host_machine_id.to_string().into()),
            report: Some(health_report.into()),
        }))
        .await
        .unwrap();
}

/// Send a health report override
pub async fn send_health_report_override(
    env: &TestEnv,
    machine_id: &MachineId,
    r#override: (HealthReport, OverrideMode),
) {
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .insert_health_report_override(Request::new(InsertHealthReportOverrideRequest {
            machine_id: Some(machine_id.to_string().into()),
            r#override: Some(HealthReportOverride {
                report: Some(r#override.0.into()),
                mode: r#override.1 as i32,
            }),
        }))
        .await
        .unwrap();
}

/// Remove a health report override
pub async fn remove_health_report_override(env: &TestEnv, machine_id: &MachineId, source: String) {
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .remove_health_report_override(Request::new(RemoveHealthReportOverrideRequest {
            machine_id: Some(machine_id.to_string().into()),
            source,
        }))
        .await
        .unwrap();
}

pub async fn forge_agent_control(
    env: &TestEnv,
    machine_id: rpc::common::MachineId,
) -> rpc::forge::ForgeAgentControlResponse {
    let _ = reboot_completed(env, machine_id.clone()).await;

    env.api
        .forge_agent_control(Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner()
}

pub async fn create_managed_host(env: &TestEnv) -> (MachineId, MachineId) {
    create_managed_host_with_config(env, ManagedHostConfig::default()).await
}

pub async fn create_managed_host_with_config(
    env: &TestEnv,
    config: ManagedHostConfig,
) -> (MachineId, MachineId) {
    // TODO: Return host_sim
    let host_sim = env.start_managed_host_sim_with_config(config);
    let dpu_machine_id = create_dpu_machine(env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let host_machine_id = create_host_machine(env, &host_sim.config, &dpu_machine_id).await;

    (
        try_parse_machine_id(&host_machine_id).unwrap(),
        dpu_machine_id,
    )
}

pub async fn update_time_params(
    pool: &sqlx::PgPool,
    machine: &Machine,
    retry_count: i64,
    last_reboot_requested: Option<DateTime<Utc>>,
) {
    let mut txn = pool.begin().await.unwrap();
    let data = MachineLastRebootRequested {
        time: if let Some(last_reboot_requested) = last_reboot_requested {
            last_reboot_requested
        } else {
            machine.last_reboot_requested().unwrap().time - Duration::minutes(1)
        },
        mode: machine.last_reboot_requested().unwrap().mode,
    };

    let last_reboot_time = machine.last_reboot_time().unwrap() - Duration::minutes(2i64);

    let ts = machine.last_reboot_requested().unwrap().time - Duration::minutes(retry_count);
    let last_discovery_time = ts - Duration::minutes(1);

    let version = format!(
        "V{}-T{}",
        machine.current_version().version_nr(),
        ts.timestamp_micros()
    );

    let query = "UPDATE machines SET last_reboot_requested=$1, controller_state_version=$3, last_reboot_time=$4, last_discovery_time=$5 WHERE id=$2 RETURNING *";
    sqlx::query(query)
        .bind(sqlx::types::Json(&data))
        .bind(machine.id().to_string())
        .bind(version)
        .bind(last_reboot_time)
        .bind(last_discovery_time)
        .execute(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

pub async fn reboot_completed(
    env: &TestEnv,
    machine_id: rpc::common::MachineId,
) -> rpc::forge::MachineRebootCompletedResponse {
    tracing::info!("Machine ={} rebooted", machine_id);
    env.api
        .reboot_completed(Request::new(rpc::forge::MachineRebootCompletedRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner()
}

// Emulates the `MachineValidationComplete` request of a Host
pub async fn machine_validation_completed(
    env: &TestEnv,
    machine_id: rpc::common::MachineId,
    machine_validation_error: Option<String>,
) {
    let response = forge_agent_control(env, machine_id.clone()).await;
    let uuid = &response.data.unwrap().pair[1].value;

    let _response = env
        .api
        .machine_validation_completed(Request::new(
            rpc::forge::MachineValidationCompletedRequest {
                machine_id: Some(machine_id),
                machine_validation_error,
                validation_id: Some(rpc::Uuid {
                    value: uuid.to_owned(),
                }),
            },
        ))
        .await
        .unwrap()
        .into_inner();
}

/// inject_machine_measurements injects auto-approved measurements
/// for a machine. This also will create a new profile and bundle,
/// if needed, as part of the auto-approval process.
pub async fn inject_machine_measurements(env: &TestEnv, machine_id: rpc::common::MachineId) {
    let _response = env
        .api
        .add_measurement_trusted_machine(Request::new(
            rpc::protos::measured_boot::AddMeasurementTrustedMachineRequest {
                machine_id: machine_id.to_string(),
                approval_type: rpc::protos::measured_boot::MeasurementApprovedTypePb::Oneshot
                    as i32,
                pcr_registers: "0-1".to_string(),
                comments: "".to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let pcr_values: Vec<PcrRegisterValue> = vec![
        PcrRegisterValue {
            pcr_register: 0,
            sha256: "aa".to_string(),
        },
        PcrRegisterValue {
            pcr_register: 1,
            sha256: "bb".to_string(),
        },
    ];

    let _response = env
        .api
        .attest_candidate_machine(Request::new(
            rpc::protos::measured_boot::AttestCandidateMachineRequest {
                machine_id: machine_id.to_string(),
                pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            },
        ))
        .await
        .unwrap()
        .into_inner();
}

/// Emulates the `MachineValidationComplete` request of a Host
pub async fn persist_machine_validation_result(
    env: &TestEnv,
    machine_validation_result: rpc::forge::MachineValidationResult,
) {
    env.api
        .persist_validation_result(Request::new(
            rpc::forge::MachineValidationResultPostRequest {
                result: Some(machine_validation_result),
            },
        ))
        .await
        .unwrap()
        .into_inner();
}

/// Emulates the `get_machine_validation_results` request of a Host
pub async fn get_machine_validation_results(
    env: &TestEnv,
    machine_id: Option<rpc::common::MachineId>,
    include_history: bool,
    validation_id: Option<rpc::common::Uuid>,
) -> rpc::forge::MachineValidationResultList {
    env.api
        .get_machine_validation_results(Request::new(rpc::forge::MachineValidationGetRequest {
            machine_id,
            include_history,
            validation_id,
        }))
        .await
        .unwrap()
        .into_inner()
}

/// Emulates the `get_machine_validation_runs` request of a Host
pub async fn get_machine_validation_runs(
    env: &TestEnv,
    machine_id: rpc::common::MachineId,
    include_history: bool,
) -> rpc::forge::MachineValidationRunList {
    env.api
        .get_machine_validation_runs(Request::new(
            rpc::forge::MachineValidationRunListGetRequest {
                machine_id: Some(machine_id),
                include_history,
            },
        ))
        .await
        .unwrap()
        .into_inner()
}

// Emulates the `OnDemandMachineValidation` request of a Host
pub async fn on_demand_machine_validation(
    env: &TestEnv,
    machine_id: rpc::common::MachineId,
    tags: Vec<String>,
    allowed_tests: Vec<String>,
    run_unverfied_tests: bool,
    contexts: Vec<String>,
) -> rpc::forge::MachineValidationOnDemandResponse {
    env.api
        .on_demand_machine_validation(Request::new(rpc::forge::MachineValidationOnDemandRequest {
            machine_id: Some(machine_id),
            action: rpc::forge::machine_validation_on_demand_request::Action::Start.into(),
            tags,
            allowed_tests,
            run_unverfied_tests,
            contexts,
        }))
        .await
        .unwrap()
        .into_inner()
}

pub async fn update_machine_validation_run(
    env: &TestEnv,
    validation_id: Option<rpc::common::Uuid>,
    duration_to_complete: Option<rpc::Duration>,
    total: u32,
) -> rpc::forge::MachineValidationRunResponse {
    env.api
        .update_machine_validation_run(Request::new(rpc::forge::MachineValidationRunRequest {
            validation_id,
            duration_to_complete,
            total,
        }))
        .await
        .unwrap()
        .into_inner()
}
/// A hot swappable machine state handler.
/// Allows modifying the handler behavior without reconstructing the machine
/// state controller (which leads to stale metrics being saved).
#[derive(Debug, Clone)]
pub struct SwapHandler<H: StateHandler> {
    inner: Arc<Mutex<H>>,
}

#[async_trait::async_trait]
impl<H: StateHandler> StateHandler for SwapHandler<H>
where
    H::ObjectId: Send + Sync,
    H::State: Send + Sync,
    H::ControllerState: Send + Sync,
    H::ContextObjects: Send + Sync,
{
    type ObjectId = H::ObjectId;
    type State = H::State;
    type ControllerState = H::ControllerState;
    type ContextObjects = H::ContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut Self::State,
        controller_state: &Self::ControllerState,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        self.inner
            .lock()
            .await
            .handle_object_state(object_id, state, controller_state, txn, ctx)
            .await
    }
}

fn create_random_self_signed_cert() -> Vec<u8> {
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    let CertifiedKey { cert, .. } = generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate self-signed cert");
    cert.der().to_vec()
}
