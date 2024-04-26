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
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};

use arc_swap::ArcSwap;
use carbide::{
    api::Api,
    cfg::{
        default_dpu_models, CarbideConfig, DpuFwUpdateConfig, IbFabricMonitorConfig,
        IbPartitionStateControllerConfig, MachineStateControllerConfig,
        NetworkSegmentStateControllerConfig, StateControllerConfig,
    },
    db::machine::Machine,
    ethernet_virtualization::EthVirtData,
    ib::{self, IBFabricManager, IBFabricManagerConfig, IBFabricManagerType},
    ipmitool::IPMIToolTestImpl,
    logging::level_filter::ActiveLevel,
    model::{
        hardware_info::TpmEkCertificate,
        machine::{
            machine_id::{try_parse_machine_id, MachineId},
            MachineLastRebootRequested, ManagedHostState,
        },
    },
    redfish::RedfishSim,
    resource_pool::{self, common::CommonPools},
    state_controller::{
        controller::StateController,
        ib_partition::{handler::IBPartitionStateHandler, io::IBPartitionStateControllerIO},
        io::StateControllerIO,
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
use chrono::Duration;
use rpc::forge::forge_server::Forge;
use sqlx::PgPool;
use tonic::Request;
use tracing_subscriber::EnvFilter;

use crate::common::{
    api_fixtures::{
        dpu::create_dpu_machine,
        host::create_host_machine,
        managed_host::{ManagedHostConfig, ManagedHostSim},
    },
    mac_address_pool,
    test_certificates::TestCertificateProvider,
    test_credentials::TestCredentialProvider,
    test_meter::TestMeter,
};

pub mod dpu;
pub mod host;
pub mod ib_partition;
pub mod instance;
pub mod managed_host;
pub mod network_segment;

/// Carbide API for integration tests
pub type TestApi = Api<TestCredentialProvider, TestCertificateProvider>;

/// The datacenter-level DHCP relay that is assumed for all DPU discovery
///
/// For integration testing this must match a prefix defined in fixtures/create_network_segment.sql
/// In production the relay IP is a MetalLB VIP so isn't in a network segment.
pub const FIXTURE_DHCP_RELAY_ADDRESS: &str = "192.0.2.1";

pub const FIXTURE_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");
pub const FIXTURE_DPU_MACHINE_ID: &str =
    "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g";
pub const FIXTURE_X86_MACHINE_ID: &str =
    "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";

pub struct TestEnv {
    pub api: Arc<TestApi>,
    pub config: Arc<CarbideConfig>,
    pub credential_provider: Arc<TestCredentialProvider>,
    pub certificate_provider: Arc<TestCertificateProvider>,
    pub common_pools: Arc<CommonPools>,
    pub eth_virt_data: EthVirtData,
    pub pool: PgPool,
    pub redfish_sim: Arc<RedfishSim>,
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,
    pub ipmi_tool: Arc<IPMIToolTestImpl>,
    pub machine_state_controller_io: MachineStateControllerIO,
    pub network_segment_state_controller_io: NetworkSegmentStateControllerIO,
    pub reachability_params: ReachabilityParams,
    pub ib_partition_state_controller_io: IBPartitionStateControllerIO,
    pub test_meter: TestMeter,
}

impl TestEnv {
    /// Creates an instance of StateHandlerServices that are suitable for this
    /// test environment
    pub fn state_handler_services(&self) -> StateHandlerServices {
        StateHandlerServices {
            pool: self.pool.clone(),
            redfish_client_pool: self.redfish_sim.clone(),
            ib_fabric_manager: self.ib_fabric_manager.clone(),
            forge_api: self.api.clone(),
            meter: Some(self.test_meter.meter()),
            pool_pkey: Some(self.common_pools.infiniband.pool_pkey.clone()),
            ipmi_tool: self.ipmi_tool.clone(),
        }
    }

    /// Generates a simulation for Host+DPU pair
    pub fn start_managed_host_sim(&self) -> ManagedHostSim {
        // TODO: Also add unique serial numbers, etc
        let host_cert_data: [u8; 32] = rand::random();
        let config = ManagedHostConfig {
            dpu_bmc_mac_address: mac_address_pool::DPU_BMC_MAC_ADDRESS_POOL.allocate(),
            dpu_oob_mac_address: mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL.allocate(),
            host_bmc_mac_address: mac_address_pool::HOST_BMC_MAC_ADDRESS_POOL.allocate(),
            host_mac_address: mac_address_pool::HOST_BMC_MAC_ADDRESS_POOL.allocate(),
            host_tpm_ek_cert: TpmEkCertificate::from(host_cert_data.to_vec()),
        };

        // TODO: This will in the future also spin up redfish mocks for these components
        ManagedHostSim { config }
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    pub async fn run_machine_state_controller_iteration_until_state_matches(
        &self,
        host_machine_id: &MachineId,
        handler: MachineStateHandler,
        max_iterations: u32,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        expected_state: ManagedHostState,
    ) {
        let mut controller = self.build_machine_state_controller(handler);

        for _ in 0..max_iterations {
            controller.run_single_iteration().await;

            let machine = Machine::find_one(
                txn,
                host_machine_id,
                carbide::db::machine::MachineSearchConfig::default(),
            )
            .await
            .unwrap()
            .unwrap();

            if machine.current_state() == expected_state {
                return;
            }
        }

        let machine = Machine::find_one(
            txn,
            host_machine_id,
            carbide::db::machine::MachineSearchConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();

        panic!(
            "Expected Machine state to be {expected_state} after {max_iterations} iterations, but state is {}",
            machine.current_state()
        );
    }

    /// Builds a State Controller that executes a specific handler for unit-testing purposes
    pub fn build_state_controller<IO: StateControllerIO, H>(
        &self,
        object_type_for_metrics: &str,
        handler: H,
    ) -> StateController<IO>
    where
        H: StateHandler<
            State = IO::State,
            ControllerState = IO::ControllerState,
            ContextObjects = IO::ContextObjects,
            ObjectId = IO::ObjectId,
        >,
    {
        StateController::<IO>::builder()
            .database(self.pool.clone())
            .meter(object_type_for_metrics, self.test_meter.meter())
            .redfish_client_pool(self.redfish_sim.clone())
            .ib_fabric_manager(self.ib_fabric_manager.clone())
            .forge_api(self.api.clone())
            .ipmi_tool(self.ipmi_tool.clone())
            .state_handler(Arc::new(handler))
            .build_for_manual_iterations()
            .expect("Unable to build state controller")
    }

    /// Builds a Machine State Controller that executes a specific handler for unit-testing purposes
    pub fn build_machine_state_controller(
        &self,
        handler: MachineStateHandler,
    ) -> StateController<MachineStateControllerIO> {
        self.build_state_controller("forge_machines", handler)
    }

    /// Builds a Network Segment State Controller that executes a specific handler for unit-testing purposes
    pub fn build_network_segment_state_controller(
        &self,
        handler: NetworkSegmentStateHandler,
    ) -> StateController<NetworkSegmentStateControllerIO> {
        self.build_state_controller("forge_network_segments", handler)
    }

    /// Builds a InfiniBand Partition State Controller that executes a specific handler for unit-testing purposes
    pub fn build_ib_partition_state_controller(
        &self,
        handler: IBPartitionStateHandler,
    ) -> StateController<IBPartitionStateControllerIO> {
        self.build_state_controller("forge_ib_partitions", handler)
    }

    /// Runs a single state controller iteration for any kind of state controller
    pub async fn run_state_controller_iteration<IO: StateControllerIO>(
        &self,
        object_type_for_metrics: &str,
        handler: impl StateHandler<
            State = IO::State,
            ControllerState = IO::ControllerState,
            ObjectId = IO::ObjectId,
            ContextObjects = IO::ContextObjects,
        >,
    ) {
        let mut controller = self.build_state_controller::<IO, _>(object_type_for_metrics, handler);
        controller.run_single_iteration().await;
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    pub async fn run_machine_state_controller_iteration(&self, handler: MachineStateHandler) {
        self.run_state_controller_iteration::<MachineStateControllerIO>("forge_machines", handler)
            .await
    }

    /// Runs one iteration of the network state controller handler with the services
    /// in this test environment
    pub async fn run_network_segment_controller_iteration(
        &self,
        handler: NetworkSegmentStateHandler,
    ) {
        self.run_state_controller_iteration::<NetworkSegmentStateControllerIO>(
            "forge_network_segments",
            handler,
        )
        .await
    }

    /// Runs one iteration of the IB partition state controller handler with the services
    /// in this test environment
    pub async fn run_ib_partition_controller_iteration(&self, handler: IBPartitionStateHandler) {
        self.run_state_controller_iteration::<IBPartitionStateControllerIO>(
            "forge_ib_partitions",
            handler,
        )
        .await
    }

    // Returns all machines using FindMachines call.
    pub async fn find_machines(
        &self,
        id: Option<rpc::forge::MachineId>,
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
    pub async fn find_instances(&self, id: Option<rpc::forge::Uuid>) -> rpc::forge::InstanceList {
        self.api
            .find_instances(tonic::Request::new(rpc::forge::InstanceSearchQuery { id }))
            .await
            .unwrap()
            .into_inner()
    }
}

fn get_config() -> CarbideConfig {
    CarbideConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1079),
        metrics_endpoint: None,
        otlp_endpoint: None,
        database_url: "pgsql:://localhost".to_string(),
        max_database_connections: 1000,
        asn: 0,
        dhcp_servers: vec![],
        route_servers: vec![],
        enable_route_servers: false,
        deny_prefixes: vec![],
        site_fabric_prefixes: vec![],
        tls: Some(carbide::cfg::TlsConfig {
            root_cafile_path: "Not a real path".to_string(),
            identity_pemfile_path: "Not a real pemfile".to_string(),
            identity_keyfile_path: "Not a real keyfile".to_string(),
            admin_root_cafile_path: "Not a real cafile".to_string(),
        }),
        auth: None,
        pools: None,
        networks: None,
        dpu_impi_tool_impl: None,
        dpu_ipmi_reboot_attempts: Some(0),
        initial_domain_name: Some("test.com".to_string()),
        initial_dpu_agent_upgrade_policy: None,
        dpu_fw_update_config: DpuFwUpdateConfig::default(),
        dpu_nic_firmware_update_version: None,
        dpu_nic_firmware_initial_update_enabled: true,
        dpu_nic_firmware_reprovision_update_enabled: true,
        max_concurrent_machine_updates: None,
        machine_update_run_interval: None,
        site_explorer: None,
        dpu_dhcp_server_enabled: false,
        nvue_enabled: true,
        ib_config: None,
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
        dpu_models: default_dpu_models(),
    }
}

/// sqlx::test shares the pool with all testcases in a file. If there are many testcases in a file,
/// test cases will start getting PoolTimedOut error. To avoid it, each test case will be assigned
/// its own pool.
async fn create_pool(current_pool: sqlx::PgPool) -> sqlx::PgPool {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set.");
    let db_options = current_pool.connect_options();
    let db: &str = db_options
        .get_database()
        .expect("No database is set initially.");
    let db_url = format!("{}/{}", db_url, db);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Pool creation failed.")
}

/// Creates an environment for unit-testing
///
/// This retuns the `Api` object instance which can be used to simulate calls against
/// the Forge site controller, as well as mocks for dependent services that
/// can be inspected and passed to other systems.
pub async fn create_test_env(db_pool: sqlx::PgPool) -> TestEnv {
    let db_pool = create_pool(db_pool).await;
    let test_meter = TestMeter::default();
    let credential_provider = Arc::new(TestCredentialProvider::new());
    let certificate_provider = Arc::new(TestCertificateProvider::new());
    let redfish_sim = Arc::new(RedfishSim::default());
    let ib_fabric_manager_impl = ib::create_ib_fabric_manager(
        credential_provider.clone(),
        IBFabricManagerConfig {
            manager_type: IBFabricManagerType::Mock,
            ..IBFabricManagerConfig::default()
        },
    );

    let ib_fabric_manager: Arc<dyn IBFabricManager> = Arc::new(ib_fabric_manager_impl);

    let eth_virt_data = EthVirtData {
        asn: 65535,
        dhcp_servers: vec![FIXTURE_DHCP_RELAY_ADDRESS.to_string()],
        route_servers: vec![],
        route_servers_enabled: true,
        deny_prefixes: vec![],
    };

    // Populate resource pools
    let mut txn = db_pool.begin().await.unwrap();
    resource_pool::define_all_from(&mut txn, &pool_defs())
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let common_pools = CommonPools::create(db_pool.clone())
        .await
        .expect("Creating pools should work");

    let config = Arc::new(get_config());

    let api = Arc::new(Api::new(
        config.clone(),
        credential_provider.clone(),
        certificate_provider.clone(),
        db_pool.clone(),
        redfish_sim.clone(),
        eth_virt_data.clone(),
        common_pools.clone(),
        ib_fabric_manager.clone(),
        Arc::new(ArcSwap::from(Arc::new(ActiveLevel::new(
            EnvFilter::builder()
                .parse(std::env::var("RUST_LOG").unwrap_or("trace".to_string()))
                .unwrap(),
        )))),
        Arc::new(IPMIToolTestImpl {}),
    ));

    TestEnv {
        api,
        common_pools,
        config,
        credential_provider,
        certificate_provider,
        eth_virt_data,
        pool: db_pool,
        redfish_sim,
        ib_fabric_manager,
        ipmi_tool: Arc::new(IPMIToolTestImpl {}),
        machine_state_controller_io: MachineStateControllerIO::default(),
        network_segment_state_controller_io: NetworkSegmentStateControllerIO::default(),
        reachability_params: ReachabilityParams {
            dpu_wait_time: Duration::seconds(0),
            power_down_wait: Duration::seconds(0),
            failure_retry_time: Duration::seconds(0),
        },
        ib_partition_state_controller_io: IBPartitionStateControllerIO::default(),
        test_meter,
    }
}

fn pool_defs() -> HashMap<String, resource_pool::ResourcePoolDef> {
    let mut defs = HashMap::new();
    defs.insert(
        resource_pool::common::PKEY.to_string(),
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
pub async fn update_bmc_metadata(
    env: &TestEnv,
    machine_id: rpc::forge::MachineId,
    bmc_ip_address: &str,
    admin_user: String,
    bmc_mac_address: String,
    bmc_version: String,
    bmc_firmware_version: String,
) {
    let bmc_info = rpc::forge::BmcInfo {
        ip: Some(bmc_ip_address.to_owned()),
        port: None,
        mac: Some(bmc_mac_address.to_owned()),
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
pub async fn discovery_completed(
    env: &TestEnv,
    machine_id: rpc::forge::MachineId,
    discovery_error: Option<String>,
) {
    let _response = env
        .api
        .discovery_completed(Request::new(rpc::forge::MachineDiscoveryCompletedRequest {
            machine_id: Some(machine_id),
            discovery_error,
        }))
        .await
        .unwrap()
        .into_inner();
}

/// Fake an iteration of forge-dpu-agent requesting network config, applying it, and reporting back
/// Returns tuple of latest (machine_config_version, instance_config_version)
pub async fn network_configured(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
) -> (String, Option<String>) {
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

    let instance_cv = if network_config.instance_config_version.is_empty() {
        None
    } else {
        Some(network_config.instance_config_version.clone())
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
        }]
    } else {
        let mut interfaces = vec![];
        for iface in network_config.tenant_interfaces.iter() {
            interfaces.push(rpc::forge::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: iface.virtual_function_id,
                mac_address: None,
                addresses: vec![iface.ip.clone()],
            });
        }
        interfaces
    };
    let status = rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(dpu_machine_id.to_string().into()),
        dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
        observed_at: Some(SystemTime::now().into()),
        health: Some(rpc::forge::NetworkHealth {
            is_healthy: true,
            ..Default::default()
        }),
        network_config_version: Some(network_config.managed_host_config_version.clone()),
        instance_id: network_config.instance_id.clone(),
        instance_config_version: instance_cv.clone(),
        interfaces,
        network_config_error: None,
        client_certificate_expiry_unix_epoch_secs: None,
    };
    tracing::trace!(
        "network_configured machine={} instance={}",
        status.network_config_version.as_ref().unwrap(),
        instance_cv.clone().unwrap_or_default(),
    );
    let _ = env
        .api
        .record_dpu_network_status(Request::new(status))
        .await
        .unwrap();

    (
        network_config.managed_host_config_version.clone(),
        instance_cv,
    )
}

pub async fn forge_agent_control(
    env: &TestEnv,
    machine_id: rpc::forge::MachineId,
) -> rpc::forge::ForgeAgentControlResponse {
    env.api
        .forge_agent_control(Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner()
}

pub async fn create_managed_host(env: &TestEnv) -> (MachineId, MachineId) {
    // TODO: Return host_sim
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = create_dpu_machine(env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let host_machine_id = create_host_machine(env, &host_sim.config, &dpu_machine_id).await;

    (
        try_parse_machine_id(&host_machine_id).unwrap(),
        dpu_machine_id,
    )
}

pub async fn update_time_params(pool: &sqlx::PgPool, machine: &Machine, retry_count: i64) {
    let mut txn = pool.begin().await.unwrap();
    let data = MachineLastRebootRequested {
        time: machine.last_reboot_requested().unwrap().time - Duration::minutes(1),
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
