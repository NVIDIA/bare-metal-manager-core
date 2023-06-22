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

use std::{net::Ipv4Addr, sync::Arc, time::SystemTime};

use carbide::{
    api::Api,
    auth::{Authorizer, NoopEngine},
    db::machine::Machine,
    ethernet_virtualization::{self, EthVirtData},
    ib,
    model::machine::{
        machine_id::{try_parse_machine_id, MachineId},
        ManagedHostState,
    },
    redfish::RedfishSim,
    resource_pool::common::CommonPools,
    state_controller::{
        controller::{ReachabilityParams, StateControllerIO},
        ib_subnet::{handler::IBSubnetStateHandler, io::IBSubnetStateControllerIO},
        machine::{handler::MachineStateHandler, io::MachineStateControllerIO},
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerServices,
        },
    },
};
use chrono::Duration;
use rpc::forge::forge_server::Forge;
use sqlx::PgPool;
use tonic::Request;

use crate::common::{
    api_fixtures::{dpu::create_dpu_machine, host::create_host_machine},
    test_credentials::TestCredentialProvider,
};

pub mod dpu;
pub mod host;
pub mod instance;
pub mod network_segment;

/// Carbide API for integration tests
pub type TestApi = Api<TestCredentialProvider>;

/// The datacenter-level DHCP relay that is assumed for all DPU discovery
pub const FIXTURE_DHCP_RELAY_ADDRESS: &str = "192.0.2.1";

pub const FIXTURE_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");
pub const FIXTURE_DPU_MACHINE_ID: &str =
    "fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g";
pub const FIXTURE_X86_MACHINE_ID: &str =
    "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";

pub struct TestEnv {
    pub api: TestApi,
    pub credential_provider: Arc<TestCredentialProvider>,
    pub common_pools: Arc<CommonPools>,
    pub eth_virt_data: EthVirtData,
    pub pool: PgPool,
    pub redfish_sim: Arc<RedfishSim>,
    pub ib_fabric_manager: Arc<dyn ib::IBFabricManager>,
    pub machine_state_controller_io: MachineStateControllerIO,
    pub network_segment_state_controller_io: NetworkSegmentStateControllerIO,
    pub reachability_params: ReachabilityParams,
    pub ib_subnet_state_controller_io: IBSubnetStateControllerIO,
}

impl TestEnv {
    /// Creates an instance of StateHandlerServices that are suitable for this
    /// test environment
    pub fn state_handler_services(&self) -> StateHandlerServices {
        let forge_api = Arc::new(Api::new(
            self.credential_provider.clone(),
            self.pool.clone(),
            Authorizer::new(Arc::new(NoopEngine {})),
            self.redfish_sim.clone(),
            None,
            self.eth_virt_data.clone(),
            self.common_pools.clone(),
            "not a real pemfile path".to_string(),
            "not a real keyfile path".to_string(),
        ));

        StateHandlerServices {
            pool: self.pool.clone(),
            redfish_client_pool: self.redfish_sim.clone(),
            vpc_api: None,
            ib_fabric_manager: self.ib_fabric_manager.clone(),
            forge_api,
            meter: None,
            reachability_params: self.reachability_params.clone(),
            pool_vlan_id: Some(self.common_pools.ethernet.pool_vlan_id.clone()),
            pool_vni: Some(self.common_pools.ethernet.pool_vni.clone()),
            pool_pkey: Some(self.common_pools.infiniband.pool_pkey.clone()),
        }
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    pub async fn run_machine_state_controller_iteration_until_state_matches(
        &self,
        host_machine_id: &MachineId,
        handler: &MachineStateHandler,
        max_iterations: u32,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        expected_state: ManagedHostState,
    ) {
        let services = Arc::new(self.state_handler_services());
        for _ in 0..max_iterations {
            run_state_controller_iteration(
                &services,
                &self.pool,
                &self.machine_state_controller_io,
                host_machine_id.clone(),
                handler,
            )
            .await
        }
        let machine = Machine::find_one(
            txn,
            host_machine_id,
            carbide::db::machine::MachineSearchConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(machine.current_state(), expected_state);
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    pub async fn run_machine_state_controller_iteration(
        &self,
        host_machine_id: MachineId,
        handler: &MachineStateHandler,
    ) {
        let services = Arc::new(self.state_handler_services());
        run_state_controller_iteration(
            &services,
            &self.pool,
            &self.machine_state_controller_io,
            host_machine_id,
            handler,
        )
        .await
    }

    /// Runs one iteration of the network state controller handler with the services
    /// in this test environment
    pub async fn run_network_segment_controller_iteration(
        &self,
        segment_id: uuid::Uuid,
        handler: &NetworkSegmentStateHandler,
    ) {
        let services = Arc::new(self.state_handler_services());
        run_state_controller_iteration(
            &services,
            &self.pool,
            &self.network_segment_state_controller_io,
            segment_id,
            handler,
        )
        .await
    }

    /// Runs one iteration of the ibsubnet state controller handler with the services
    /// in this test environment
    pub async fn run_ib_subnet_controller_iteration(
        &self,
        segment_id: uuid::Uuid,
        handler: &IBSubnetStateHandler,
    ) {
        let services = Arc::new(self.state_handler_services());
        run_state_controller_iteration(
            &services,
            &self.pool,
            &self.ib_subnet_state_controller_io,
            segment_id,
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
                    include_predicted_host: false,
                }),
                id,
                fqdn,
            }))
            .await
            .unwrap()
            .into_inner()
    }
}

/// Creates an environment for unit-testing
///
/// This retuns the `Api` object instance which can be used to simulate calls against
/// the Forge site controller, as well as mocks for dependent services that
/// can be inspected and passed to other systems.
pub async fn create_test_env(db_pool: sqlx::PgPool) -> TestEnv {
    let credential_provider = Arc::new(TestCredentialProvider::new());
    let redfish_sim = Arc::new(RedfishSim::default());
    let common_pools = CommonPools::create(db_pool.clone());
    let ib_fabric_manager = ib::local_ib_fabric_manager();

    let mut eth_virt_data = ethernet_virtualization::enable(&common_pools);
    eth_virt_data.asn = 65535;
    eth_virt_data.dhcp_servers = vec![FIXTURE_DHCP_RELAY_ADDRESS.to_string()];

    // Populate resource pools
    let mut txn = db_pool.begin().await.unwrap();
    common_pools
        .infiniband
        .pool_pkey
        .populate(&mut txn, (1..100).collect())
        .await
        .unwrap();
    common_pools
        .ethernet
        .pool_loopback_ip
        .as_ref()
        .populate(
            &mut txn,
            // Must match a network_prefix in fixtures/create_network_segment.sql
            // Here it's 192.0.2.X
            (0xC0_00_02_00..0xC0_00_02_FF).map(Ipv4Addr::from).collect(),
        )
        .await
        .unwrap();
    common_pools
        .ethernet
        .pool_vni
        .as_ref()
        .populate(&mut txn, (10001..10005).collect())
        .await
        .unwrap();
    common_pools
        .ethernet
        .pool_vlan_id
        .as_ref()
        .populate(&mut txn, (1..5).collect())
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let api = carbide::api::Api::new(
        credential_provider.clone(),
        db_pool.clone(),
        Authorizer::new(Arc::new(NoopEngine {})),
        redfish_sim.clone(),
        None,
        eth_virt_data.clone(),
        common_pools.clone(),
        "not a real pemfile path".to_string(),
        "not a real keyfile path".to_string(),
    );
    TestEnv {
        api,
        common_pools,
        credential_provider,
        eth_virt_data,
        pool: db_pool,
        redfish_sim,
        ib_fabric_manager,
        machine_state_controller_io: MachineStateControllerIO::default(),
        network_segment_state_controller_io: NetworkSegmentStateControllerIO::default(),
        reachability_params: ReachabilityParams {
            dpu_wait_time: Duration::seconds(0),
        },
        ib_subnet_state_controller_io: IBSubnetStateControllerIO::default(),
    }
}

/// Runs a single state controller iteration for any kind of state controller
async fn run_state_controller_iteration<IO: StateControllerIO>(
    handler_services: &Arc<StateHandlerServices>,
    pool: &PgPool,
    io: &IO,
    object_id: IO::ObjectId,
    handler: &impl StateHandler<
        State = IO::State,
        ControllerState = IO::ControllerState,
        ObjectId = IO::ObjectId,
    >,
) {
    let mut handler_ctx = StateHandlerContext {
        services: handler_services,
    };
    let mut txn = pool.begin().await.unwrap();

    let mut db_segment = io.load_object_state(&mut txn, &object_id).await.unwrap();
    let mut controller_state = io
        .load_controller_state(&mut txn, &object_id, &db_segment)
        .await
        .unwrap();

    let mut holder = ControllerStateReader::new(&mut controller_state.value);
    handler
        .handle_object_state(
            &object_id,
            &mut db_segment,
            &mut holder,
            &mut txn,
            &mut handler_ctx,
        )
        .await
        .unwrap();

    if holder.is_modified() {
        io.persist_controller_state(
            &mut txn,
            &object_id,
            controller_state.version,
            controller_state.value,
        )
        .await
        .unwrap();
    }
    txn.commit().await.unwrap();
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
pub async fn discovery_completed(env: &TestEnv, machine_id: rpc::forge::MachineId) {
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
            function_type: iface.function,
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![iface.ip.clone()],
        }]
    } else {
        let mut interfaces = vec![];
        for (i, iface) in network_config.tenant_interfaces.iter().enumerate() {
            interfaces.push(rpc::forge::InstanceInterfaceStatusObservation {
                function_type: iface.function,
                virtual_function_id: if iface.function
                    == rpc::InterfaceFunctionType::Physical as i32
                {
                    None
                } else {
                    Some(i as u32)
                },
                mac_address: None,
                addresses: vec![iface.ip.clone()],
            });
        }
        interfaces
    };
    let status = rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(dpu_machine_id.to_string().into()),
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
    let dpu_machine_id = create_dpu_machine(env).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let host_machine_id = create_host_machine(env, &dpu_machine_id).await;

    (
        try_parse_machine_id(&host_machine_id).unwrap(),
        dpu_machine_id,
    )
}
