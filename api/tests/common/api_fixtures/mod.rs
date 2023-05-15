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

use std::sync::Arc;

use carbide::{
    api::Api,
    auth::{Authorizer, NoopEngine},
    db::machine::Machine,
    ethernet_virtualization::EthVirtData,
    kubernetes::{VpcApiSim, VpcApiSimConfig},
    model::machine::{
        machine_id::{try_parse_machine_id, MachineId},
        ManagedHostState,
    },
    reachability::TestPingReachabilityChecker,
    redfish::RedfishSim,
    state_controller::{
        controller::{ReachabilityParams, StateControllerIO},
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
use rpc::forge::{
    forge_server::Forge, BmcInfo, BmcMetaDataUpdateRequest, ForgeAgentControlRequest,
    ForgeAgentControlResponse, MachineDiscoveryCompletedRequest,
};
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
    pub pool: PgPool,
    pub redfish_sim: Arc<RedfishSim>,
    pub vpc_api: Arc<VpcApiSim>,
    pub machine_state_controller_io: MachineStateControllerIO,
    pub network_segment_state_controller_io: NetworkSegmentStateControllerIO,
    pub reachability_params: ReachabilityParams,
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
            self.vpc_api.clone(),
            EthVirtData::default(),
            "not a real pemfile path".to_string(),
            "not a real keyfile path".to_string(),
        ));
        StateHandlerServices {
            pool: self.pool.clone(),
            redfish_client_pool: self.redfish_sim.clone(),
            vpc_api: self.vpc_api.clone(),
            forge_api,
            meter: None,
            reachability_params: self.reachability_params.clone(),
            pool_vlan_id: None,
            pool_vni: None,
        }
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    pub async fn run_machine_state_controller_iteration_until_state_matches(
        &self,
        dpu_machine_id: &MachineId,
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
                dpu_machine_id.clone(),
                handler,
            )
            .await
        }
        let machine = Machine::find_one(
            txn,
            dpu_machine_id,
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
        dpu_machine_id: MachineId,
        handler: &MachineStateHandler,
    ) {
        let services = Arc::new(self.state_handler_services());
        run_state_controller_iteration(
            &services,
            &self.pool,
            &self.machine_state_controller_io,
            dpu_machine_id,
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
                }),
                id,
                fqdn,
            }))
            .await
            .unwrap()
            .into_inner()
    }
}

#[derive(Default, Debug)]
pub struct TestEnvConfig {
    /// VPC simulation configuration
    pub vpc_sim_config: VpcApiSimConfig,
}

/// Creates an environment for unit-testing
///
/// This retuns the `Api` object instance which can be used to simulate calls against
/// the Forge site controller, as well as mocks for dependent services that
/// can be inspected and passed to other systems.
pub fn create_test_env(pool: sqlx::PgPool, config: TestEnvConfig) -> TestEnv {
    let credential_provider = Arc::new(TestCredentialProvider::new());
    let vpc_api = Arc::new(VpcApiSim::with_config(config.vpc_sim_config));
    let redfish_sim = Arc::new(RedfishSim::default());

    let api = carbide::api::Api::new(
        credential_provider.clone(),
        pool.clone(),
        Authorizer::new(Arc::new(NoopEngine {})),
        redfish_sim.clone(),
        vpc_api.clone(),
        EthVirtData::default(),
        "not a real pemfile path".to_string(),
        "not a real keyfile path".to_string(),
    );

    TestEnv {
        api,
        credential_provider,
        pool,
        redfish_sim,
        vpc_api,
        machine_state_controller_io: MachineStateControllerIO::default(),
        network_segment_state_controller_io: NetworkSegmentStateControllerIO::default(),
        reachability_params: ReachabilityParams {
            checker: Arc::new(TestPingReachabilityChecker::default()),
            dpu_wait_time: Duration::seconds(0),
        },
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
    machine_id: rpc::MachineId,
    bmc_ip_address: &str,
    admin_user: String,
    bmc_mac_address: String,
    bmc_version: String,
    bmc_firmware_version: String,
) {
    let bmc_info = BmcInfo {
        ip: Some(bmc_ip_address.to_owned()),
        mac: Some(bmc_mac_address.to_owned()),
        version: Some(bmc_version),
        firmware_version: Some(bmc_firmware_version),
    };

    let _response = env
        .api
        .update_bmc_meta_data(Request::new(BmcMetaDataUpdateRequest {
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
pub async fn discovery_completed(env: &TestEnv, machine_id: rpc::MachineId) {
    let _response = env
        .api
        .discovery_completed(Request::new(MachineDiscoveryCompletedRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
}

/// Emulates the `DiscoveryCompleted` request of a DPU/Host
pub async fn forge_agent_control(
    env: &TestEnv,
    machine_id: rpc::MachineId,
) -> ForgeAgentControlResponse {
    env.api
        .forge_agent_control(Request::new(ForgeAgentControlRequest {
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
