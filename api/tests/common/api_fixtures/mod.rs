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

use carbide::{
    api::Api,
    auth::{Authorizer, NoopEngine},
    kubernetes::{VpcApiSim, VpcApiSimConfig},
    state_controller::{
        controller::StateControllerIO,
        machine::{handler::MachineStateHandler, io::MachineStateControllerIO},
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerServices,
        },
    },
};
use rpc::forge::forge_server::Forge;
use sqlx::PgPool;
use std::sync::Arc;

use crate::common::test_credentials::TestCredentialProvider;

pub mod dpu;
pub mod host;
pub mod instance;
pub mod network_segment;

/// Carbide API for integration tests
pub type TestApi = Api<TestCredentialProvider>;

pub const FIXTURE_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

pub struct TestEnv {
    pub api: TestApi,
    pub credential_provider: Arc<TestCredentialProvider>,
    pub pool: PgPool,
    pub vpc_api: Arc<VpcApiSim>,
    pub machine_state_controller_io: MachineStateControllerIO,
    pub network_segment_state_controller_io: NetworkSegmentStateControllerIO,
}

impl TestEnv {
    /// Creates an instance of StateHandlerServices that are suitable for this
    /// test environment
    pub fn state_handler_services(&self) -> StateHandlerServices {
        StateHandlerServices {
            pool: self.pool.clone(),
            vpc_api: self.vpc_api.clone(),
        }
    }

    /// Runs one iteration of the machine state controller handler with the services
    /// in this test environment
    pub async fn run_machine_state_controller_iteration(
        &self,
        machine_id: uuid::Uuid,
        handler: &MachineStateHandler,
    ) {
        let services = Arc::new(self.state_handler_services());
        run_state_controller_iteration(
            &services,
            &self.pool,
            &self.machine_state_controller_io,
            machine_id,
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
                search_config: Some(rpc::forge::MachineSearchConfig { include_dpus }),
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

    let api = carbide::api::Api::new(
        credential_provider.clone(),
        pool.clone(),
        Authorizer::new(Arc::new(NoopEngine {})),
        vpc_api.clone(),
    );

    TestEnv {
        api,
        credential_provider,
        pool,
        vpc_api,
        machine_state_controller_io: MachineStateControllerIO::default(),
        network_segment_state_controller_io: NetworkSegmentStateControllerIO::default(),
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
