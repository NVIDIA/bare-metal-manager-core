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

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use forge_uuid::machine::MachineId;
use model::hardware_info::HardwareInfo;
use model::machine::machine_id::host_id_from_dpu_hardware_info;
use model::machine::{ManagedHostState, ManagedHostStateSnapshot};
use rpc::forge::forge_server::Forge;
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use sqlx::PgConnection;
use tonic::Request;

use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::machine::io::MachineStateControllerIO;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::dpu::dpu_discover_dhcp;

#[derive(Debug, Default, Clone)]
pub struct TestMachineStateHandler {
    /// The total count for the handler
    pub count: Arc<AtomicUsize>,
    /// We count for every machine ID how often the handler was called
    pub counts_per_id: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait::async_trait]
impl StateHandler for TestMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &Self::ControllerState,
        _txn: &mut PgConnection,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        assert_eq!(state.host_snapshot.id, *machine_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(machine_id.to_string()).or_default() += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(StateHandlerOutcome::do_nothing())
    }
}

#[crate::sqlx_test]
async fn iterate_over_all_machines(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool.clone()).await;
    let host_configs: Vec<_> = (0..4).map(|_| env.managed_host_config()).collect();

    let mut machine_ids = Vec::new();
    for host_config in host_configs.iter() {
        let dpu = host_config.get_and_assert_single_dpu();
        let interface_id = dpu_discover_dhcp(&env, &dpu.oob_mac_address.to_string()).await;

        let hardware_info = HardwareInfo::from(dpu);
        let _response = env
            .api
            .discover_machine(Request::new(MachineDiscoveryInfo {
                machine_interface_id: Some(interface_id),
                discovery_data: Some(DiscoveryData::Info(
                    DiscoveryInfo::try_from(hardware_info.clone()).unwrap(),
                )),
                create_machine: true,
            }))
            .await
            .unwrap()
            .into_inner();

        let host_machine_id = host_id_from_dpu_hardware_info(&hardware_info).unwrap();
        machine_ids.push(host_machine_id);
    }

    let machine_handler = Arc::new(TestMachineStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let expected_iterations = (TEST_TIME.as_millis() / ITERATION_TIME.as_millis()) as f64;
    let expected_total_count = expected_iterations * host_configs.len() as f64;

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: env.pool.clone(),
        redfish_client_pool: env.redfish_sim.clone(),
        ib_fabric_manager: env.ib_fabric_manager.clone(),
        ib_pools: env.common_pools.infiniband.clone(),
        ipmi_tool: env.ipmi_tool.clone(),
        site_config: env.config.clone(),
        mqtt_client: None,
    });

    // We build multiple state controllers. But since only one should act at a time,
    // the count should still not increase
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(
            StateController::<MachineStateControllerIO>::builder()
                .iteration_config(IterationConfig {
                    iteration_time: ITERATION_TIME,
                    ..Default::default()
                })
                .database(pool.clone())
                .services(handler_services.clone())
                .state_handler(machine_handler.clone())
                .build_and_spawn()
                .unwrap(),
        );
    }

    tokio::time::sleep(TEST_TIME).await;
    drop(handles);
    // Wait some extra time until the controller background task shuts down
    tokio::time::sleep(Duration::from_secs(1)).await;

    let count = machine_handler.count.load(Ordering::SeqCst) as f64;
    assert!(
        count >= 0.65 * expected_total_count && count <= 1.25 * expected_total_count,
        "Expected count of {expected_total_count}, but got {count}"
    );

    for machine_id in machine_ids {
        let guard = machine_handler.counts_per_id.lock().unwrap();
        let count = guard
            .get(&machine_id.to_string())
            .copied()
            .unwrap_or_default() as f64;

        assert!(
            count >= 0.65 * expected_iterations && count <= 1.25 * expected_iterations,
            "Expected individual count of {expected_iterations}, but got {count} for {machine_id}"
        );
    }

    Ok(())
}
