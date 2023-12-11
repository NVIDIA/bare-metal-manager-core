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
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use carbide::{
    ipmitool::IPMIToolTestImpl,
    model::machine::{machine_id::MachineId, ManagedHostState, ManagedHostStateSnapshot},
    redfish::RedfishSim,
    state_controller::{
        controller::{ReachabilityParams, StateController},
        machine::{context::MachineStateHandlerContextObjects, io::MachineStateControllerIO},
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
        },
    },
};
use rpc::{forge::forge_server::Forge, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use tonic::Request;

use crate::common::api_fixtures::{
    create_test_env,
    dpu::{create_dpu_hardware_info, dpu_discover_dhcp},
};

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
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError> {
        assert_eq!(state.host_snapshot.machine_id, *machine_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(machine_id.to_string()).or_default() += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }
}

#[sqlx::test(fixtures(
    "../../fixtures/create_domain",
    "../../fixtures/create_vpc",
    "../../fixtures/create_network_segment",
))]
async fn iterate_over_all_machines(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool.clone()).await;
    let hosts: Vec<_> = [0..4]
        .iter()
        .map(|_| env.start_managed_host_sim())
        .collect();

    let mut machine_ids = Vec::new();
    for host_sim in hosts.iter() {
        let interface_id =
            dpu_discover_dhcp(&env, &host_sim.config.dpu_oob_mac_address.to_string()).await;

        let hardware_info = create_dpu_hardware_info(&host_sim.config);
        let _response = env
            .api
            .discover_machine(Request::new(MachineDiscoveryInfo {
                machine_interface_id: Some(interface_id),
                discovery_data: Some(DiscoveryData::Info(
                    DiscoveryInfo::try_from(hardware_info.clone()).unwrap(),
                )),
            }))
            .await
            .unwrap()
            .into_inner();

        let host_machine_id = MachineId::host_id_from_dpu_hardware_info(&hardware_info).unwrap();
        machine_ids.push(host_machine_id);
    }

    let machine_handler = Arc::new(TestMachineStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let expected_iterations = (TEST_TIME.as_millis() / ITERATION_TIME.as_millis()) as f64;
    let expected_total_count = expected_iterations * hosts.len() as f64;

    let test_api = Arc::new(env.api);
    // We build multiple state controllers. But since only one should act at a time,
    // the count should still not increase
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(
            StateController::<MachineStateControllerIO>::builder()
                .iteration_time(Duration::from_millis(100))
                .database(pool.clone())
                .redfish_client_pool(Arc::new(RedfishSim::default()))
                .ib_fabric_manager(env.ib_fabric_manager.clone())
                .forge_api(test_api.clone())
                .state_handler(machine_handler.clone())
                .reachability_params(ReachabilityParams {
                    dpu_wait_time: chrono::Duration::seconds(0),
                    host_wait_time: chrono::Duration::seconds(0),
                    power_down_wait: chrono::Duration::seconds(0),
                    failure_retry_time: chrono::Duration::seconds(0),
                })
                .ipmi_tool(Arc::new(IPMIToolTestImpl {}))
                .build()
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
        "Expected count of {}, but got {}",
        expected_total_count,
        count
    );

    for machine_id in machine_ids {
        let guard = machine_handler.counts_per_id.lock().unwrap();
        let count = guard
            .get(&machine_id.to_string())
            .cloned()
            .unwrap_or_default() as f64;

        assert!(
            count >= 0.65 * expected_iterations && count <= 1.25 * expected_iterations,
            "Expected individual count of {}, but got {} for {}",
            expected_iterations,
            count,
            machine_id
        );
    }

    Ok(())
}
