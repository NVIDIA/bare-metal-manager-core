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
    db::machine::Machine,
    ipmitool::IPMIToolTestImpl,
    model::machine::{machine_id::MachineId, ManagedHostState, ManagedHostStateSnapshot},
    redfish::RedfishSim,
    state_controller::{
        controller::{ReachabilityParams, StateController},
        machine::{
            handler::MachineStateHandler, io::MachineStateControllerIO, metrics::MachineMetrics,
        },
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
        },
    },
};
use rpc::{forge::forge_server::Forge, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use tonic::Request;

use crate::common::api_fixtures::{
    create_managed_host, create_test_env,
    dpu::{create_dpu_hardware_info, dpu_discover_dhcp},
    run_state_controller_iteration,
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
    type ObjectMetrics = MachineMetrics;

    async fn handle_object_state(
        &self,
        machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _metrics: &mut MachineMetrics,
        _ctx: &mut StateHandlerContext,
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

    // Insert some machines
    let dpu_macs = &[
        "11:22:33:44:55:01",
        "11:22:33:44:55:02",
        "11:22:33:44:55:03",
        "11:22:33:44:55:04",
    ];

    let host_macs = &[
        "21:22:33:44:55:01",
        "21:22:33:44:55:02",
        "21:22:33:44:55:03",
        "21:22:33:44:55:04",
    ];
    let mut machine_ids = Vec::new();
    for (idx, mac) in dpu_macs.iter().enumerate() {
        let interface_id = dpu_discover_dhcp(&env, mac).await;

        let mut hardware_info = create_dpu_hardware_info();
        hardware_info.dmi_data.as_mut().unwrap().product_serial = format!("DPU_{}", mac);
        hardware_info.dpu_info.as_mut().unwrap().factory_mac_address = host_macs[idx].to_string();
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
    let expected_total_count = expected_iterations * dpu_macs.len() as f64;

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

/// If the DPU stops sending us health updates we eventually mark it unhealthy
#[sqlx::test(fixtures(
    "../../fixtures/create_domain",
    "../../fixtures/create_vpc",
    "../../fixtures/create_network_segment",
))]
async fn test_dpu_heartbeat(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = pool.begin().await.unwrap();

    // create_dpu_machine runs record_dpu_network_status, so machine should be healthy
    let dpu_machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert!(matches!(dpu_machine.has_healthy_network(), Ok(true)));

    // Tell state handler to mark DPU as unhealthy after 1 second
    let handler = MachineStateHandler::new(chrono::Duration::seconds(1));
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler
    let services = Arc::new(env.state_handler_services());
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
    )
    .await;

    // Now the network should be marked unhealthy
    let dpu_machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert!(matches!(dpu_machine.has_healthy_network(), Ok(false)));

    Ok(())
}
