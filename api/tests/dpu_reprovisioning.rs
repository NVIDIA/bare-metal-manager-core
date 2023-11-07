/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::sync::Arc;

use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::db::machine_interface::MachineInterface;
use carbide::model::machine::{InstanceState, MachineState, ManagedHostState, ReprovisionState};
use carbide::state_controller::machine::handler::MachineStateHandler;
use carbide::state_controller::metrics::IterationMetrics;
use common::api_fixtures::create_test_env;
use rpc::forge::dpu_reprovisioning_request::Mode;
use rpc::forge::forge_server::Forge;

pub mod common;

use crate::common::api_fixtures::dpu::create_dpu_machine;
use crate::common::api_fixtures::instance::{create_instance, single_interface_network_config};
use crate::common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;
use crate::common::api_fixtures::{
    create_managed_host, discovery_completed, forge_agent_control, network_configured,
    run_state_controller_iteration, TestEnv,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_set_clear_reprovisioning(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovisioning_requested().is_none(),);

    env.api
        .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
            host_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: 0,
            reference: Some("no reference".to_string()),
        }))
        .await
        .unwrap();

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.reprovisioning_requested().unwrap().initiator,
        "AdminCli"
    );

    let res = env
        .api
        .list_dpu_waiting_for_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningListRequest {},
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(res.dpus.len(), 1);
    assert_eq!(
        res.dpus[0].id.clone().unwrap().to_string(),
        dpu_machine_id.to_string()
    );

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Clear, true).await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovisioning_requested().is_none(),);
}

async fn trigger_dpu_reprovisioning(
    env: &TestEnv,
    dpu_id: String,
    mode: Mode,
    update_firmware: bool,
) {
    env.api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: Some(rpc::MachineId {
                    id: dpu_id.to_string(),
                }),
                mode: mode as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware,
            },
        ))
        .await
        .unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovisioning_requested().is_none(),);

    let interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    env.api
        .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
            host_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: 0,
            reference: Some("no reference".to_string()),
        }))
        .await
        .unwrap();

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.reprovisioning_requested().unwrap().initiator,
        "AdminCli"
    );

    let handler = MachineStateHandler::new(chrono::Duration::minutes(5), true);
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::FirmwareUpgrade,
            ..
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_ne!(pxe.pxe_script, "exit".to_string());

    let dpu_rpc_id = rpc::forge::MachineId {
        id: dpu_machine_id.to_string(),
    };
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::WaitingForNetworkInstall,
            ..
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_ne!(pxe.pxe_script, "exit".to_string());
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::BufferTime,
            ..
        }
    ));
    txn.commit().await.unwrap();

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(pxe.pxe_script, "exit".to_string());

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::WaitingForNetworkConfig,
            ..
        }
    ));
    txn.commit().await.unwrap();
    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(pxe.pxe_script, "exit".to_string());

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    let _ = network_configured(&env, &dpu_machine_id).await;
    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered
        }
    ));
    txn.commit().await.unwrap();

    let _response = forge_agent_control(
        &env,
        rpc::forge::MachineId {
            id: host_machine_id.to_string(),
        },
    )
    .await;
    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_reprovisioning_fail_if_maintenance_not_set(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (_host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovisioning_requested().is_none(),);

    assert!(env
        .api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: Some(rpc::MachineId {
                    id: dpu_machine_id.to_string(),
                }),
                mode: rpc::forge::dpu_reprovisioning_request::Mode::Set as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware: true
            },
        ))
        .await
        .is_err());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_reprovisioning_fail_if_state_is_not_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = create_dpu_machine(&env, &host_sim.config).await;

    assert!(env
        .api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: Some(rpc::MachineId {
                    id: dpu_machine_id.to_string(),
                }),
                mode: rpc::forge::dpu_reprovisioning_request::Mode::Set as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware: true
            },
        ))
        .await
        .is_err());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_reprovisioning_with_no_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovisioning_requested().is_none(),);

    let interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    env.api
        .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
            host_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: 0,
            reference: Some("no reference".to_string()),
        }))
        .await
        .unwrap();

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, false).await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.reprovisioning_requested().unwrap().initiator,
        "AdminCli"
    );

    let handler = MachineStateHandler::new(chrono::Duration::minutes(5), true);
    let services = Arc::new(env.state_handler_services());

    let dpu_rpc_id = rpc::forge::MachineId {
        id: dpu_machine_id.to_string(),
    };
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::WaitingForNetworkInstall,
            ..
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_ne!(pxe.pxe_script, "exit".to_string());
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::BufferTime,
            ..
        }
    ));
    txn.commit().await.unwrap();
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Retry as i32
    );

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::WaitingForNetworkConfig,
            ..
        }
    ));
    txn.commit().await.unwrap();
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    let _ = network_configured(&env, &dpu_machine_id).await;
    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered
        }
    ));
    txn.commit().await.unwrap();

    let _response = forge_agent_control(
        &env,
        rpc::forge::MachineId {
            id: host_machine_id.to_string(),
        },
    )
    .await;
    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_reprov_with_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (_instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec![],
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    env.api
        .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
            host_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: 0,
            reference: Some("no reference".to_string()),
        }))
        .await
        .unwrap();

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: Some(::rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .unwrap();

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.reprovisioning_requested().unwrap().initiator,
        "AdminCli"
    );

    let handler = MachineStateHandler::new(chrono::Duration::minutes(5), true);
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::FirmwareUpgrade,
                ..
            }
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_ne!(pxe.pxe_script, "exit".to_string());

    let dpu_rpc_id = rpc::forge::MachineId {
        id: dpu_machine_id.to_string(),
    };
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                ..
            }
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_ne!(pxe.pxe_script, "exit".to_string());
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::BufferTime,
                ..
            }
        }
    ));
    txn.commit().await.unwrap();

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(pxe.pxe_script, "exit".to_string());

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::WaitingForNetworkConfig,
                ..
            }
        }
    ));
    txn.commit().await.unwrap();
    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(pxe.pxe_script, "exit".to_string());

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    let _ = network_configured(&env, &dpu_machine_id).await;
    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_reprov_without_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec![],
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    env.api
        .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
            host_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: 0,
            reference: Some("no reference".to_string()),
        }))
        .await
        .unwrap();

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, false).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: Some(::rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .unwrap();

    let current_instance = env
        .api
        .find_instances(tonic::Request::new(rpc::InstanceSearchQuery {
            id: Some(rpc::Uuid {
                value: instance_id.to_string(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(current_instance.instances[0]
        .status
        .as_ref()
        .unwrap()
        .update
        .is_some());

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.reprovisioning_requested().unwrap().initiator,
        "AdminCli"
    );

    let handler = MachineStateHandler::new(chrono::Duration::minutes(5), true);
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                ..
            }
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_ne!(pxe.pxe_script, "exit".to_string());
    let dpu_rpc_id = rpc::forge::MachineId {
        id: dpu_machine_id.to_string(),
    };
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::BufferTime,
                ..
            }
        }
    ));
    txn.commit().await.unwrap();

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(pxe.pxe_script, "exit".to_string());

    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::WaitingForNetworkConfig,
                ..
            }
        }
    ));
    txn.commit().await.unwrap();
    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(pxe.pxe_script, "exit".to_string());

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    let _ = network_configured(&env, &dpu_machine_id).await;
    let mut txn = env.pool.begin().await.unwrap();
    run_state_controller_iteration(
        &services,
        &env.pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();
}
