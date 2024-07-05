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
use carbide::cfg::default_dpu_models;
use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::db::machine_interface::MachineInterface;
use carbide::model::machine::{
    InstanceState, MachineLastRebootRequestedMode, MachineState, ManagedHostState, ReprovisionState,
};
use carbide::state_controller::machine::handler::MachineStateHandler;
use common::api_fixtures::create_test_env;
use rpc::forge::dpu_reprovisioning_request::Mode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{DpuResetRequest, MachineArchitecture};

pub mod common;

use crate::common::api_fixtures::dpu::{
    create_dpu_machine, create_dpu_machine_in_waiting_for_network_install,
};
use crate::common::api_fixtures::instance::{create_instance, single_interface_network_config};
use crate::common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;
use crate::common::api_fixtures::{
    create_managed_host, discovery_completed, forge_agent_control, network_configured,
    update_time_params, TestEnv,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_set_clear_reprovisioning(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
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
    let env = create_test_env(pool).await;
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

    let last_reboot_requested_time = dpu.last_reboot_requested();

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

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

    let dpu_rpc_id = rpc::common::MachineId {
        id: dpu_machine_id.to_string(),
    };
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::PowerDown,
            ..
        }
    ));
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
        rpc::common::MachineId {
            id: host_machine_id.to_string(),
        },
    )
    .await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration(handler.clone())
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
    let env = create_test_env(pool).await;
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
    let env = create_test_env(pool).await;
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
    let env = create_test_env(pool).await;
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

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );

    let dpu_rpc_id = rpc::common::MachineId {
        id: dpu_machine_id.to_string(),
    };
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
        rpc::common::MachineId {
            id: host_machine_id.to_string(),
        },
    )
    .await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration(handler.clone())
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
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (_instance_id, instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
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
            machine_id: Some(::rpc::common::MachineId {
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

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage { .. }
        }
    ));

    _ = forge_agent_control(&env, instance.machine_id.clone().unwrap()).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration(handler.clone())
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

    let dpu_rpc_id = rpc::common::MachineId {
        id: dpu_machine_id.to_string(),
    };
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    discovery_completed(&env, dpu_rpc_id.clone(), None).await;

    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                reprovision_state: ReprovisionState::PowerDown,
                ..
            }
        }
    ));

    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
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

    let host_interface_id =
        MachineInterface::find_by_machine_ids(&mut txn, &[host_machine_id.clone()])
            .await
            .unwrap()
            .get(&host_machine_id)
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
            machine_id: Some(::rpc::common::MachineId {
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
            label: None,
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

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage { .. }
        }
    ));

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: MachineArchitecture::X86 as i32,
            interface_id: Some(rpc::Uuid {
                value: host_interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(pxe.pxe_script.contains("scout.efi"));

    _ = forge_agent_control(
        &env,
        current_instance.instances[0].machine_id.clone().unwrap(),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Since DPU reprovisioning is started, we can't allow user to reboot host in between. It
    // should be prevented from cloud itself.

    assert!(env
        .api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: Some(::rpc::common::MachineId {
                id: host_machine_id.to_string(),
            }),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .is_err());

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let dpu_rpc_id = rpc::common::MachineId {
        id: dpu_machine_id.to_string(),
    };

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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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

    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: MachineArchitecture::X86 as i32,
            interface_id: Some(rpc::Uuid {
                value: host_interface_id.clone(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(pxe.pxe_script.contains("exit"));

    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_for_set_but_clear_failed(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
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

    Machine::update_dpu_reprovision_start_time(&dpu_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    assert!(env
        .api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: Some(rpc::MachineId {
                    id: dpu_machine_id.to_string(),
                }),
                mode: rpc::forge::dpu_reprovisioning_request::Mode::Clear as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware: true
            },
        ))
        .await
        .is_err());

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovisioning_requested().is_some(),);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_reboot_retry(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
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

    let last_reboot_requested_time = dpu.last_reboot_requested();

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::FirmwareUpgrade,
            ..
        }
    ));

    txn.commit().await.unwrap();

    // Retry 1
    update_time_params(&env.pool, &dpu, 1).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    txn.commit().await.unwrap();

    // Retry 2
    update_time_params(&env.pool, &dpu, 2).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu_ = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu_.last_reboot_requested().unwrap().time,
        dpu.last_reboot_requested().unwrap().time
    );
    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();

    // Retry 3
    update_time_params(&env.pool, &dpu, 3).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();

    // Retry 4
    update_time_params(&env.pool, &dpu, 4).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::PowerOff
    ));
    txn.commit().await.unwrap();

    // Retry 5
    update_time_params(&env.pool, &dpu, 5).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::PowerOn
    ));
    txn.commit().await.unwrap();

    // Retry 6
    update_time_params(&env.pool, &dpu, 5).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_clear_with_function_call(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();
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

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        Machine::clear_dpu_reprovisioning_request(&mut txn, dpu.id(), true)
            .await
            .is_ok()
    );
    txn.rollback().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    Machine::update_dpu_reprovision_start_time(dpu.id(), &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        Machine::clear_dpu_reprovisioning_request(&mut txn, dpu.id(), true)
            .await
            .is_err()
    );
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_clear_maintenance_when_reprov_is_set(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();
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

    assert!(env
        .api
        .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
            host_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: 1,
            reference: Some("no reference".to_string()),
        }))
        .await
        .is_err());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_reset(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );

    let (dpu_machine_id, host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(&env, &host_sim.config).await;
    let dpu_rpc_machine_id: rpc::MachineId = dpu_machine_id.to_string().into();
    let mut txn = env.pool.begin().await.unwrap();

    let agent_control_response = forge_agent_control(&env, dpu_rpc_machine_id.clone()).await;
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Noop as i32
    );

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler.clone(),
        4,
        &mut txn,
        ManagedHostState::DPUNotReady {
            machine_state: carbide::model::machine::MachineState::WaitingForNetworkConfig,
        },
    )
    .await;
    txn.commit().await.unwrap();

    env.api
        .trigger_dpu_reset(tonic::Request::new(DpuResetRequest {
            dpu_id: Some(rpc::MachineId {
                id: dpu_machine_id.to_string(),
            }),
        }))
        .await
        .unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::Init
        }
    ));

    let mut txn = env.pool.begin().await.unwrap();
    let interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;
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

    assert!(!pxe.pxe_script.contains("exit"));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_reset_fail_in_not_dpunotready_state(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;

    assert!(env
        .api
        .trigger_dpu_reset(tonic::Request::new(DpuResetRequest {
            dpu_id: Some(rpc::MachineId {
                id: dpu_machine_id.to_string(),
            }),
        }))
        .await
        .is_err());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_restart_dpu_reprov(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();
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

    assert!(env
        .api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: Some(rpc::MachineId {
                    id: dpu_machine_id.to_string(),
                }),
                mode: Mode::Restart as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware: false,
            },
        ))
        .await
        .is_err());

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let mut txn = env.pool.begin().await.unwrap();
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

    let restart_time = dpu
        .reprovisioning_requested()
        .unwrap()
        .restart_reprovision_requested_at;
    txn.commit().await.unwrap();

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Restart, true).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();
    assert_ne!(
        restart_time,
        dpu.reprovisioning_requested()
            .unwrap()
            .restart_reprovision_requested_at
    );

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::FirmwareUpgrade,
            ..
        }
    ));

    // change the mode
    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Restart, false).await;
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();
    assert_ne!(
        restart_time,
        dpu.reprovisioning_requested()
            .unwrap()
            .restart_reprovision_requested_at
    );

    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUReprovision {
            reprovision_state: ReprovisionState::WaitingForNetworkInstall,
            ..
        }
    ));
}
