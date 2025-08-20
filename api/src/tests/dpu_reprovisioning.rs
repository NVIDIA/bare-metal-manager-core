use std::collections::HashMap;

use forge_uuid::machine::MachineId;
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
use crate::db::{self, machine::MachineSearchConfig};
use crate::model::machine::InstallDpuOsState;
use crate::model::{
    instance::status::tenant::TenantState,
    machine::{
        DpuInitState, FailureDetails, InstanceState, MachineLastRebootRequestedMode, MachineState,
        ManagedHostState, ReprovisionState,
    },
};
use crate::state_controller::machine::handler::MachineStateHandlerBuilder;
use chrono::Utc;
use common::api_fixtures::create_managed_host_multi_dpu;
use common::api_fixtures::{create_test_env, reboot_completed};
use rpc::forge::MachineArchitecture;
use rpc::forge::dpu_reprovisioning_request::Mode;
use rpc::forge::forge_server::Forge;

use crate::tests::common;

use crate::tests::common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;
use crate::tests::common::api_fixtures::instance::TestInstance;
use crate::tests::common::api_fixtures::{
    TestEnv, create_managed_host, discovery_completed, forge_agent_control, network_configured,
    update_time_params,
};

#[crate::sqlx_test]
async fn test_dpu_for_set_clear_reprovisioning(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&dpu.reprovision_requested.unwrap().initiator, "AdminCli");

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

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);
}

pub async fn trigger_dpu_reprovisioning(
    env: &TestEnv,
    machine_id: String,
    mode: Mode,
    update_firmware: bool,
) {
    env.api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: None,
                machine_id: Some(rpc::MachineId {
                    id: machine_id.to_string(),
                }),
                mode: mode as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware,
            },
        ))
        .await
        .unwrap();
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    let last_reboot_requested_time = dpu.last_reboot_requested;

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested.unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    crate::model::machine::ReprovisionState::InstallDpuOs {
                        substate: InstallDpuOsState::InstallingBFB
                    }
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    crate::model::machine::ReprovisionState::WaitingForNetworkInstall,
                )]),
            },
        }
    );

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

    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id.into();
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::PoweringOffHost)]),
            },
        }
    );
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

    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::PowerDown)]),
            },
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::VerifyFirmareVersions)]),
            },
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkConfig
                )]),
            },
        }
    );
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

    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    network_configured(&env, &vec![dpu_machine_id]).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHostBmc)]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHost)]),
            },
        }
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));
    txn.commit().await.unwrap();

    let _response = forge_agent_control(&env, host_machine_id.into()).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_fail_if_maintenance_not_set(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: Some(rpc::MachineId {
                        id: dpu_machine_id.to_string(),
                    }),
                    mode: rpc::forge::dpu_reprovisioning_request::Mode::Set as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: true
                },
            ))
            .await
            .is_err()
    );
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_fail_if_state_is_not_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_, dpu_machine_id) = create_managed_host(&env).await;

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: Some(rpc::MachineId {
                        id: dpu_machine_id.to_string(),
                    }),
                    mode: rpc::forge::dpu_reprovisioning_request::Mode::Set as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: true
                },
            ))
            .await
            .is_err()
    );
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_no_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, false).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id.into();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::InstallDpuOs {
                        substate: InstallDpuOsState::InstallingBFB
                    }
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall
                )]),
            },
        }
    );

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
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::PoweringOffHost)]),
            },
        }
    );
    txn.commit().await.unwrap();
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::PowerDown)]),
            },
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::VerifyFirmareVersions)]),
            },
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkConfig
                )]),
            },
        }
    );
    txn.commit().await.unwrap();
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    network_configured(&env, &vec![dpu_machine_id]).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHostBmc)]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHost)]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));

    let _response = forge_agent_control(&env, host_machine_id.into()).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_instance_reprov_with_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: Some(host_machine_id.into()),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .unwrap();

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage { .. }
        }
    ));

    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );

    _ = forge_agent_control(&env, instance.machine_id.clone().unwrap()).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkInstall
                    )]),
                },
            }
        }
    );

    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );

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
    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id.into();
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PoweringOffHost)]),
                },
            }
        }
    );

    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );

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

    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PowerDown)]),
                },
            }
        }
    );

    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::VerifyFirmareVersions
                    )]),
                },
            }
        }
    );

    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkConfig
                    )]),
                },
            }
        }
    );
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );
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

    assert!(pxe.pxe_script.contains("exit"));

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    network_configured(&env, &vec![dpu_machine_id]).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHostBmc)]),
                },
            }
        }
    );

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHost)]),
                },
            }
        }
    );
    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        // TODO:  This should become `Updating` after we finish
        // deprecating Dpu/Host reprov states. DpuReprovisioning
        // is just being used as a temporary alias for a generic
        // `Updating`.
        TenantState::DpuReprovisioning
    );
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    // Check that the tenant state is still what we expect now that reprovisioning has completed.
    let db_instance = db::instance::Instance::find_by_id(&mut txn, instance_id)
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));

    let device_id_maps = host.get_dpu_device_and_id_mappings().unwrap();
    assert_eq!(
        db_instance
            .derive_status(device_id_maps.1, host.state.clone().value, None, None)
            .unwrap()
            .tenant
            .unwrap()
            .state,
        TenantState::Configuring
    );
}

#[crate::sqlx_test]
async fn test_instance_reprov_without_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let host_interface_id =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id])
            .await
            .unwrap()
            .get(&host_machine_id)
            .unwrap()[0]
            .id
            .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, false).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: Some(host_machine_id.into()),
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

    assert!(
        current_instance.instances[0]
            .status
            .as_ref()
            .unwrap()
            .update
            .is_some()
    );

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
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

    assert!(
        env.api
            .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
                machine_id: Some(host_machine_id.into()),
                apply_updates_on_reboot: true,
                boot_with_custom_ipxe: false,
                operation: 0,
            }))
            .await
            .is_err()
    );

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id.into();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkInstall
                    )]),
                },
            }
        }
    );

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PoweringOffHost)]),
                },
            }
        }
    );
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

    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PowerDown)]),
                },
            }
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::VerifyFirmareVersions
                    )]),
                },
            }
        }
    );

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkConfig
                    )]),
                },
            }
        }
    );
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

    assert!(
        pxe.pxe_script.contains(
            "Current state: Assigned/Reprovision/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
        )
    );

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    let _ = network_configured(&env, &vec![dpu_machine_id]).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHostBmc)]),
                },
            }
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHost)]),
                },
            }
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
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
}

#[crate::sqlx_test]
async fn test_dpu_for_set_but_clear_failed(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");

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

    db::machine::update_dpu_reprovision_start_time(&dpu_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: Some(rpc::MachineId {
                        id: dpu_machine_id.to_string(),
                    }),
                    mode: rpc::forge::dpu_reprovisioning_request::Mode::Clear as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: true
                },
            ))
            .await
            .is_err()
    );

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_some(),);
}

#[crate::sqlx_test]
async fn test_reboot_retry(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();

    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested.unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall
                )]),
            },
        }
    );

    txn.commit().await.unwrap();

    // no reboots should be forced during firmware update
    for _ in 1..5 {
        update_time_params(&env.pool, &dpu, 1, None).await;
        env.run_machine_state_controller_iteration().await;

        let mut txn = env.pool.begin().await.unwrap();
        let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            dpu.current_state(),
            &ManagedHostState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkInstall
                    )]),
                },
            }
        );
    }

    reboot_completed(
        &env,
        rpc::MachineId {
            id: dpu.id.to_string(),
        },
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall
                )]),
            },
        }
    );

    txn.rollback().await.unwrap();

    update_time_params(&env.pool, &dpu, 1, None).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall
                )]),
            },
        }
    );

    txn.rollback().await.unwrap();

    update_time_params(&env.pool, &dpu, 1, None).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall
                )]),
            },
        }
    );

    txn.rollback().await.unwrap();

    // Retry 1
    update_time_params(&env.pool, &dpu, 1, None).await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    txn.commit().await.unwrap();

    // Retry 2
    update_time_params(&env.pool, &dpu, 2, None).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu_ = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu_.last_reboot_requested.as_ref().unwrap().time,
        dpu.last_reboot_requested.as_ref().unwrap().time
    );
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();

    // Retry 3
    update_time_params(&env.pool, &dpu, 3, None).await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();

    // Retry 4
    update_time_params(&env.pool, &dpu, 4, None).await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::PowerOff
    ));
    txn.commit().await.unwrap();

    // Retry 5
    update_time_params(&env.pool, &dpu, 5, None).await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::PowerOn
    ));
    txn.commit().await.unwrap();

    // Retry 6
    update_time_params(&env.pool, &dpu, 5, None).await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_reboot_no_retry_during_firmware_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();

    let handler = MachineStateHandlerBuilder::builder()
        .hardware_models(env.config.get_firmware_config())
        .dpu_up_threshold(chrono::Duration::minutes(5))
        .dpu_nic_firmware_initial_update_enabled(true)
        .dpu_nic_firmware_reprovision_update_enabled(true)
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .build();
    env.override_machine_state_controller_handler(handler).await;

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::InstallDpuOs {
                        substate: InstallDpuOsState::InstallingBFB
                    }
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall,
                )]),
            },
        }
    );

    txn.commit().await.unwrap();

    reboot_completed(
        &env,
        rpc::MachineId {
            id: dpu.id.to_string(),
        },
    )
    .await;

    env.run_machine_state_controller_iteration().await;

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = env.pool.begin().await.unwrap();
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let last_reboot_requested = host.last_reboot_requested.as_ref().unwrap();

    tracing::info!("power request: {:?}", last_reboot_requested);
    assert!(matches!(
        host.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall
                )]),
            },
        }
    );

    txn.rollback().await.unwrap();
}

#[crate::sqlx_test]
async fn test_clear_with_function_call(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();
    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::machine::clear_dpu_reprovisioning_request(&mut txn, &dpu.id, true)
            .await
            .is_ok()
    );
    txn.rollback().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    db::machine::update_dpu_reprovision_start_time(&dpu.id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::machine::clear_dpu_reprovisioning_request(&mut txn, &dpu.id, true)
            .await
            .is_err()
    );
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_clear_maintenance_when_reprov_is_set(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();
    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    assert!(
        env.api
            .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
                host_id: Some(rpc::MachineId {
                    id: host_machine_id.to_string(),
                }),
                operation: 1,
                reference: Some("no reference".to_string()),
            }))
            .await
            .is_err()
    );
}

#[crate::sqlx_test]
async fn test_dpu_reset(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();

    let (dpu_machine_id, host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(&env, &host_config).await;
    let dpu_rpc_machine_id: rpc::MachineId = dpu_machine_id.to_string().into();

    let agent_control_response = forge_agent_control(&env, dpu_rpc_machine_id.clone()).await;
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Noop as i32
    );

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        ManagedHostState::DPUInit {
            dpu_states: crate::model::machine::DpuInitStates {
                states: HashMap::from([(dpu_machine_id, DpuInitState::WaitingForNetworkConfig)]),
            },
        },
    )
    .await;
}

#[crate::sqlx_test]
async fn test_restart_dpu_reprov(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();
    assert!(dpu.reprovision_requested.is_none(),);

    mark_machine_for_updates(&env, &host_machine_id).await;

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: Some(rpc::MachineId {
                        id: host_machine_id.to_string(),
                    }),
                    mode: Mode::Restart as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: false,
                },
            ))
            .await
            .is_err()
    );

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, true).await;

    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.pool.begin().await.unwrap();

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall,
                )]),
            }
        }
    );

    let restart_time = dpu
        .reprovision_requested
        .as_ref()
        .unwrap()
        .restart_reprovision_requested_at;
    txn.commit().await.unwrap();

    trigger_dpu_reprovisioning(&env, host_machine_id.to_string(), Mode::Restart, true).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();
    assert_ne!(
        restart_time,
        dpu.reprovision_requested
            .as_ref()
            .unwrap()
            .restart_reprovision_requested_at
    );

    let _expected_state = ManagedHostState::DPUReprovision {
        dpu_states: crate::model::machine::DpuReprovisionStates {
            states: HashMap::from([(dpu_machine_id, ReprovisionState::WaitingForNetworkInstall)]),
        },
    };
    assert!(matches!(dpu.current_state(), _expected_state));

    // change the mode
    trigger_dpu_reprovisioning(&env, host_machine_id.to_string(), Mode::Restart, false).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();
    assert_ne!(
        restart_time,
        dpu.reprovision_requested
            .as_ref()
            .unwrap()
            .restart_reprovision_requested_at
    );

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    dpu_machine_id,
                    ReprovisionState::WaitingForNetworkInstall,
                )]),
            },
        }
    );
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade_multidpu_onedpu_reprov(
    pool: sqlx::PgPool,
) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _) = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    let dpu_machine_id_1 = dpus[0].id;
    let dpu_machine_id_2 = dpus[1].id;

    assert!(dpus[0].reprovision_requested.is_none(),);

    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id_1])
        .await
        .unwrap()
        .get(&dpu_machine_id_1)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id_1.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (
                        dpu_machine_id_1,
                        ReprovisionState::InstallDpuOs {
                            substate: InstallDpuOsState::InstallingBFB
                        }
                    ),
                    (dpu_machine_id_2, ReprovisionState::NotUnderReprovision)
                ]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::WaitingForNetworkInstall,),
                    (dpu_machine_id_2, ReprovisionState::NotUnderReprovision)
                ]),
            },
        }
    );

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

    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id_1.into();
    let _response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::PoweringOffHost),
                    (dpu_machine_id_2, ReprovisionState::PoweringOffHost)
                ]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::PowerDown),
                    (dpu_machine_id_2, ReprovisionState::PowerDown)
                ]),
            },
        }
    );
    txn.rollback().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::VerifyFirmareVersions),
                    (dpu_machine_id_2, ReprovisionState::NotUnderReprovision),
                ]),
            },
        }
    );
    txn.rollback().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::WaitingForNetworkConfig),
                    (dpu_machine_id_2, ReprovisionState::NotUnderReprovision),
                ]),
            },
        }
    );

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

    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::WaitingForNetworkConfig),
                    (dpu_machine_id_2, ReprovisionState::NotUnderReprovision)
                ]),
            },
        }
    );
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

    assert!(pxe.pxe_script.contains(
        "This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
    ));

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    network_configured(&env, &vec![dpu_machine_id_1, dpu_machine_id_2]).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::RebootHostBmc),
                    (dpu_machine_id_2, ReprovisionState::RebootHostBmc)
                ]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::RebootHost),
                    (dpu_machine_id_2, ReprovisionState::RebootHost)
                ]),
            },
        }
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));
    txn.commit().await.unwrap();

    let _response = forge_agent_control(&env, host_machine_id.into()).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade_multidpu_bothdpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _) = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpus = db::machine::find_dpus_by_host_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();
    let dpu_machine_id_1 = dpus[0].id;
    let dpu_machine_id_2 = dpus[1].id;

    assert!(dpus[0].reprovision_requested.is_none(),);

    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id_1])
        .await
        .unwrap()
        .get(&dpu_machine_id_1)
        .unwrap()[0]
        .id
        .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id_1.to_string(), Mode::Set, true).await;
    trigger_dpu_reprovisioning(&env, dpu_machine_id_2.to_string(), Mode::Set, true).await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (
                        dpu_machine_id_1,
                        ReprovisionState::InstallDpuOs {
                            substate: InstallDpuOsState::InstallingBFB
                        }
                    ),
                    (
                        dpu_machine_id_2,
                        ReprovisionState::InstallDpuOs {
                            substate: InstallDpuOsState::InstallingBFB
                        }
                    )
                ]),
            },
        }
    );

    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::WaitingForNetworkInstall),
                    (dpu_machine_id_2, ReprovisionState::WaitingForNetworkInstall)
                ]),
            },
        }
    );

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

    let dpu_rpc_id_1: rpc::common::MachineId = dpu_machine_id_1.into();
    let dpu_rpc_id_2: rpc::common::MachineId = dpu_machine_id_2.into();

    let _response = forge_agent_control(&env, dpu_rpc_id_1.clone()).await;
    let _response = forge_agent_control(&env, dpu_rpc_id_2.clone()).await;
    discovery_completed(&env, dpu_rpc_id_1.clone()).await;
    discovery_completed(&env, dpu_rpc_id_2.clone()).await;

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::PoweringOffHost),
                    (dpu_machine_id_2, ReprovisionState::PoweringOffHost)
                ]),
            },
        }
    );

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

    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::PowerDown),
                    (dpu_machine_id_2, ReprovisionState::PowerDown)
                ]),
            },
        }
    );
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::VerifyFirmareVersions),
                    (dpu_machine_id_2, ReprovisionState::VerifyFirmareVersions)
                ]),
            },
        }
    );
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::WaitingForNetworkConfig),
                    (dpu_machine_id_2, ReprovisionState::WaitingForNetworkConfig)
                ]),
            },
        }
    );
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

    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let response = forge_agent_control(&env, dpu_rpc_id_1.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    network_configured(&env, &vec![dpu_machine_id_1, dpu_machine_id_2]).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::RebootHostBmc),
                    (dpu_machine_id_2, ReprovisionState::RebootHostBmc)
                ]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::DPUReprovision {
            dpu_states: crate::model::machine::DpuReprovisionStates {
                states: HashMap::from([
                    (dpu_machine_id_1, ReprovisionState::RebootHost),
                    (dpu_machine_id_2, ReprovisionState::RebootHost)
                ]),
            },
        }
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));
    txn.commit().await.unwrap();

    let _response = forge_agent_control(&env, host_machine_id.into()).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id_1, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_instance_reprov_restart_failed(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id])
        .await
        .unwrap()
        .get(&dpu_machine_id)
        .unwrap()[0]
        .id
        .to_string();

    let host_interface_id =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id])
            .await
            .unwrap()
            .get(&host_machine_id)
            .unwrap()[0]
            .id
            .to_string();

    let arch = rpc::forge::MachineArchitecture::Arm;

    mark_machine_for_updates(&env, &host_machine_id).await;

    trigger_dpu_reprovisioning(&env, dpu_machine_id.to_string(), Mode::Set, false).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: Some(host_machine_id.into()),
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

    assert!(
        current_instance.instances[0]
            .status
            .as_ref()
            .unwrap()
            .update
            .is_some()
    );

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
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

    assert!(
        env.api
            .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
                machine_id: Some(host_machine_id.into()),
                apply_updates_on_reboot: true,
                boot_with_custom_ipxe: false,
                operation: 0,
            }))
            .await
            .is_err()
    );

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id.into();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkInstall
                    )]),
                },
            }
        }
    );

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
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PoweringOffHost)]),
                },
            }
        }
    );
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

    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PowerDown)]),
                },
            }
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::VerifyFirmareVersions
                    )]),
                },
            }
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkConfig
                    )]),
                },
            }
        }
    );
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

    assert!(
        pxe.pxe_script.contains(
            "Current state: Assigned/Reprovision/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
        )
    );

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let failed_at = Utc::now();
    let deserialized = FailureDetails {
        cause: crate::model::machine::FailureCause::NVMECleanFailed {
            err: "error1".to_string(),
        },
        source: crate::model::machine::FailureSource::Scout,
        failed_at,
    };

    db::machine::update_failure_details(&dpu, &mut txn, deserialized)
        .await
        .unwrap();

    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::Failed {
                details: FailureDetails {
                    cause: crate::model::machine::FailureCause::NVMECleanFailed {
                        err: "error1".to_string()
                    },
                    source: crate::model::machine::FailureSource::Scout,
                    failed_at
                },
                machine_id: dpu.id
            }
        }
    );

    txn.rollback().await.unwrap();

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: Some(rpc::MachineId {
                        id: host_machine_id.to_string(),
                    }),
                    mode: Mode::Restart as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: false,
                },
            ))
            .await
            .is_ok()
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::InstallDpuOs {
                            substate: InstallDpuOsState::InstallingBFB,
                        },
                    )]),
                },
            }
        }
    );
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let dpu_rpc_id: ::rpc::common::MachineId = dpu_machine_id.into();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkInstall
                    )]),
                },
            }
        }
    );
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

    assert!(pxe.pxe_script.contains("internal/aarch64/carbide.efi"));
    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    discovery_completed(&env, dpu_rpc_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PoweringOffHost)]),
                },
            }
        }
    );
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

    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::PowerDown)]),
                },
            }
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::VerifyFirmareVersions
                    )]),
                },
            }
        }
    );
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(
                        dpu_machine_id,
                        ReprovisionState::WaitingForNetworkConfig
                    )]),
                },
            }
        }
    );
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

    assert!(
        pxe.pxe_script.contains(
            "Current state: Assigned/Reprovision/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
        )
    );

    let response = forge_agent_control(&env, dpu_rpc_id.clone()).await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    network_configured(&env, &vec![dpu_machine_id]).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHostBmc)]),
                },
            }
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: crate::model::machine::DpuReprovisionStates {
                    states: HashMap::from([(dpu_machine_id, ReprovisionState::RebootHost)]),
                },
            }
        }
    );

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
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
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_cannot_restart_if_not_started(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    mark_machine_for_updates(&env, &host_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu.reprovision_requested.is_none(),);

    match env
        .api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: None,
                machine_id: Some(rpc::MachineId {
                    id: host_machine_id.to_string(),
                }),
                mode: rpc::forge::dpu_reprovisioning_request::Mode::Restart as i32,
                initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                update_firmware: true,
            },
        ))
        .await
    {
        Ok(_) => panic!("Request to restart provisioning should have failed"),
        Err(e) => {
            assert!(matches!(e.code(), tonic::Code::InvalidArgument));
        }
    }
}

async fn mark_machine_for_updates(env: &TestEnv, host_machine_id: &MachineId) {
    env.api
        .insert_health_report_override(tonic::Request::new(
            rpc::forge::InsertHealthReportOverrideRequest {
                machine_id: Some(host_machine_id.to_string().into()),
                r#override: Some(rpc::forge::HealthReportOverride {
                    report: Some(
                        health_report::HealthReport {
                            source: "host-update".to_string(),
                            observed_at: None,
                            successes: Vec::new(),
                            alerts: vec![health_report::HealthProbeAlert {
                                id: "HostUpdateInProgress".parse().unwrap(),
                                target: None,
                                in_alert_since: None,
                                message: "Update".to_string(),
                                tenant_message: None,
                                classifications: vec![
                                    health_report::HealthAlertClassification::prevent_allocations(),
                                ],
                            }],
                        }
                        .into(),
                    ),
                    mode: rpc::forge::OverrideMode::Merge.into(),
                }),
            },
        ))
        .await
        .unwrap();
}
