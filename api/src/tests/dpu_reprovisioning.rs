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

use crate::db;
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
use std::collections::HashMap;

use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;
use crate::tests::common::api_fixtures::managed_host::ManagedHost;
use crate::tests::common::api_fixtures::{
    create_managed_host, forge_agent_control, update_time_params,
};

#[crate::sqlx_test]
async fn test_dpu_for_set_clear_reprovisioning(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

    let dpu = mh.dpu().db_machine(&mut txn).await;

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
        mh.dpu().machine_id().to_string()
    );

    mh.dpu().trigger_dpu_reprovisioning(Mode::Clear, true).await;

    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none());
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert!(dpu.reprovision_requested.is_none(),);

    let dpu_interface = mh.dpu().first_interface(&mut txn).await;
    let dpu_arch = rpc::forge::MachineArchitecture::Arm;

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(&dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    let last_reboot_requested_time = dpu.last_reboot_requested;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_ne!(
        dpu.last_reboot_requested.unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::InstallDpuOs {
            substate: InstallDpuOsState::InstallingBFB
        }),
    );

    env.run_machine_state_controller_iteration().await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert_ne!(pxe.pxe_script, "exit".to_string());

    let _response = mh.dpu().forge_agent_control().await;
    mh.dpu().discovery_completed().await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::PoweringOffHost)
    );
    txn.commit().await.unwrap();

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    for state in [
        ReprovisionState::PowerDown,
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(dpu.current_state(), &mh.new_dpu_reprovision_state(state));
    }

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );

    mh.network_configured(&env).await;
    for state in [
        ReprovisionState::RebootHostBmc,
        ReprovisionState::RebootHost,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(dpu.current_state(), &mh.new_dpu_reprovision_state(state));
    }

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));

    let _response = mh.host().forge_agent_control().await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_fail_if_maintenance_not_set(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none(),);

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: mh.dpu().machine_id().into(),
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
    let (_, dpu_machine_id) = create_managed_host(&env).await.into();

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: dpu_machine_id.into(),
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
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none(),);

    let dpu_interface = mh.dpu().first_interface(&mut txn).await;
    let dpu_arch = rpc::forge::MachineArchitecture::Arm;

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, false).await;

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::InstallDpuOs {
            substate: InstallDpuOsState::InstallingBFB
        }),
    );

    env.run_machine_state_controller_iteration().await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert_ne!(pxe.pxe_script, "exit".to_string());

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    mh.dpu().discovery_completed().await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::PoweringOffHost)
    );

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );

    for state in [
        ReprovisionState::PowerDown,
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(dpu.current_state(), &mh.new_dpu_reprovision_state(state));
    }

    let _response = mh.dpu().forge_agent_control().await;
    mh.network_configured(&env).await;
    for state in [
        ReprovisionState::RebootHostBmc,
        ReprovisionState::RebootHost,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(dpu.current_state(), &mh.new_dpu_reprovision_state(state));
    }

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));

    let _response = mh.host().forge_agent_control().await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
}

#[crate::sqlx_test]
async fn test_instance_reprov_with_firmware_upgrade(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let (tinstance, rpc_instance) = mh
        .instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build_and_return()
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_interface = mh.dpu().first_interface(&mut txn).await;
    let dpu_arch = rpc::forge::MachineArchitecture::Arm;

    mh.mark_machine_for_updates().await;
    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: mh.id.into(),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .unwrap();

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage { .. }
        }
    ));

    let host = mh.host().db_machine(&mut txn).await;

    // Check that the tenant state is what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;

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

    _ = forge_agent_control(&env, rpc_instance.machine_id().into()).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::WaitingForNetworkInstall),
    );

    let host = mh.host().db_machine(&mut txn).await;

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;

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

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert_ne!(pxe.pxe_script, "exit".to_string());

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    mh.dpu().discovery_completed().await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::PoweringOffHost),
    );

    let host = mh.host().db_machine(&mut txn).await;
    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;

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

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::PowerDown)
    );

    let host = mh.host().db_machine(&mut txn).await;

    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;

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
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::VerifyFirmareVersions)
    );
    let host = mh.host().db_machine(&mut txn).await;
    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;
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
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::WaitingForNetworkConfig)
    );
    let host = mh.host().db_machine(&mut txn).await;
    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;
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

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(pxe.pxe_script.contains("exit"));

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    mh.network_configured(&env).await;

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;
    let host = mh.host().db_machine(&mut txn).await;
    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;
    txn.commit().await.unwrap();
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::RebootHostBmc)
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
    let dpu = mh.dpu().db_machine(&mut txn).await;
    let host = mh.host().db_machine(&mut txn).await;
    // Check that the tenant state is still what we expect now that reprovisioning has started.
    let db_instance = tinstance.db_instance(&mut txn).await;
    txn.commit().await.unwrap();
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::RebootHost),
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
    let dpu = mh.dpu().db_machine(&mut txn).await;
    let host = mh.host().db_machine(&mut txn).await;
    // Check that the tenant state is still what we expect now that reprovisioning has completed.
    let db_instance = tinstance.db_instance(&mut txn).await;
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
    let mh = create_managed_host(&env).await;

    let tinstance = mh
        .instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_interface = mh.dpu().first_interface(&mut txn).await;
    let host_interface = mh.host().first_interface(&mut txn).await;
    let dpu_arch = MachineArchitecture::Arm;
    let host_arch = MachineArchitecture::X86;

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, false).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: mh.id.into(),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .unwrap();

    let current_instance = tinstance.rpc_instance().await;
    assert!(current_instance.status().inner().update.is_some());

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage { .. }
        }
    ));

    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert!(pxe.pxe_script.contains("scout.efi"));

    _ = forge_agent_control(&env, current_instance.inner().machine_id.clone().unwrap()).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // Since DPU reprovisioning is started, we can't allow user to reboot host in between. It
    // should be prevented from cloud itself.
    assert!(
        env.api
            .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
                machine_id: mh.id.into(),
                apply_updates_on_reboot: true,
                boot_with_custom_ipxe: false,
                operation: 0,
            }))
            .await
            .is_err()
    );
    txn.commit().await.unwrap();

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    mh.dpu().discovery_completed().await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::PoweringOffHost)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    for state in [
        ReprovisionState::PowerDown,
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpu_assigned_reprovision_state(state)
        );
    }

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script.contains(
            "Current state: Assigned/Reprovision/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
        )
    );

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    mh.network_configured(&env).await;

    for state in [
        ReprovisionState::RebootHostBmc,
        ReprovisionState::RebootHost,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpu_assigned_reprovision_state(state)
        );
    }

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));

    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert!(pxe.pxe_script.contains("exit"));
}

#[crate::sqlx_test]
async fn test_dpu_for_set_but_clear_failed(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;
    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
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
    assert_eq!(res.dpus[0].id, mh.dpu().machine_id().into());

    db::machine::update_dpu_reprovision_start_time(mh.dpu().machine_id(), &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: mh.dpu().machine_id().into(),
                    mode: rpc::forge::dpu_reprovisioning_request::Mode::Clear as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: true
                },
            ))
            .await
            .is_err()
    );

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert!(dpu.reprovision_requested.is_some(),);
}

#[crate::sqlx_test]
async fn test_reboot_retry(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;
    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(dpu.reprovision_requested.unwrap().initiator, "AdminCli");
    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_ne!(
        dpu.last_reboot_requested.unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );
    txn.commit().await.unwrap();

    // no reboots should be forced during firmware update
    for _ in 1..5 {
        update_time_params(&env.pool, &dpu, 1, None).await;
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
        );
    }

    reboot_completed(&env, dpu.id.into()).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    update_time_params(&env.pool, &dpu, 1, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    update_time_params(&env.pool, &dpu, 1, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    // Retry 1
    update_time_params(&env.pool, &dpu, 1, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    // Retry 2
    update_time_params(&env.pool, &dpu, 2, None).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu_ = mh.dpu().db_machine(&mut txn).await;

    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
    txn.commit().await.unwrap();

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_ne!(
        dpu_.last_reboot_requested.as_ref().unwrap().time,
        dpu.last_reboot_requested.as_ref().unwrap().time
    );
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    // Retry 3
    update_time_params(&env.pool, &dpu, 3, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    // Retry 4
    update_time_params(&env.pool, &dpu, 4, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::PowerOff
    ));

    // Retry 5
    update_time_params(&env.pool, &dpu, 5, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::PowerOn
    ));

    // Retry 6
    update_time_params(&env.pool, &dpu, 5, None).await;
    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));
}

#[crate::sqlx_test]
async fn test_reboot_no_retry_during_firmware_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

    let dpu = mh.dpu().db_machine(&mut txn).await;
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
        .dpu_enable_secure_boot(true)
        .attestation_enabled(env.attestation_enabled)
        .build();
    env.override_machine_state_controller_handler(handler).await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::InstallDpuOs {
            substate: InstallDpuOsState::InstallingBFB
        })
    );

    env.run_machine_state_controller_iteration().await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    txn.commit().await.unwrap();

    reboot_completed(&env, dpu.id.into()).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    let last_reboot_requested = host.last_reboot_requested.as_ref().unwrap();

    tracing::info!("power request: {:?}", last_reboot_requested);
    assert!(matches!(
        host.last_reboot_requested.as_ref().unwrap().mode,
        MachineLastRebootRequestedMode::Reboot
    ));

    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    txn.rollback().await.unwrap();
}

#[crate::sqlx_test]
async fn test_clear_with_function_call(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    txn.commit().await.unwrap();
    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

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
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    txn.commit().await.unwrap();
    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

    assert!(
        env.api
            .set_maintenance(tonic::Request::new(::rpc::forge::MaintenanceRequest {
                host_id: mh.id.into(),
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
    let dpu_rpc_machine_id: rpc::MachineId = dpu_machine_id.into();

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
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    txn.commit().await.unwrap();
    assert!(dpu.reprovision_requested.is_none(),);

    mh.mark_machine_for_updates().await;

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: mh.id.into(),
                    mode: Mode::Restart as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: false,
                },
            ))
            .await
            .is_err()
    );

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, true).await;

    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.pool.begin().await.unwrap();

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    let restart_time = dpu
        .reprovision_requested
        .as_ref()
        .unwrap()
        .restart_reprovision_requested_at;
    txn.commit().await.unwrap();

    mh.host()
        .trigger_dpu_reprovisioning(Mode::Restart, true)
        .await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_ne!(
        restart_time,
        dpu.reprovision_requested
            .as_ref()
            .unwrap()
            .restart_reprovision_requested_at
    );

    let _expected_state = ManagedHostState::DPUReprovision {
        dpu_states: crate::model::machine::DpuReprovisionStates {
            states: HashMap::from([(
                *mh.dpu().machine_id(),
                ReprovisionState::WaitingForNetworkInstall,
            )]),
        },
    };
    assert!(matches!(dpu.current_state(), _expected_state));

    // change the mode
    mh.host()
        .trigger_dpu_reprovisioning(Mode::Restart, false)
        .await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_ne!(
        restart_time,
        dpu.reprovision_requested
            .as_ref()
            .unwrap()
            .restart_reprovision_requested_at
    );

    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_reprovision_state(ReprovisionState::WaitingForNetworkInstall),
    );
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade_multidpu_onedpu_reprov(
    pool: sqlx::PgPool,
) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpus = mh.dpu_db_machines(&mut txn).await;
    assert!(dpus[0].reprovision_requested.is_none(),);

    let dpu0_interface = mh.dpu_n(0).first_interface(&mut txn).await;
    let dpu_arch = rpc::forge::MachineArchitecture::Arm;

    mh.mark_machine_for_updates().await;

    mh.dpu_n(0)
        .trigger_dpu_reprovisioning(Mode::Set, true)
        .await;

    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpus_reprovision_state(&[
            &ReprovisionState::InstallDpuOs {
                substate: InstallDpuOsState::InstallingBFB
            },
            &ReprovisionState::NotUnderReprovision,
        ])
    );

    env.run_machine_state_controller_iteration().await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpus_reprovision_state(&[
            &ReprovisionState::WaitingForNetworkInstall,
            &ReprovisionState::NotUnderReprovision,
        ])
    );

    let pxe = dpu0_interface.get_pxe_instructions(dpu_arch).await;
    assert_ne!(pxe.pxe_script, "exit".to_string());

    let _response = mh.dpu_n(0).forge_agent_control().await;
    mh.dpu_n(0).discovery_completed().await;

    for state in [
        ReprovisionState::PoweringOffHost,
        ReprovisionState::PowerDown,
    ] {
        let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpus_reprovision_state(&[&state, &state])
        );
    }

    for state in [
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpus_reprovision_state(&[&state, &ReprovisionState::NotUnderReprovision])
        );
    }

    let pxe = dpu0_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpus_reprovision_state(&[
            &ReprovisionState::WaitingForNetworkConfig,
            &ReprovisionState::NotUnderReprovision
        ])
    );

    let pxe = dpu0_interface.get_pxe_instructions(dpu_arch).await;
    assert!(pxe.pxe_script.contains(
        "This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
    ));

    let response = mh.dpu_n(0).forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    mh.network_configured(&env).await;

    for state in [
        ReprovisionState::RebootHostBmc,
        ReprovisionState::RebootHost,
    ] {
        let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpus_reprovision_state(&[&state, &state])
        );
    }

    let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));

    let _response = mh.host().forge_agent_control().await;

    let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_with_firmware_upgrade_multidpu_bothdpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpus = mh.dpu_db_machines(&mut txn).await;
    assert!(dpus[0].reprovision_requested.is_none());

    let dpu0_interface = mh.dpu_n(0).first_interface(&mut txn).await;
    let dpu_arch = rpc::forge::MachineArchitecture::Arm;

    mh.mark_machine_for_updates().await;

    mh.dpu_n(0)
        .trigger_dpu_reprovisioning(Mode::Set, true)
        .await;
    mh.dpu_n(1)
        .trigger_dpu_reprovisioning(Mode::Set, true)
        .await;

    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    let last_reboot_requested_time = dpu.last_reboot_requested.as_ref();

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpus_reprovision_state(&[
            &ReprovisionState::InstallDpuOs {
                substate: InstallDpuOsState::InstallingBFB
            },
            &ReprovisionState::InstallDpuOs {
                substate: InstallDpuOsState::InstallingBFB
            }
        ]),
    );

    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_ne!(
        dpu.last_reboot_requested.as_ref().unwrap().time,
        last_reboot_requested_time.unwrap().time
    );
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpus_reprovision_state(&[
            &ReprovisionState::WaitingForNetworkInstall,
            &ReprovisionState::WaitingForNetworkInstall
        ])
    );

    let pxe = dpu0_interface.get_pxe_instructions(dpu_arch).await;
    assert_ne!(pxe.pxe_script, "exit".to_string());

    mh.dpu_n(0).forge_agent_control().await;
    mh.dpu_n(1).forge_agent_control().await;
    mh.dpu_n(0).discovery_completed().await;
    mh.dpu_n(1).discovery_completed().await;

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu_n(0).db_machine(&mut txn).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpus_reprovision_state(&[
            &ReprovisionState::PoweringOffHost,
            &ReprovisionState::PoweringOffHost
        ])
    );

    let pxe = dpu0_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    for state in [
        ReprovisionState::PowerDown,
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpus_reprovision_state(&[&state, &state])
        );
    }

    let pxe = dpu0_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Reprovisioning/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    let response = mh.dpu_n(0).forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    mh.network_configured(&env).await;

    for state in [
        ReprovisionState::RebootHostBmc,
        ReprovisionState::RebootHost,
    ] {
        let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpus_reprovision_state(&[&state, &state])
        );
    }

    let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered { .. },
        }
    ));

    mh.host().forge_agent_control().await;
    let dpu = mh.dpu_n(0).next_iteration_machine(&env).await;
    assert!(matches!(dpu.current_state(), &ManagedHostState::Ready));
}

#[crate::sqlx_test]
async fn test_instance_reprov_restart_failed(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;
    let tinstance = mh
        .instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_interface = mh.dpu().first_interface(&mut txn).await;
    let host_interface = mh.host().first_interface(&mut txn).await;
    let dpu_arch = MachineArchitecture::Arm;
    let host_arch = MachineArchitecture::X86;

    mh.mark_machine_for_updates().await;

    mh.dpu().trigger_dpu_reprovisioning(Mode::Set, false).await;
    env.api
        .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
            machine_id: mh.id.into(),
            apply_updates_on_reboot: true,
            boot_with_custom_ipxe: false,
            operation: 0,
        }))
        .await
        .unwrap();

    let current_instance = tinstance.rpc_instance().await;
    assert!(current_instance.status().inner().update.is_some());

    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert_eq!(
        &dpu.reprovision_requested.as_ref().unwrap().initiator,
        "AdminCli"
    );

    env.run_machine_state_controller_iteration().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage { .. }
        }
    ));

    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert!(pxe.pxe_script.contains("scout.efi"));

    forge_agent_control(&env, current_instance.inner().machine_id.clone().unwrap()).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Since DPU reprovisioning is started, we can't allow user to reboot host in between. It
    // should be prevented from cloud itself.
    assert!(
        env.api
            .invoke_instance_power(tonic::Request::new(::rpc::forge::InstancePowerRequest {
                machine_id: mh.id.into(),
                apply_updates_on_reboot: true,
                boot_with_custom_ipxe: false,
                operation: 0,
            }))
            .await
            .is_err()
    );
    txn.commit().await.unwrap();

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert_ne!(pxe.pxe_script, "exit".to_string());

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    mh.dpu().discovery_completed().await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::PoweringOffHost)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    for state in [
        ReprovisionState::PowerDown,
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpu_assigned_reprovision_state(state)
        );
    }

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script.contains(
            "Current state: Assigned/Reprovision/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
        )
    );

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;
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

    let dpu = mh.dpu().next_iteration_machine(&env).await;
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

    assert!(
        env.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: mh.id.into(),
                    mode: Mode::Restart as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware: false,
                },
            ))
            .await
            .is_ok()
    );

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::InstallDpuOs {
            substate: InstallDpuOsState::InstallingBFB,
        },)
    );

    env.run_machine_state_controller_iteration().await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::WaitingForNetworkInstall)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(pxe.pxe_script.contains("internal/aarch64/carbide.efi"));

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Discovery as i32
    );
    mh.dpu().discovery_completed().await;

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert_eq!(
        dpu.current_state(),
        &mh.new_dpu_assigned_reprovision_state(ReprovisionState::PoweringOffHost)
    );

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Current state: Assigned/Reprovision/PoweringOffHost. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. ")
    );

    for state in [
        ReprovisionState::PowerDown,
        ReprovisionState::VerifyFirmareVersions,
        ReprovisionState::WaitingForNetworkConfig,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpu_assigned_reprovision_state(state)
        );
    }

    let pxe = dpu_interface.get_pxe_instructions(dpu_arch).await;
    assert!(
        pxe.pxe_script.contains(
            "Current state: Assigned/Reprovision/WaitingForNetworkConfig. This state assumes an OS is provisioned and will exit into the OS in 5 seconds. "
        )
    );

    let response = mh.dpu().forge_agent_control().await;
    assert_eq!(
        response.action,
        rpc::forge::forge_agent_control_response::Action::Noop as i32
    );
    mh.network_configured(&env).await;

    for state in [
        ReprovisionState::RebootHostBmc,
        ReprovisionState::RebootHost,
    ] {
        let dpu = mh.dpu().next_iteration_machine(&env).await;
        assert_eq!(
            dpu.current_state(),
            &mh.new_dpu_assigned_reprovision_state(state)
        );
    }

    let dpu = mh.dpu().next_iteration_machine(&env).await;
    assert!(matches!(
        dpu.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));

    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert!(pxe.pxe_script.contains("exit"));
}

#[crate::sqlx_test]
async fn test_dpu_for_reprovisioning_cannot_restart_if_not_started(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    mh.mark_machine_for_updates().await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(dpu.reprovision_requested.is_none(),);

    match env
        .api
        .trigger_dpu_reprovisioning(tonic::Request::new(
            ::rpc::forge::DpuReprovisioningRequest {
                dpu_id: None,
                machine_id: mh.id.into(),
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

impl ManagedHost {
    pub async fn mark_machine_for_updates(&self) {
        self.api
            .insert_health_report_override(tonic::Request::new(
                rpc::forge::InsertHealthReportOverrideRequest {
                    machine_id: self.id.into(),
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
}
