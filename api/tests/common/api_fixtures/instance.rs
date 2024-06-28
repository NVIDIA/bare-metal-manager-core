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

use carbide::{
    cfg::default_dpu_models,
    db::instance::InstanceId,
    db::machine::Machine,
    model::{
        machine::machine_id::MachineId, machine::CleanupState, machine::MachineState,
        machine::ManagedHostState,
    },
    state_controller::machine::handler::MachineStateHandler,
};
use rpc::{forge::forge_server::Forge, InstanceReleaseRequest};

use crate::common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;

use super::TestEnv;

pub const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
pub const FIXTURE_CIRCUIT_ID_1: &str = "vlan_101";

pub async fn create_instance(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
    infiniband: Option<rpc::InstanceInfinibandConfig>,
    keyset_ids: Vec<String>,
) -> (InstanceId, rpc::Instance) {
    let mut tenant_config = default_tenant_config();
    tenant_config.tenant_keyset_ids = keyset_ids;

    let config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network,
        infiniband,
    };

    create_instance_with_config(env, dpu_machine_id, host_machine_id, config, None).await
}

pub async fn create_instance_with_labels(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
    infiniband: Option<rpc::InstanceInfinibandConfig>,
    keyset_ids: Vec<String>,
    instance_metadata: rpc::Metadata,
) -> (InstanceId, rpc::Instance) {
    let mut tenant_config = default_tenant_config();
    tenant_config.tenant_keyset_ids = keyset_ids;

    let config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network,
        infiniband,
    };
    create_instance_with_config(
        env,
        dpu_machine_id,
        host_machine_id,
        config,
        Some(instance_metadata),
    )
    .await
}

pub async fn create_instance_with_ib_config(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> (InstanceId, rpc::forge::Instance) {
    let config = config_for_ib_config(ib_config);

    create_instance_with_config(env, dpu_machine_id, host_machine_id, config, None).await
}

pub fn single_interface_network_config(segment_id: uuid::Uuid) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id.into()),
        }],
    }
}

pub fn default_os_config() -> rpc::forge::OperatingSystem {
    rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe".to_string(),
                user_data: Some("SomeRandomData".to_string()),
                always_boot_with_ipxe: false,
            },
        )),
    }
}

pub fn default_tenant_config() -> rpc::TenantConfig {
    rpc::TenantConfig {
        user_data: None,
        custom_ipxe: "".to_string(),
        phone_home_enabled: false,
        always_boot_with_custom_ipxe: false,
        tenant_organization_id: "Tenant1".to_string(),
        tenant_keyset_ids: vec![],
    }
}

pub fn config_for_ib_config(
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> rpc::forge::InstanceConfig {
    rpc::forge::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: Some(ib_config),
    }
}

pub async fn create_instance_with_config(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    config: rpc::InstanceConfig,
    instance_metadata: Option<rpc::Metadata>,
) -> (InstanceId, rpc::Instance) {
    let instance_id: InstanceId = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: instance_metadata,
        }))
        .await
        .expect("Create instance failed.")
        .into_inner()
        .id
        .expect("Missing instance ID")
        .try_into()
        .unwrap();

    let instance = advance_created_instance_into_ready_state(
        env,
        dpu_machine_id,
        host_machine_id,
        instance_id,
    )
    .await;
    (instance_id, instance)
}

pub async fn advance_created_instance_into_ready_state(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    instance_id: InstanceId,
) -> rpc::Instance {
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );

    // - first run: state controller moves state to WaitingForNetworkConfig
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    // - second run: state controller sets use_admin_network to false
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    // - forge-dpu-agent gets an instance network to configure, reports it configured
    super::network_configured(env, dpu_machine_id).await;

    // - third run: state controller runs again, advances state to Ready
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler,
        2,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::Ready,
        },
    )
    .await;

    txn.commit().await.unwrap();

    // get the updated info with proper network config info added after the instance state is ready
    env.api
        .find_instances(tonic::Request::new(rpc::InstanceSearchQuery {
            id: Some(instance_id.into()),
            label: None,
        }))
        .await
        .expect("Find instance failed.")
        .into_inner()
        .instances
        .remove(0)
}

pub async fn delete_instance(
    env: &TestEnv,
    instance_id: InstanceId,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
) {
    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
        }))
        .await
        .expect("Delete instance failed.");

    // The instance should show up immediatly as terminating - even if the state handler didn't yet run
    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::TenantState::Terminating
    );

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler.clone(),
        1,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: carbide::model::machine::RetryInfo { count: 0 },
            },
        },
    )
    .await;
    txn.commit().await.unwrap();
    handle_delete_post_bootingwithdiscoveryimage(env, dpu_machine_id, host_machine_id, handler)
        .await;

    assert!(env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .is_empty());
}

pub async fn handle_delete_post_bootingwithdiscoveryimage(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    handler: MachineStateHandler,
) {
    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    // Run state machine twice.
    // First DeletingManagedResource updates use_admin_network, transitions to WaitingForNetworkReconfig
    // Second to discover we are now in WaitingForNetworkReconfig
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler.clone(),
        2,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::WaitingForNetworkReconfig,
        },
    )
    .await;
    txn.commit().await.unwrap();

    // Apply switching back to admin network
    super::network_configured(env, dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler.clone(),
        1,
        &mut txn,
        ManagedHostState::WaitingForCleanup {
            cleanup_state: CleanupState::HostCleanup,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    machine.update_cleanup_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler.clone(),
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::MachineValidating {
                context: "CleanupState".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    Machine::update_machine_validation_time(host_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler.clone(),
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        handler,
        3,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();
}
