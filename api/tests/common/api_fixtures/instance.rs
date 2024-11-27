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

use std::time::SystemTime;

use carbide::{
    db::machine::Machine,
    model::machine::{CleanupState, MachineState, ManagedHostState},
};
use forge_uuid::{instance::InstanceId, machine::MachineId, network::NetworkSegmentId};
use rpc::{
    forge::{forge_server::Forge, instance_interface_config::NetworkDetails},
    InstanceReleaseRequest, Timestamp,
};

use crate::common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;

use super::{
    forge_agent_control, inject_machine_measurements, persist_machine_validation_result, TestEnv,
};

pub const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
pub const FIXTURE_CIRCUIT_ID_1: &str = "vlan_101";

pub async fn create_instance(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
    infiniband: Option<rpc::InstanceInfinibandConfig>,
    storage: Option<rpc::forge::InstanceStorageConfig>,
    keyset_ids: Vec<String>,
) -> (InstanceId, rpc::Instance) {
    let mut tenant_config = default_tenant_config();
    tenant_config.tenant_keyset_ids = keyset_ids;

    let config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network,
        infiniband,
        storage,
    };

    create_instance_with_config(env, dpu_machine_id, host_machine_id, config, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_instance_with_labels(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
    infiniband: Option<rpc::InstanceInfinibandConfig>,
    storage: Option<rpc::forge::InstanceStorageConfig>,
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
        storage,
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

#[allow(clippy::too_many_arguments)]
pub async fn create_instance_with_hostname(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
    infiniband: Option<rpc::InstanceInfinibandConfig>,
    storage: Option<rpc::forge::InstanceStorageConfig>,
    keyset_ids: Vec<String>,
    hostname: String,
    tenant_org: String,
) -> (InstanceId, rpc::Instance) {
    let mut tenant_config = default_tenant_config();
    tenant_config.tenant_keyset_ids = keyset_ids;
    tenant_config.tenant_organization_id = tenant_org;
    tenant_config.hostname = Some(hostname);

    let config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network,
        infiniband,
        storage,
    };
    create_instance_with_config(env, dpu_machine_id, host_machine_id, config, None).await
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

pub fn single_interface_network_config(segment_id: NetworkSegmentId) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id.into()),
            network_details: Some(NetworkDetails::SegmentId(segment_id.into())),
        }],
    }
}

pub fn single_interface_network_config_with_vpc_prefix(
    prefix_id: rpc::Uuid,
) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(NetworkDetails::VpcPrefixId(prefix_id)),
        }],
    }
}

pub fn default_os_config() -> rpc::forge::OperatingSystem {
    rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe".to_string(),
                user_data: Some("SomeRandomData".to_string()),
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
        hostname: None,
    }
}

pub fn config_for_ib_config(
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> rpc::forge::InstanceConfig {
    rpc::forge::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: Some(ib_config),
        storage: None,
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
    // Run network state machine handler here.
    env.run_network_segment_controller_iteration().await;

    // - zero run: state controller moves state to WaitingForNetworkSegmentToBeReady
    env.run_machine_state_controller_iteration().await;
    // - first run: state controller moves state to WaitingForNetworkConfig
    env.run_machine_state_controller_iteration().await;
    // - second run: state controller sets use_admin_network to false
    env.run_machine_state_controller_iteration().await;
    // - forge-dpu-agent gets an instance network to configure, reports it configured
    super::network_configured(env, dpu_machine_id).await;
    // - simulate that the host's hardware is reported healthy
    super::simulate_hardware_health_report(
        env,
        host_machine_id,
        health_report::HealthReport::empty("hardware-health".to_string()),
    )
    .await;

    // - third run: state controller runs again, advances state to Ready
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
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

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
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
    handle_delete_post_bootingwithdiscoveryimage(env, dpu_machine_id, host_machine_id).await;

    assert!(env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .is_empty());

    // Run network state machine handler here.
    env.run_network_segment_controller_iteration().await;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;
}

pub async fn handle_delete_post_bootingwithdiscoveryimage(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
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

    if env.attestation_enabled {
        inject_machine_measurements(env, host_machine_id.clone().into()).await;
    }

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
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
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "Cleanup".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: true,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "instance".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context: "Cleanup".to_string(),
        exit_code: 0,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
        test_id: Some("instance".to_string()),
    };

    let response = forge_agent_control(
        env,
        rpc::MachineId {
            id: host_machine_id.to_string(),
        },
    )
    .await;
    let uuid = &response.data.unwrap().pair[1].value;

    machine_validation_result.validation_id = Some(rpc::Uuid {
        value: uuid.to_owned(),
    });
    persist_machine_validation_result(env, machine_validation_result.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    Machine::update_machine_validation_time(host_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
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
        3,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();
}
