/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{collections::HashMap, time::Duration};

use ::rpc::forge::forge_server::Forge;
use carbide::{
    cfg::default_dpu_models,
    db::{
        dhcp_record::InstanceDhcpRecord,
        instance::{Instance, InstanceId},
        instance_address::InstanceAddress,
        machine::{Machine, MachineSearchConfig},
        ObjectFilter,
    },
    instance::{allocate_instance, InstanceAllocationRequest},
    model::{
        instance::{
            config::{
                infiniband::InstanceInfinibandConfig,
                network::{InstanceNetworkConfig, InterfaceFunctionId},
                InstanceConfig,
            },
            status::{
                network::{
                    InstanceInterfaceStatus, InstanceInterfaceStatusObservation,
                    InstanceNetworkStatusObservation,
                },
                tenant::TenantState,
                SyncState,
            },
        },
        machine::{machine_id::try_parse_machine_id, InstanceState, ManagedHostState},
        metadata::Metadata,
    },
    state_controller::machine::handler::MachineStateHandler,
};
use chrono::Utc;
use common::api_fixtures::{
    create_managed_host, create_test_env, dpu,
    instance::{
        advance_created_instance_into_ready_state, create_instance, create_instance_with_labels,
        default_os_config, default_tenant_config, delete_instance, single_interface_network_config,
        FIXTURE_CIRCUIT_ID,
    },
    network_segment::{FIXTURE_NETWORK_SEGMENT_ID, FIXTURE_NETWORK_SEGMENT_ID_1},
};
use mac_address::MacAddress;
use rpc::InstanceReleaseRequest;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::common::api_fixtures::instance::create_instance_with_config;
use crate::common::api_fixtures::update_time_params;

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_allocate_and_release_instance(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let dpu_loopback_ip = dpu::loopback_ip(&mut txn, &dpu_machine_id).await;
    assert!(Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec![],
    )
    .await;

    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::forge::TenantState::Ready
    );

    let tenant_config = instance.config.as_ref().unwrap().tenant.as_ref().unwrap();
    let expected_os = default_os_config();
    let os = instance.config.as_ref().unwrap().os.as_ref().unwrap();
    assert_eq!(os, &expected_os);

    // For backward compatibilty reasons, the OS details are still signaled
    // via `TenantConfig`
    let mut expected_tenant_config = default_tenant_config();
    match &expected_os.variant {
        Some(rpc::forge::operating_system::Variant::Ipxe(ipxe)) => {
            expected_tenant_config.custom_ipxe = ipxe.ipxe_script.clone();
            expected_tenant_config.user_data = ipxe.user_data.clone();
        }
        _ => panic!("Unexpected OS"),
    }
    expected_tenant_config.always_boot_with_custom_ipxe =
        expected_os.run_provisioning_instructions_on_every_boot;
    expected_tenant_config.phone_home_enabled = expected_os.phone_home_enabled;
    assert_eq!(tenant_config, &expected_tenant_config);

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let fetched_instance = Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .unwrap_or_else(|| {
            panic!("find_by_relay_ip for loopback {dpu_loopback_ip} didn't find any instances")
        });
    assert_eq!(fetched_instance.machine_id, host_machine_id);
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        1
    );

    let network_config = fetched_instance.config.network.clone();
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        iface.ip_addrs.clear();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_id(*FIXTURE_NETWORK_SEGMENT_ID)
    );

    assert!(fetched_instance.network_status_observation.is_some());
    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(&host_machine_id, false, &mut txn).await;
    let fetched_instance = Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .unwrap();

    assert!(!fetched_instance.use_custom_pxe_on_boot);
    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // TODO: The MAC here doesn't matter. It's not used for lookup
    let parsed_mac = "ff:ff:ff:ff:ff:ff".parse::<MacAddress>().unwrap();
    let record = InstanceDhcpRecord::find_for_instance(
        &mut txn,
        parsed_mac,
        FIXTURE_CIRCUIT_ID.to_string(),
        fetched_instance,
    )
    .await
    .unwrap();

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address().to_string(), "192.0.2.3");
    assert_eq!(
        &record.address(),
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );

    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;

    // Address is freed during delete
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_allocate_instance_with_labels(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_metadata = rpc::forge::Metadata {
        name: "test_instance_with_labels".to_string(),
        description: "this instance must have labels.".to_string(),
        labels: vec![
            rpc::forge::Label {
                key: "key1".to_string(),
                value: Some("value1".to_string()),
            },
            rpc::forge::Label {
                key: "key2".to_string(),
                value: None,
            },
        ],
    };

    let (instance_id, _instance) = create_instance_with_labels(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec![],
        instance_metadata.clone(),
    )
    .await;

    // Test searching based on instance id.
    let mut instance_matched_by_id = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);

    instance_matched_by_id.metadata = instance_matched_by_id.metadata.take().map(|mut metadata| {
        metadata.labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));
        metadata
    });

    assert_eq!(
        instance_matched_by_id.metadata,
        Some(instance_metadata.clone())
    );

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let dpu_loopback_ip = dpu::loopback_ip(&mut txn, &dpu_machine_id).await;
    let fetched_instance = Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .unwrap_or_else(|| {
            panic!("find_by_relay_ip for loopback {dpu_loopback_ip} didn't find any instances")
        });
    assert_eq!(fetched_instance.machine_id, host_machine_id);

    assert_eq!(fetched_instance.metadata.name, "test_instance_with_labels");
    assert_eq!(
        fetched_instance.metadata.description,
        "this instance must have labels."
    );
    assert!(fetched_instance.metadata.labels.len() == 2);
    assert_eq!(
        fetched_instance.metadata.labels.get("key1").unwrap(),
        "value1"
    );
    assert_eq!(fetched_instance.metadata.labels.get("key2").unwrap(), "");

    let request = tonic::Request::new(rpc::InstanceSearchQuery {
        id: None,
        label: {
            Some(rpc::forge::Label {
                key: "key1".to_string(),
                value: None,
            })
        },
    });

    let mut instance_matched_by_label = env
        .api
        .find_instances(request)
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .instances
        .remove(0);
    instance_matched_by_label.metadata =
        instance_matched_by_label
            .metadata
            .take()
            .map(|mut metadata| {
                metadata.labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));
                metadata
            });

    assert_eq!(
        instance_matched_by_label.machine_id.unwrap().id,
        host_machine_id.to_string()
    );

    assert_eq!(instance_matched_by_label.metadata, Some(instance_metadata));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_search_based_on_labels(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..=9 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

        let (_instance_id, _instance) = create_instance_with_labels(
            &env,
            &dpu_machine_id,
            &host_machine_id,
            Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
            None,
            vec![],
            rpc::forge::Metadata {
                name: format!("instance_{}{}{}", i, i, i).to_string(),
                description: format!("instance_{}{}{} have labels", i, i, i).to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: format!("key_A_{}{}{}", i, i, i).to_string(),
                        value: Some(format!("value_A_{}{}{}", i, i, i).to_string()),
                    },
                    rpc::forge::Label {
                        key: format!("key_B_{}{}{}", i, i, i).to_string(),
                        value: None,
                    },
                ],
            },
        )
        .await;
    }

    // Test searching based on value.
    let request = tonic::Request::new(rpc::InstanceSearchQuery {
        id: None,
        label: {
            Some(rpc::forge::Label {
                key: "".to_string(),
                value: Some("value_A_444".to_string()),
            })
        },
    });
    let instance_matched_by_label = env
        .api
        .find_instances(request)
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .instances
        .remove(0);

    assert_eq!(
        instance_matched_by_label.metadata.unwrap().name,
        "instance_444"
    );

    // Test searching based on key.
    let request = tonic::Request::new(rpc::InstanceSearchQuery {
        id: None,
        label: {
            Some(rpc::forge::Label {
                key: "key_A_111".to_string(),
                value: None,
            })
        },
    });
    let instance_matched_by_label = env
        .api
        .find_instances(request)
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .instances
        .remove(0);

    assert_eq!(
        instance_matched_by_label.metadata.unwrap().name,
        "instance_111"
    );

    // Test searching based on key and value.
    let request = tonic::Request::new(rpc::InstanceSearchQuery {
        id: None,
        label: {
            Some(rpc::forge::Label {
                key: "key_A_888".to_string(),
                value: Some("value_A_888".to_string()),
            })
        },
    });
    let instance_matched_by_label = env
        .api
        .find_instances(request)
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .instances
        .remove(0);

    assert_eq!(
        instance_matched_by_label.metadata.unwrap().name,
        "instance_888"
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_create_instance_with_provided_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let config = rpc::InstanceConfig {
        os: Some(default_os_config()),
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    let instance_id = uuid::Uuid::new_v4();
    let rpc_instance_id: rpc::Uuid = instance_id.into();

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: Some(rpc_instance_id.clone()),
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .expect("Create instance failed.")
        .into_inner();

    assert_eq!(instance.id.as_ref(), Some(&rpc_instance_id));

    let instance = env
        .find_instances(Some(rpc_instance_id.clone()))
        .await
        .instances
        .remove(0);
    assert_eq!(instance.id.as_ref(), Some(&rpc_instance_id));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_deletion_before_provisioning_finishes(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // Create an instance in non-ready state
    let config = rpc::InstanceConfig {
        os: Some(default_os_config()),
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: Default::default(),
    };

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .expect("Create instance failed.")
        .into_inner();
    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::TenantState::Provisioning
    );

    let instance_id: InstanceId = instance
        .id
        .expect("Missing instance ID")
        .try_into()
        .unwrap();

    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
        }))
        .await
        .expect("Delete instance failed.");

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

    // Advance the instance into the "ready" state. To the tenant it will however
    // still show up as terminating
    let instance = advance_created_instance_into_ready_state(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        instance_id,
    )
    .await;
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

    // Now go through regular deletion
    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_deletion_is_idempotent(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
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

    // We can call `release_instance` multiple times
    for i in 0..2 {
        env.api
            .release_instance(tonic::Request::new(InstanceReleaseRequest {
                id: Some(instance_id.into()),
            }))
            .await
            .unwrap_or_else(|_| panic!("Delete instance failed failed on attempt {}.", i));
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
    }

    // And finally delete the instance
    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;

    // Release instance on non-existing instance should lead to a Not Found error
    let err = env
        .api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
        }))
        .await
        .expect_err("Expect deletion to fail");
    assert_eq!(err.code(), tonic::Code::NotFound);
    let err_msg = err.message();
    assert_eq!(
        err.message(),
        format!("instance not found: {instance_id}"),
        "Error message is: {}",
        err_msg
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_2_instances_with_same_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;
    let (host_machine_id_2, _dpu_machine_id_2) = create_managed_host(&env).await;

    let config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    let instance_id = uuid::Uuid::new_v4();
    let rpc_instance_id: rpc::Uuid = instance_id.into();

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: Some(rpc_instance_id.clone()),
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config.clone()),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .expect("Create instance failed.")
        .into_inner();
    assert_eq!(instance.id.as_ref(), Some(&rpc_instance_id));

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: Some(rpc_instance_id.clone()),
            machine_id: Some(rpc::MachineId {
                id: host_machine_id_2.to_string(),
            }),
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await;

    // TODO: Do not leak the full database error to users
    let err = result.expect_err("Expect instance creation to fail");
    assert!(err.message().contains("Database Error: error returned from database: duplicate key value violates unique constraint \"instances_pkey\""));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_cloud_init_metadata(
    _: PgPoolOptions,
    options: PgConnectOptions,
) -> eyre::Result<()> {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await?
        .unwrap();

    let request = tonic::Request::new(rpc::forge::CloudInitInstructionsRequest {
        ip: machine.interfaces()[0].addresses()[0].address.to_string(),
    });

    let response = env.api.get_cloud_init_instructions(request).await?;

    let Some(metadata) = response.into_inner().metadata else {
        panic!("The value for metadata should not have been None");
    };

    assert_eq!(metadata.instance_id, host_machine_id.to_string());

    let (instance_id, instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec![],
    )
    .await;

    let request = tonic::Request::new(rpc::forge::CloudInitInstructionsRequest {
        ip: instance.status.unwrap().network.unwrap().interfaces[0].addresses[0].to_string(),
    });

    let response = env.api.get_cloud_init_instructions(request).await?;

    let Some(metadata) = response.into_inner().metadata else {
        panic!("The value for metadata should not have been None");
    };

    assert_eq!(metadata.instance_id, instance_id.to_string());

    txn.commit().await.unwrap();
    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_network_status_sync(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // TODO: The test is broken from here. This method already moves the instance
    // into READY state, which means most assertions that follow this won't test
    // anything new anymmore.
    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec![],
    )
    .await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // When no network status has been observed, we report an interface
    // list with no IPs and MACs to the user
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = Instance::load_snapshot_by_machine_id(
        &mut txn,
        &host_machine_id,
        machine.current_state(),
        None,
    )
    .await
    .unwrap()
    .unwrap();

    let pf_addr = *snapshot.config.network.interfaces[0]
        .ip_addrs
        .iter()
        .next()
        .unwrap()
        .1;

    let mut updated_network_status = InstanceNetworkStatusObservation {
        config_version: snapshot.network_config_version,
        interfaces: vec![InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: vec![pf_addr],
        }],
        observed_at: Utc::now(),
    };

    Instance::update_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();

    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let snapshot = Instance::load_snapshot_by_machine_id(
        &mut txn,
        &host_machine_id,
        machine.current_state(),
        None,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );

    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.infiniband.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: vec![pf_addr],
        }]
    );

    updated_network_status.interfaces[0].mac_address =
        Some(MacAddress::new([11, 12, 13, 14, 15, 16]).into());
    Instance::update_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = Instance::load_snapshot_by_machine_id(
        &mut txn,
        &host_machine_id,
        machine.current_state(),
        None,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec![pf_addr],
        }]
    );

    // Assuming the config would change, the status should become unsynced again
    let next_config_version = snapshot.network_config_version.increment();
    let (_,): (uuid::Uuid,) = sqlx::query_as(
        "UPDATE instances SET network_config_version=$1 WHERE id = $2::uuid returning id",
    )
    .bind(&next_config_version.version_string())
    .bind(instance_id)
    .fetch_one(&mut *txn)
    .await
    .unwrap();
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = Instance::load_snapshot_by_machine_id(
        &mut txn,
        &host_machine_id,
        machine.current_state(),
        None,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Pending);
    assert_eq!(status.network.configs_synced, SyncState::Pending);
    // TODO: This is wrong - it should become `Configuring`
    assert_eq!(
        status.tenant.as_ref().unwrap().state,
        TenantState::Provisioning
    );
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: Vec::new(),
        }]
    );

    // When the observation catches up, we are good again
    // The extra VF is ignored
    updated_network_status.config_version = next_config_version;
    updated_network_status
        .interfaces
        .push(InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::Virtual { id: 0 },
            mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
            addresses: vec!["127.1.2.3".parse().unwrap()],
        });

    Instance::update_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = Instance::load_snapshot_by_machine_id(
        &mut txn,
        &host_machine_id,
        machine.current_state(),
        None,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec![pf_addr],
        }]
    );

    txn.commit().await.unwrap();
    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_dpu(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_sim.config).await;

    let request = InstanceAllocationRequest {
        instance_id: InstanceId::from(uuid::Uuid::new_v4()),
        machine_id: try_parse_machine_id(&dpu_machine_id).unwrap(),
        config: InstanceConfig {
            os: default_os_config().try_into().unwrap(),
            tenant: default_tenant_config().try_into().unwrap(),
            network: InstanceNetworkConfig::for_segment_id(*FIXTURE_NETWORK_SEGMENT_ID),
            infiniband: InstanceInfinibandConfig::default(),
        },
        metadata: Metadata {
            name: "test_instance".to_string(),
            description: "tests/instance".to_string(),
            labels: HashMap::new(),
        },
    };

    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    let result = allocate_instance(request, &env.pool).await;
    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is of type Dpu and can not be converted into an instance"),
        "Error message should contain 'is of type Dpu and can not be converted into an instance', but is {}",
        error
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_address_creation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID_1)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID).into()),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID_1).into()),
            },
        ],
    });

    let (_instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID_1)
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    // The addresses should show up in the internal config - which is sent to the DPU
    let network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!network_config.use_admin_network);
    assert_eq!(network_config.tenant_interfaces[0].ip, "192.0.2.3");
    assert_eq!(network_config.tenant_interfaces[1].ip, "192.0.3.3");
}

// TODO(gk) Restore after https://jirasw.nvidia.com/browse/FORGE-2243
//#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn _test_cannot_create_instance_on_unhealthy_dpu(
    _: PgPoolOptions,
    options: PgConnectOptions,
) -> eyre::Result<()> {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await?;

    let machine = &Machine::find(
        &mut txn,
        ObjectFilter::One(host_machine_id.clone()),
        MachineSearchConfig::default(),
    )
    .await?[0];
    let (_, version) = machine.network_config().clone().take();

    // Give it an unhealthy network
    let netstat_req = tonic::Request::new(rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(dpu_machine_id.to_string().into()),
        observed_at: None, // server sets it
        dpu_health: Some(rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            observed_at: None,
            successes: vec![],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: "everything".to_string(),
                in_alert_since: None,
                message: "test_cannot_create_instance_on_unhealthy_dpu".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_host_state_changes()
                        .to_string(),
                ],
            }],
        }),
        health: Some(rpc::forge::NetworkHealth {
            is_healthy: false,
            passed: vec![],
            failed: vec!["lol".to_string(), "everything".to_string()],
            message: Some("test_cannot_create_instance_on_unhealthy_dpu".to_string()),
        }),
        network_config_version: Some(version.version_string()),
        instance_config_version: None,
        instance_network_config_version: None,
        interfaces: vec![rpc::InstanceInterfaceStatusObservation {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![],
        }],
        network_config_error: None,
        instance_id: None,
        dpu_agent_version: Some("test_cannot_create_instance_on_unhealthy_dpu".to_string()),
        client_certificate_expiry_unix_epoch_secs: None,
    });
    env.api.record_dpu_network_status(netstat_req).await?;

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                os: Some(default_os_config()),
                tenant: Some(default_tenant_config()),
                network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
                infiniband: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await;
    let Err(err) = result else {
        panic!("Creating an instance should have been refused");
    };
    if err.code() != tonic::Code::Unavailable {
        panic!("Expected grpc code UNAVAILABLE, got {}", err.code());
    }
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_phone_home(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut os = default_os_config();
    os.phone_home_enabled = true;
    let instance_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(os),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    let (instance_id, _instance) = create_instance_with_config(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        instance_config,
        None,
    )
    .await;

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);

    // Should be in a provisioning state
    // 0 = PROVISIONING
    assert_eq!(instance.status.unwrap().tenant.unwrap().state, 0);

    // Phone home to transition to the ready state
    env.api
        .update_instance_phone_home_last_contact(tonic::Request::new(
            rpc::forge::InstancePhoneHomeLastContactRequest {
                instance_id: Some(instance_id.into()),
            },
        ))
        .await
        .unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);

    // Should be in a ready state 1 = READY
    assert_eq!(instance.status.unwrap().tenant.unwrap().state, 1);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_bootingwithdiscoveryimage_delay(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
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

    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
        }))
        .await
        .expect("Delete instance failed.");

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
        &host_machine_id,
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
    assert!(
        env.test_meter
            .formatted_metric("forge_reboot_attempts_in_booting_with_discovery_image_count")
            .is_none(),
        "State is not changed. The reboot counter should only increased once state changed"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();

    update_time_params(&env.pool, &host, 1).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler.clone(),
        1,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: carbide::model::machine::RetryInfo { count: 1 },
            },
        },
    )
    .await;
    txn.commit().await.unwrap();
    assert!(
        env.test_meter
            .formatted_metric("forge_reboot_attempts_in_booting_with_discovery_image_count")
            .is_none(),
        "State is not changed. The reboot counter should only increased once state changed"
    );

    common::api_fixtures::instance::handle_delete_post_bootingwithdiscoveryimage(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        handler,
    )
    .await;

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_reboot_attempts_in_booting_with_discovery_image_sum")
            .unwrap(),
        "2"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_reboot_attempts_in_booting_with_discovery_image_count")
            .unwrap(),
        "1"
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_instance_hostname(db_pool: sqlx::PgPool) {
    let env = create_test_env(db_pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID).into()),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID_1).into()),
            },
        ],
    });

    let (_instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!("192-0-2-3", response.tenant_interfaces[0].fqdn);
    assert_eq!("192-0-2-3", response.tenant_interfaces[1].fqdn);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_create_instance_duplicate_keyset_ids(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let config = rpc::InstanceConfig {
        os: Some(default_os_config()),
        tenant: Some(rpc::TenantConfig {
            user_data: None,
            custom_ipxe: "".to_string(),
            phone_home_enabled: false,
            always_boot_with_custom_ipxe: false,
            tenant_organization_id: "Tenant1".to_string(),
            tenant_keyset_ids: vec![
                "a".to_string(),
                "bad_id".to_string(),
                "c".to_string(),
                "bad_id".to_string(),
            ],
        }),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    let instance_id = uuid::Uuid::new_v4();
    let rpc_instance_id: rpc::Uuid = instance_id.into();

    let err = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: Some(rpc_instance_id.clone()),
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .expect_err("Duplicate TenantKeyset IDs should not be accepted");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "Duplicate TenantKeyset ID found: bad_id");
}
