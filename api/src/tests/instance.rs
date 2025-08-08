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
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    ops::DerefMut,
    str::FromStr,
    time::{Duration, SystemTime},
};

use crate::{
    db::{
        self, ObjectColumnFilter,
        instance::Instance,
        instance_address::{InstanceAddress, UsedOverlayNetworkIpResolver},
        machine::MachineSearchConfig,
        network_prefix::NetworkPrefix,
        network_segment::{IdColumn, NetworkSegment, NetworkSegmentSearchConfig},
        vpc::{UpdateVpcVirtualization, Vpc},
    },
    dhcp::allocation::UsedIpResolver,
    instance::{InstanceAllocationRequest, allocate_instance, allocate_network},
    model::{
        instance::{
            config::{
                InstanceConfig,
                infiniband::InstanceInfinibandConfig,
                network::{
                    DeviceLocator, InstanceNetworkConfig, InterfaceFunctionId, NetworkDetails,
                },
                storage::InstanceStorageConfig,
            },
            status::{
                SyncState,
                network::{InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation},
            },
        },
        machine::{
            CleanupState, FailureDetails, InstanceState, MachineState, MachineValidatingState,
            ManagedHostState, MeasuringState, NetworkConfigUpdateState, ValidationState,
            machine_id::try_parse_machine_id,
        },
        metadata::Metadata,
        network_security_group::NetworkSecurityGroupStatusObservation,
    },
    network_segment::allocate::Ipv4PrefixAllocator,
    tests::common::api_fixtures::create_managed_host_multi_dpu,
};
use ::rpc::forge::forge_server::Forge;
use chrono::Utc;
use common::api_fixtures::{
    TestEnvOverrides, create_managed_host, create_test_env, create_test_env_with_overrides, dpu,
    forge_agent_control, get_config, get_vpc_fixture_id, inject_machine_measurements,
    instance::{
        TestInstance, advance_created_instance_into_ready_state, default_os_config,
        default_tenant_config, delete_instance, interface_network_config_with_devices,
        single_interface_network_config, single_interface_network_config_with_vpc_prefix,
        update_instance_network_status_observation,
    },
    managed_host::ManagedHostConfig,
    network_configured, network_configured_with_health, persist_machine_validation_result,
    populate_network_security_groups, site_explorer,
    tpm_attestation::{CA_CERT_SERIALIZED, EK_CERT_SERIALIZED},
};
use forge_uuid::{instance::InstanceId, machine::MachineId};
use ipnetwork::{IpNetwork, Ipv4Network};
use itertools::Itertools;
use mac_address::MacAddress;

use rpc::{
    InstanceReleaseRequest, InterfaceFunctionType, Timestamp,
    forge::{NetworkSegmentSearchFilter, OperatingSystem, TpmCaCert, TpmCaCertId},
};
use tonic::Request;

use crate::tests::common;
use crate::tests::common::api_fixtures::{
    TestEnv, create_managed_host_with_ek, update_time_params,
};
use forge_uuid::vpc::VpcPrefixId;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

#[crate::sqlx_test]
async fn test_allocate_and_release_instance_one_dpu(
    pool_options: PgPoolOptions,
    options: PgConnectOptions,
) {
    test_allocate_and_release_instance_impl(pool_options, options, 1, 1).await
}
#[crate::sqlx_test]
async fn test_allocate_and_release_instance_one_of_two_dpus(
    pool_options: PgPoolOptions,
    options: PgConnectOptions,
) {
    test_allocate_and_release_instance_impl(pool_options, options, 2, 1).await
}
#[crate::sqlx_test]
async fn test_allocate_and_release_instance_two_of_two_dpus(
    pool_options: PgPoolOptions,
    options: PgConnectOptions,
) {
    test_allocate_and_release_instance_impl(pool_options, options, 2, 2).await
}
#[crate::sqlx_test]
async fn test_allocate_and_release_instance_two_of_three_dpus(
    pool_options: PgPoolOptions,
    options: PgConnectOptions,
) {
    test_allocate_and_release_instance_impl(pool_options, options, 3, 2).await
}

async fn test_allocate_and_release_instance_impl(
    _: PgPoolOptions,
    options: PgConnectOptions,
    dpu_count: usize,
    instance_interface_count: usize,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_ids = env.create_vpc_and_tenant_segments(dpu_count).await;
    let (host_machine_id, dpu_machine_ids) = create_managed_host_multi_dpu(&env, dpu_count).await;

    let (used_dpu_ids, unused_dpu_ids) = dpu_machine_ids.split_at(instance_interface_count);

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    for segment_id in &segment_ids {
        assert_eq!(
            InstanceAddress::count_by_segment_id(&mut txn, segment_id)
                .await
                .unwrap(),
            0
        );
    }
    let host_machine =
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    let mut device_locators = Vec::default();
    for dpu_machine_id in used_dpu_ids {
        device_locators.push(
            host_machine
                .get_device_locator_for_dpu_id(dpu_machine_id)
                .unwrap(),
        );
    }

    assert!(matches!(
        host_machine.current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let (instance_id, _instance) = TestInstance::new(&env)
        .network(interface_network_config_with_devices(
            &segment_ids,
            &device_locators,
        ))
        .unused_dpu_machine_ids(unused_dpu_ids)
        .create(used_dpu_ids, &host_machine_id)
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
            expected_tenant_config.user_data = expected_os.user_data.clone();
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

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();
    assert_eq!(fetched_instance.machine_id, host_machine_id);
    for (segment_index, segment_id) in segment_ids.iter().enumerate() {
        let expected_count = if segment_index < instance_interface_count {
            1
        } else {
            0
        };
        assert_eq!(
            InstanceAddress::count_by_segment_id(&mut txn, segment_id)
                .await
                .unwrap(),
            expected_count
        );
    }
    let network_config = fetched_instance.config.network.clone();
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
        iface.internal_uuid = uuid::Uuid::nil();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_ids(&segment_ids, &device_locators,)
    );

    assert!(!fetched_instance.observations.network.is_empty());
    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(&host_machine_id, false, &mut txn).await;
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // TODO: The MAC here doesn't matter. It's not used for lookup
    let record = InstanceAddress::find_by_instance_id_and_segment_id(
        &mut txn,
        &fetched_instance.id,
        segment_ids.first().unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address.to_string(), "192.0.4.3");
    assert_eq!(
        &record.address,
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );

    assert_eq!(
        format!("{}/32", &record.address),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
    );

    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    delete_instance(&env, instance_id, &dpu_machine_ids, &host_machine_id).await;

    // Address is freed during delete
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    for segment_id in &segment_ids {
        assert_eq!(
            InstanceAddress::count_by_segment_id(&mut txn, segment_id)
                .await
                .unwrap(),
            0
        );
    }
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_measurement_assigned_ready_to_waiting_for_measurements_to_ca_failed_to_ready(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();

    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    let inserted_cert = env
        .api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert")
        .into_inner();

    let (host_machine_id, dpu_machine_id, _) =
        create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    //let dpu_loopback_ip = dpu::loopback_ip(&mut txn, &dpu_machine_id).await;
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );

    let host_machine =
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(
        host_machine.current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let device_locator = host_machine
        .get_device_locator_for_dpu_id(&dpu_machine_id)
        .unwrap();
    let (instance_id, _instance) = TestInstance::new(&env)
        .network(interface_network_config_with_devices(
            &[segment_id],
            &[device_locator.clone()],
        ))
        .create(&[dpu_machine_id], &host_machine_id)
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
            expected_tenant_config.user_data = expected_os.user_data.clone();
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

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();
    assert_eq!(fetched_instance.machine_id, host_machine_id);
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        1
    );

    let network_config = fetched_instance.config.network.clone();
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
        iface.internal_uuid = uuid::Uuid::nil();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_ids(&[segment_id], &[device_locator],)
    );

    assert!(!fetched_instance.observations.network.is_empty());
    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(&host_machine_id, false, &mut txn).await;
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();

    assert!(!fetched_instance.use_custom_pxe_on_boot);
    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // TODO: The MAC here doesn't matter. It's not used for lookup
    let segment = NetworkSegment::find_by_name(&mut txn, "TENANT")
        .await
        .unwrap();
    let record = InstanceAddress::find_by_instance_id_and_segment_id(
        &mut txn,
        &fetched_instance.id,
        segment.id(),
    )
    .await
    .unwrap()
    .unwrap();

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address.to_string(), "192.0.4.3");
    assert_eq!(
        &record.address,
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );

    assert_eq!(
        format!("{}/32", &record.address),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
    );

    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    // from delete_instance()
    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
            issue: None,
            is_repair_tenant: None,
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
        &host_machine_id,
        1,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: crate::model::machine::RetryInfo { count: 0 },
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    // handle_delete_post_bootingwithdiscoveryimage()

    let mut txn = env.pool.begin().await.unwrap();
    let machine = db::machine::find_one(
        &mut txn,
        &host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // Run state machine twice.
    // First DeletingManagedResource updates use_admin_network, transitions to WaitingForNetworkReconfig
    // Second to discover we are now in WaitingForNetworkReconfig
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        2,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::WaitingForNetworkReconfig,
        },
    )
    .await;
    txn.commit().await.unwrap();

    // Apply switching back to admin network
    network_configured(&env, &vec![dpu_machine_id]).await;

    // now we should be in waiting for measurument state
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        2,
        &mut txn,
        ManagedHostState::PostAssignedMeasuring {
            measuring_state: MeasuringState::WaitingForMeasurements,
        },
    )
    .await;
    txn.commit().await.unwrap();

    // remove ca cert and inject measurements, now we should go to failed ca
    // validation state
    let delete_ca_certs_request = tonic::Request::new(TpmCaCertId {
        ca_cert_id: inserted_cert.id.unwrap().ca_cert_id,
    });
    env.api
        .tpm_delete_ca_cert(delete_ca_certs_request)
        .await
        .unwrap();

    inject_machine_measurements(&env, host_machine_id.into()).await;

    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    // check that it has failed as intended due to the lack of ca cert
    let mut txn = env.pool.begin().await.unwrap();
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: crate::model::machine::FailureCause::MeasurementsCAValidationFailed { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // now re-add the ca cert
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::WaitingForCleanup {
            cleanup_state: CleanupState::HostCleanup {
                boss_controller_id: None,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = db::machine::find_one(
        &mut txn,
        &host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    db::machine::update_cleanup_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Cleanup".to_string(),
                    id: uuid::Uuid::default(),
                    completed: 1,
                    total: 1,
                    is_enabled: true,
                },
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
        test_id: Some("test1".to_string()),
    };

    let response = forge_agent_control(
        &env,
        rpc::MachineId {
            id: host_machine_id.to_string(),
        },
    )
    .await;
    let uuid = &response.data.unwrap().pair[1].value;

    machine_validation_result.validation_id = Some(rpc::Uuid {
        value: uuid.to_owned(),
    });
    persist_machine_validation_result(&env, machine_validation_result.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    db::machine::update_machine_validation_time(&host_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
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
    let machine = db::machine::find_one(
        &mut txn,
        &host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();

    // end of handle_delete_post_bootingwithdiscoveryimage()

    assert!(
        env.find_instances(Some(instance_id.into()))
            .await
            .instances
            .is_empty()
    );

    // end of delete_instance()

    // Address is freed during delete
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_allocate_instance_with_labels(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
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

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .metadata(instance_metadata.clone())
        .create(&[dpu_machine_id], &host_machine_id)
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

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();
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

#[crate::sqlx_test]
async fn test_allocate_instance_with_invalid_metadata(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    for (invalid_metadata, expected_err) in common::metadata::invalid_metadata_testcases(true) {
        let tenant_config = default_tenant_config();
        let config = rpc::InstanceConfig {
            tenant: Some(tenant_config),
            os: Some(default_os_config()),
            network: Some(single_interface_network_config(segment_id)),
            infiniband: None,
            storage: None,
            network_security_group_id: None,
        };

        let result = env
            .api
            .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
                instance_id: None,
                machine_id: Some(rpc::MachineId {
                    id: host_machine_id.to_string(),
                }),
                instance_type_id: None,
                config: Some(config),
                metadata: Some(invalid_metadata.clone()),
                allow_unhealthy_machine: false,
            }))
            .await;

        let err = result.expect_err(&format!(
            "Invalid metadata of type should not be accepted: {:?}",
            invalid_metadata
        ));

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains(&expected_err),
            "Testcase: {:?}\nMessage is \"{}\".\nMessage should contain: \"{}\"",
            invalid_metadata,
            err.message(),
            expected_err
        );
    }
}

#[crate::sqlx_test]
async fn test_instance_hostname_creation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_hostname = "test-hostname";

    let (_instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .hostname(instance_hostname)
        .tenant_org("org-nebulon")
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();

    let returned_hostname = fetched_instance.config.tenant.hostname;

    assert_eq!(returned_hostname.unwrap(), instance_hostname);

    //Check for duplicate hostnames
    let txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let (new_host_machine_id, new_dpu_machine_id) = create_managed_host(&env).await;
    let (_instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .hostname(instance_hostname)
        .tenant_org("org-nvidia") // different org, should fail on the same one
        .create(&[new_dpu_machine_id], &new_host_machine_id)
        .await;
}

#[crate::sqlx_test]
async fn test_instance_dns_resolution(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (segment_id_1, segment_id_2) = env.create_vpc_and_dual_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some((segment_id_1).into()),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((segment_id_2).into()),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            },
        ],
    };

    // Create instance with hostname
    let (_instance_id, _instance) = TestInstance::new(&env)
        .network(network)
        .hostname("test-hostname")
        .tenant_org("nvidia-org")
        .create(&[dpu_machine_id], &host_machine_id)
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

    //DNS record domain always uses IP Address (for now)
    let dns_record = env
        .api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some("192-0-4-3.dwrt1.com.".to_string()),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!("192.0.4.3", &dns_record.rrs[0].rdata.clone().unwrap());

    //DHCP response uses hostname set during allocation
    assert_eq!(
        "test-hostname.dwrt1.com",
        response.tenant_interfaces[0].fqdn
    );
}

#[crate::sqlx_test]
async fn test_instance_null_hostname(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    //Create instance with no hostname set
    let mut tenant_config = default_tenant_config();
    tenant_config.hostname = None;
    let instance_config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
    };

    let (_instance_id, _instance) = TestInstance::new(&env)
        .config(instance_config)
        .create(&[dpu_machine_id], &host_machine_id)
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

    //DNS record domain always uses dashed IP (for now)
    let dns_record = env
        .api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some("192-0-4-3.dwrt1.com.".to_string()),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!("192.0.4.3", &dns_record.rrs[0].rdata.clone().unwrap());

    //DHCP response uses dashed IP
    assert_eq!("192-0-4-3.dwrt1.com", response.tenant_interfaces[0].fqdn);
}

#[crate::sqlx_test]
async fn test_instance_search_based_on_labels(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    for i in 0..=9 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

        let (_instance_id, _instance) = TestInstance::new(&env)
            .single_interface_network_config(segment_id)
            .metadata(rpc::forge::Metadata {
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
            })
            .create(&[dpu_machine_id], &host_machine_id)
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

#[crate::sqlx_test]
async fn test_create_instance_with_provided_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let config = rpc::InstanceConfig {
        os: Some(default_os_config()),
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
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
            instance_type_id: None,
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
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

#[crate::sqlx_test]
async fn test_instance_deletion_before_provisioning_finishes(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // Create an instance in non-ready state
    let config = rpc::InstanceConfig {
        os: Some(default_os_config()),
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: Default::default(),
        storage: None,
        network_security_group_id: None,
    };

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            instance_type_id: None,
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
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
            issue: None,
            is_repair_tenant: None,
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
        &vec![dpu_machine_id],
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
    delete_instance(&env, instance_id, &vec![dpu_machine_id], &host_machine_id).await;
}

#[crate::sqlx_test]
async fn test_instance_deletion_is_idempotent(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = common::api_fixtures::instance::TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    // We can call `release_instance` multiple times
    for i in 0..2 {
        env.api
            .release_instance(tonic::Request::new(InstanceReleaseRequest {
                id: Some(instance_id.into()),
                issue: None,
                is_repair_tenant: None,
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
    delete_instance(&env, instance_id, &vec![dpu_machine_id], &host_machine_id).await;

    // Release instance on non-existing instance should lead to a Not Found error
    let err = env
        .api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
            issue: None,
            is_repair_tenant: None,
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

#[crate::sqlx_test]
async fn test_can_not_create_2_instances_with_same_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;
    let (host_machine_id_2, _dpu_machine_id_2) = create_managed_host(&env).await;

    let config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
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
            instance_type_id: None,
            config: Some(config.clone()),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
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
            instance_type_id: None,
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
        }))
        .await;

    // TODO: Do not leak the full database error to users
    let err = result.expect_err("Expect instance creation to fail");
    assert!(err.message().contains("Database Error: error returned from database: duplicate key value violates unique constraint \"instances_pkey\""));
}

#[crate::sqlx_test]
async fn test_instance_cloud_init_metadata(
    _: PgPoolOptions,
    options: PgConnectOptions,
) -> eyre::Result<()> {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await?
        .unwrap();

    let request = tonic::Request::new(rpc::forge::CloudInitInstructionsRequest {
        ip: machine.interfaces[0].addresses[0].to_string(),
    });

    let response = env.api.get_cloud_init_instructions(request).await?;

    let Some(metadata) = response.into_inner().metadata else {
        panic!("The value for metadata should not have been None");
    };

    assert_eq!(metadata.instance_id, host_machine_id.to_string());

    let (instance_id, instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
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
    delete_instance(&env, instance_id, &vec![dpu_machine_id], &host_machine_id).await;

    Ok(())
}

#[crate::sqlx_test]
async fn test_instance_network_status_sync(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // TODO: The test is broken from here. This method already moves the instance
    // into READY state, which means most assertions that follow this won't test
    // anything new anymmore.
    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // When no network status has been observed, we report an interface
    // list with no IPs and MACs to the user
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let snapshot = snapshot.instance.unwrap();

    let (pf_segment, pf_addr) = snapshot.config.network.interfaces[0]
        .ip_addrs
        .iter()
        .next()
        .unwrap();

    let pf_instance_prefix = snapshot.config.network.interfaces[0]
        .interface_prefixes
        .get(pf_segment)
        .expect("Could not find matching interface_prefixes entry for pf_segment from ip_addrs.");

    let pf_gw = NetworkPrefix::find(&mut txn, pf_segment.into())
        .await
        .ok()
        .and_then(|pfx| pfx.gateway_cidr())
        .expect("Could not find gateway in network segment");

    let mut updated_network_status = InstanceNetworkStatusObservation {
        instance_config_version: Some(snapshot.config_version),
        config_version: snapshot.network_config_version,
        interfaces: vec![InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: vec![*pf_addr],
            prefixes: vec![*pf_instance_prefix],
            gateways: vec![IpNetwork::try_from(pf_gw.as_str()).expect("Invalid gateway")],
            network_security_group: Some(NetworkSecurityGroupStatusObservation {
                id: "c7c056c8-daa5-11ef-b221-c76a97b6c2ec".parse().unwrap(),
                source: rpc::forge::NetworkSecurityGroupSource::NsgSourceInstance
                    .try_into()
                    .unwrap(),
                version: "V1-T1".parse().unwrap(),
            }),
            internal_uuid: None,
        }],
        observed_at: Utc::now(),
    };

    update_instance_network_status_observation(&dpu_machine_id, &updated_network_status, &mut txn)
        .await;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let snapshot = snapshot.instance.unwrap();

    assert_eq!(
        snapshot.observations.network.values().next(),
        Some(&updated_network_status)
    );
    txn.commit().await.unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    let status = instance.status.as_ref().unwrap();
    assert_eq!(status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(
        status.network.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );
    assert_eq!(
        status.infiniband.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );
    assert_eq!(
        status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Ready
    );
    assert_eq!(
        status.network.as_ref().unwrap().interfaces,
        vec![rpc::InstanceInterfaceStatus {
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![pf_addr.to_string()],
            prefixes: vec![pf_instance_prefix.to_string()],
            gateways: vec![pf_gw.clone()],
            device: None,
            device_instance: 0u32,
        }]
    );

    let mut txn = env.pool.begin().await.unwrap();
    updated_network_status.interfaces[0].mac_address =
        Some(MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]).into());
    update_instance_network_status_observation(&dpu_machine_id, &updated_network_status, &mut txn)
        .await;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let snapshot = snapshot.instance.unwrap();

    assert_eq!(
        snapshot.observations.network.values().next(),
        Some(&updated_network_status)
    );
    txn.commit().await.unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    let status = instance.status.as_ref().unwrap();
    assert_eq!(status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(
        status.network.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );
    assert_eq!(
        status.infiniband.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );
    assert_eq!(
        status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Ready
    );
    assert_eq!(
        status.network.as_ref().unwrap().interfaces,
        vec![rpc::InstanceInterfaceStatus {
            virtual_function_id: None,
            mac_address: Some("11:12:13:14:15:16".to_string()),
            addresses: vec![pf_addr.to_string()],
            prefixes: vec![pf_instance_prefix.to_string()],
            gateways: vec![pf_gw.clone()],
            device: None,
            device_instance: 0u32,
        }]
    );

    // Assuming the config would change, the status should become unsynced again
    let mut txn = env.pool.begin().await.unwrap();
    let next_config_version = snapshot.network_config_version.increment();
    let (_,): (uuid::Uuid,) = sqlx::query_as(
        "UPDATE instances SET network_config_version=$1 WHERE id = $2::uuid returning id",
    )
    .bind(next_config_version.version_string())
    .bind(instance_id)
    .fetch_one(&mut *txn)
    .await
    .unwrap();
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let snapshot = snapshot.instance.unwrap();

    assert_eq!(
        snapshot.observations.network.values().next(),
        Some(&updated_network_status)
    );
    txn.commit().await.unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    let status = instance.status.as_ref().unwrap();
    assert_eq!(status.configs_synced(), rpc::SyncState::Pending);
    assert_eq!(
        status.network.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Pending
    );
    assert_eq!(
        status.infiniband.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );

    assert_eq!(
        status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Configuring
    );
    assert_eq!(
        status.network.as_ref().unwrap().interfaces,
        vec![rpc::InstanceInterfaceStatus {
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![],
            prefixes: vec![],
            gateways: vec![],
            device: None,
            device_instance: 0u32,
        }]
    );

    // When the observation catches up, we are good again
    // The extra VF is ignored
    let mut txn = env.pool.begin().await.unwrap();
    updated_network_status.config_version = next_config_version;
    updated_network_status
        .interfaces
        .push(InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::Virtual { id: 0 },
            mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
            addresses: vec!["127.1.2.3".parse().unwrap()],
            prefixes: vec!["127.1.2.3/32".parse().unwrap()],
            gateways: vec!["127.1.2.1".parse().unwrap()],
            network_security_group: Some(NetworkSecurityGroupStatusObservation {
                id: "c7c056c8-daa5-11ef-b221-c76a97b6c2ec".parse().unwrap(),
                source: rpc::forge::NetworkSecurityGroupSource::NsgSourceInstance
                    .try_into()
                    .unwrap(),
                version: "V1-T1".parse().unwrap(),
            }),
            internal_uuid: None,
        });

    update_instance_network_status_observation(&dpu_machine_id, &updated_network_status, &mut txn)
        .await;
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let snapshot = snapshot.instance.unwrap();
    assert_eq!(
        snapshot.observations.network.values().next(),
        Some(&updated_network_status)
    );
    txn.commit().await.unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    let status = instance.status.as_ref().unwrap();
    assert_eq!(status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(
        status.network.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );
    assert_eq!(
        status.infiniband.as_ref().unwrap().configs_synced(),
        rpc::SyncState::Synced
    );
    assert_eq!(
        status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Ready
    );
    assert_eq!(
        status.network.as_ref().unwrap().interfaces,
        vec![rpc::InstanceInterfaceStatus {
            virtual_function_id: None,
            mac_address: Some("11:12:13:14:15:16".to_string()),
            addresses: vec![pf_addr.to_string()],
            prefixes: vec![pf_instance_prefix.to_string()],
            gateways: vec![pf_gw.clone()],
            device: None,
            device_instance: 0u32,
        }]
    );

    // Drop the gateways and prefixes fields from the JSONB and ensure the rest of the
    // object is OK (to emulate older agents not sending gateways and prefixes in the status
    // observations).
    let mut txn = env.pool.begin().await.unwrap();
    let gateways_query = "UPDATE machines SET network_status_observation=jsonb_strip_nulls(jsonb_set(network_status_observation, '{instance_network_observation,interfaces,0,gateways}', 'null', false)) where id = $1 returning id";
    let prefixes_query = "UPDATE machines SET network_status_observation=jsonb_strip_nulls(jsonb_set(network_status_observation, '{instance_network_observation,interfaces,0,prefixes}', 'null', false)) where id = $1 returning id";

    let (_,): (MachineId,) = sqlx::query_as(gateways_query)
        .bind(dpu_machine_id)
        .fetch_one(txn.deref_mut())
        .await
        .expect("Database error rewriting JSON");

    let (_,): (MachineId,) = sqlx::query_as(prefixes_query)
        .bind(dpu_machine_id)
        .fetch_one(txn.deref_mut())
        .await
        .expect("Database error rewriting JSON");

    txn.commit().await.unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    let status = instance.status.as_ref().unwrap();
    assert_eq!(
        status.network.as_ref().unwrap().interfaces,
        vec![rpc::InstanceInterfaceStatus {
            virtual_function_id: None,
            mac_address: Some("11:12:13:14:15:16".to_string()),
            addresses: vec![pf_addr.to_string()],
            // prefixes and gateways should have been turned into empty arrays.
            prefixes: vec![],
            gateways: vec![],
            device: None,
            device_instance: 0u32,
        }]
    );

    delete_instance(&env, instance_id, &vec![dpu_machine_id], &host_machine_id).await;
}

#[crate::sqlx_test]
async fn test_can_not_create_instance_for_dpu(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let request = InstanceAllocationRequest {
        instance_id: InstanceId::from(uuid::Uuid::new_v4()),
        machine_id: dpu_machine_id,
        instance_type_id: None,
        config: InstanceConfig {
            os: default_os_config().try_into().unwrap(),
            tenant: default_tenant_config().try_into().unwrap(),
            network: InstanceNetworkConfig::for_segment_ids(&[segment_id], &Vec::default()),
            infiniband: InstanceInfinibandConfig::default(),
            storage: InstanceStorageConfig::default(),
            network_security_group_id: None,
        },
        metadata: Metadata {
            name: "test_instance".to_string(),
            description: "tests/instance".to_string(),
            labels: HashMap::new(),
        },
        allow_unhealthy_machine: false,
    };

    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    let result = allocate_instance(request, &env.pool, env.config.host_health).await;
    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is of type Dpu and can not be converted into an instance"),
        "Error message should contain 'is of type Dpu and can not be converted into an instance', but is {}",
        error
    );
}

#[crate::sqlx_test]
async fn test_instance_address_creation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (segment_id_1, segment_id_2) = env.create_vpc_and_dual_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id_1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id_2)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some((segment_id_1).into()),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((segment_id_2).into()),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            },
        ],
    };

    let (instance_id, _instance) = TestInstance::new(&env)
        .network(network)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id_1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id_2)
            .await
            .unwrap(),
        1
    );

    // TODO(chet): This will be where I also drop prefix allocation testing!

    // Check the allocated IP for the PF/primary interface.
    let allocated_ip_resolver = UsedOverlayNetworkIpResolver {
        segment_id: segment_id_1,
        busy_ips: vec![],
    };
    let used_ips = allocated_ip_resolver.used_ips(&mut txn).await.unwrap();
    let used_prefixes = allocated_ip_resolver.used_prefixes(&mut txn).await.unwrap();
    assert_eq!(1, used_ips.len());
    assert_eq!(1, used_prefixes.len());
    assert_eq!("192.0.4.3", used_ips[0].to_string());
    assert_eq!("192.0.4.3/32", used_prefixes[0].to_string());

    // Check the allocated VF.
    let allocated_ip_resolver = UsedOverlayNetworkIpResolver {
        segment_id: segment_id_2,
        busy_ips: vec![],
    };
    let used_ips = allocated_ip_resolver.used_ips(&mut txn).await.unwrap();
    let used_prefixes = allocated_ip_resolver.used_prefixes(&mut txn).await.unwrap();
    assert_eq!(1, used_ips.len());
    assert_eq!(1, used_prefixes.len());
    assert_eq!("192.1.4.3", used_ips[0].to_string());
    assert_eq!("192.1.4.3/32", used_prefixes[0].to_string());

    // And make sure find_by_prefix works -- just leverage
    // the last used_prefixes prefix and make sure it matches
    // the allocated instance ID.
    let address_by_prefix = InstanceAddress::find_by_prefix(&mut txn, used_prefixes[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        instance_id.to_string(),
        address_by_prefix.instance_id.to_string()
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
    assert_eq!(network_config.tenant_interfaces.len(), 2);
    assert_eq!(network_config.tenant_interfaces[0].ip, "192.0.4.3");
    assert_eq!(network_config.tenant_interfaces[1].ip, "192.1.4.3");
    assert_eq!(network_config.dpu_network_pinger_type, None);
    // Ensure the VPC prefixes (which in this case are the two network segment
    // IDs referenced above) are both associated with both interfaces.
    let expected_vpc_prefixes = vec!["192.0.4.0/24".to_string(), "192.1.4.0/24".to_string()];
    assert_eq!(
        network_config.tenant_interfaces[0].vpc_prefixes,
        expected_vpc_prefixes
    );
    assert_eq!(
        network_config.tenant_interfaces[1].vpc_prefixes,
        expected_vpc_prefixes
    );
}

#[crate::sqlx_test]
async fn test_cannot_create_instance_on_unhealthy_dpu(
    _: PgPoolOptions,
    options: PgConnectOptions,
) -> eyre::Result<()> {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // Report an unhealthy DPU
    network_configured_with_health(
        &env,
        &dpu_machine_id,
        Some(rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            observed_at: None,
            successes: vec![],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: "everything".to_string(),
                target: None,
                in_alert_since: None,
                message: "test_cannot_create_instance_on_unhealthy_dpu".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations().to_string(),
                    health_report::HealthAlertClassification::prevent_host_state_changes()
                        .to_string(),
                ],
            }],
        }),
    )
    .await;

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            instance_type_id: None,
            config: Some(rpc::InstanceConfig {
                os: Some(default_os_config()),
                tenant: Some(default_tenant_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
        }))
        .await;
    let Err(err) = result else {
        panic!("Creating an instance should have been refused");
    };
    if err.code() != tonic::Code::FailedPrecondition {
        panic!("Expected grpc code FailedPrecondition, got {}", err.code());
    }
    assert_eq!(
        err.message(),
        "Host is not available for allocation due to health probe alert"
    );
    Ok(())
}

#[crate::sqlx_test]
async fn test_create_instance_with_allow_unhealthy_machine_true(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // Report an unhealthy DPU
    network_configured_with_health(
        &env,
        &dpu_machine_id,
        Some(rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            observed_at: None,
            successes: vec![],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: "everything".to_string(),
                target: None,
                in_alert_since: None,
                message: "test_cannot_create_instance_on_unhealthy_dpu".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations().to_string(),
                    health_report::HealthAlertClassification::prevent_host_state_changes()
                        .to_string(),
                ],
            }],
        }),
    )
    .await;

    let instance_id = uuid::Uuid::new_v4();
    let rpc_instance_id: rpc::Uuid = instance_id.into();

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: Some(rpc_instance_id.clone()),
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            instance_type_id: None,
            config: Some(rpc::InstanceConfig {
                os: Some(default_os_config()),
                tenant: Some(default_tenant_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            }),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: true,
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

#[crate::sqlx_test]
async fn test_instance_phone_home(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut os = default_os_config();
    os.phone_home_enabled = true;
    let instance_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(os),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
    };

    let (instance_id, _instance) = TestInstance::new(&env)
        .config(instance_config)
        .create(&[dpu_machine_id], &host_machine_id)
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

#[crate::sqlx_test]
async fn test_bootingwithdiscoveryimage_delay(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
            issue: None,
            is_repair_tenant: None,
        }))
        .await
        .expect("Delete instance failed.");

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        1,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: crate::model::machine::RetryInfo { count: 0 },
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
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    txn.commit().await.unwrap();

    update_time_params(&env.pool, &host, 1, None).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        1,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: crate::model::machine::RetryInfo { count: 1 },
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
        &vec![dpu_machine_id],
        &host_machine_id,
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

#[crate::sqlx_test]
async fn test_create_instance_duplicate_keyset_ids(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
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
            hostname: Some("test-instance".to_string()),
        }),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
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
            instance_type_id: None,
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .expect_err("Duplicate TenantKeyset IDs should not be accepted");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "Duplicate Tenant KeySet ID found: bad_id");
}

#[crate::sqlx_test]
async fn test_create_instance_keyset_ids_max(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
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
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string(),
                "f".to_string(),
                "g".to_string(),
                "h".to_string(),
                "i".to_string(),
                "j".to_string(),
                "k".to_string(),
            ],
            hostname: Some("test-hostname".to_string()),
        }),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
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
            instance_type_id: None,
            config: Some(config),
            metadata: Some(rpc::Metadata {
                name: "test_instance".to_string(),
                description: "tests/instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .expect_err("More than 10 TenantKeyset IDs should not be accepted");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "More than 10 Tenant KeySet IDs are not allowed"
    );
}

#[crate::sqlx_test]
async fn test_allocate_instance_with_old_network_segemnt(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_metadata = rpc::forge::Metadata {
        name: "test_instance_with_labels".to_string(),
        description: "this instance does not have labels.".to_string(),
        labels: vec![],
    };

    let device_locator = DeviceLocator {
        device: "DPU1".to_string(),
        device_instance: 0,
    };
    let mut nw_config =
        interface_network_config_with_devices(&[segment_id], &[device_locator.clone()]);
    for interface in &mut nw_config.interfaces {
        interface.network_details = None;
    }

    let (instance_id, _instance) = TestInstance::new(&env)
        .network(nw_config)
        .metadata(instance_metadata.clone())
        .create(&[dpu_machine_id], &host_machine_id)
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

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();
    assert_eq!(fetched_instance.machine_id, host_machine_id);

    let network_config = fetched_instance.config.network;
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config;
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
        iface.internal_uuid = uuid::Uuid::nil();
    }

    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_ids(&[segment_id], &[device_locator],)
    );
}

#[crate::sqlx_test]
async fn test_allocate_network_vpc_prefix_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc = Vpc::find_by_name(&mut env.pool.begin().await.unwrap(), "test vpc 1")
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let vpc_prefix_id = create_tenant_overlay_prefix(&env, vpc.id).await;

    let x = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: 0,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(
                    vpc_prefix_id.into(),
                ),
            ),
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
        }],
    };

    let config = rpc::InstanceConfig {
        tenant: Some(rpc::TenantConfig {
            tenant_organization_id: "abc".to_string(),
            user_data: None,
            custom_ipxe: "exit".to_string(),
            always_boot_with_custom_ipxe: false,
            phone_home_enabled: false,
            hostname: Some("xyz".to_string()),
            tenant_keyset_ids: vec![],
        }),
        os: Some(OperatingSystem {
            phone_home_enabled: false,
            run_provisioning_instructions_on_every_boot: false,
            user_data: Some("".to_string()),
            variant: Some(rpc::forge::operating_system::Variant::OsImageId(
                rpc::Uuid {
                    value: uuid::Uuid::new_v4().to_string(),
                },
            )),
        }),
        network: Some(x),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
    };

    let mut config: InstanceConfig = config.try_into().unwrap();

    assert!(config.network.interfaces[0].network_segment_id.is_none());

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    allocate_network(&mut config.network, &mut txn)
        .await
        .unwrap();

    txn.commit().await.unwrap();
    assert!(config.network.interfaces[0].network_segment_id.is_some());

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let network_segment = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(
            IdColumn,
            &config.network.interfaces[0].network_segment_id.unwrap(),
        ),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    let np = network_segment[0].prefixes[0].prefix;
    match np {
        IpNetwork::V4(ipv4_network) => assert_eq!(
            Ipv4Addr::from_str("10.217.5.224").unwrap(),
            ipv4_network.network()
        ),
        IpNetwork::V6(_) => panic!("Can not be ipv6."),
    }
}

#[crate::sqlx_test]
async fn test_allocate_and_release_instance_vpc_prefix_id(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    let mut vpc = Vpc::find_by_name(&mut txn, "test vpc 1").await.unwrap();
    let vpc = vpc.remove(0);

    let update_vpc = UpdateVpcVirtualization {
        id: vpc.id,
        if_version_match: None,
        network_virtualization_type: forge_network::virtualization::VpcVirtualizationType::Fnn,
    };
    update_vpc.update(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let vpc_prefix_id = create_tenant_overlay_prefix(&env, vpc.id).await;
    let vpc_prefix = env
        .api
        .get_vpc_prefixes(tonic::Request::new(rpc::forge::VpcPrefixGetRequest {
            vpc_prefix_ids: vec![rpc::Uuid {
                value: vpc_prefix_id.to_string(),
            }],
        }))
        .await
        .unwrap()
        .into_inner()
        .vpc_prefixes[0]
        .clone();

    assert_eq!(vpc_prefix.total_31_segments, 16);
    assert_eq!(vpc_prefix.available_31_segments, 16);

    let (instance_id, _instance) = TestInstance::new(&env)
        .network(single_interface_network_config_with_vpc_prefix(rpc::Uuid {
            value: vpc_prefix_id.to_string(),
        }))
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let vpc_prefix = env
        .api
        .get_vpc_prefixes(tonic::Request::new(rpc::forge::VpcPrefixGetRequest {
            vpc_prefix_ids: vec![rpc::Uuid {
                value: vpc_prefix_id.to_string(),
            }],
        }))
        .await
        .unwrap()
        .into_inner()
        .vpc_prefixes[0]
        .clone();

    assert_eq!(vpc_prefix.total_31_segments, 16);
    assert_eq!(vpc_prefix.available_31_segments, 15);

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
            expected_tenant_config.user_data = expected_os.user_data.clone();
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

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();
    assert_eq!(fetched_instance.machine_id, host_machine_id);
    assert_eq!(
        InstanceAddress::count_by_segment_id(
            &mut txn,
            &fetched_instance.config.network.interfaces[0]
                .network_segment_id
                .unwrap()
        )
        .await
        .unwrap(),
        1
    );

    let ns_id = fetched_instance.config.network.interfaces[0]
        .network_segment_id
        .unwrap();

    let ns = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(db::network_segment::IdColumn, &ns_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();
    let ns = ns.first().unwrap();

    assert!(ns.vlan_id.is_none());
    assert!(ns.vni.is_none());

    let network_config = fetched_instance.config.network.clone();
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
        iface.network_segment_id = None;
        iface.internal_uuid = uuid::Uuid::nil();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_vpc_prefix_id(vpc_prefix_id.into(), Some(dpu_machine_id))
    );

    assert!(!fetched_instance.observations.network.is_empty());
    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(&host_machine_id, false, &mut txn).await;
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &host_machine_id,
        db::managed_host::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let fetched_instance = snapshot.instance.unwrap();

    assert!(!fetched_instance.use_custom_pxe_on_boot);
    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut ns = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(
            IdColumn,
            &fetched_instance.config.network.interfaces[0]
                .network_segment_id
                .unwrap(),
        ),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    let ns = ns.remove(0);

    let record = InstanceAddress::find_by_instance_id_and_segment_id(
        &mut txn,
        &fetched_instance.id,
        ns.id(),
    )
    .await
    .unwrap()
    .unwrap();

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address.to_string(), "10.217.5.225");
    assert_eq!(
        &record.address,
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );

    assert_eq!(
        format!("{}/32", &record.address),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
    );

    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    delete_instance(&env, instance_id, &vec![dpu_machine_id], &host_machine_id).await;

    let segment_ids = fetched_instance
        .config
        .network
        .interfaces
        .iter()
        .filter_map(|x| match x.network_details {
            Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
            _ => None,
        })
        .collect_vec();

    // Address is freed during delete
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let network_segments = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::List(IdColumn, &segment_ids),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    assert!(network_segments.is_empty());

    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    assert_eq!(
        InstanceAddress::count_by_segment_id(
            &mut txn,
            &fetched_instance.config.network.interfaces[0]
                .network_segment_id
                .unwrap()
        )
        .await
        .unwrap(),
        0
    );
    let vpc_prefix = env
        .api
        .get_vpc_prefixes(tonic::Request::new(rpc::forge::VpcPrefixGetRequest {
            vpc_prefix_ids: vec![rpc::Uuid {
                value: vpc_prefix_id.to_string(),
            }],
        }))
        .await
        .unwrap()
        .into_inner()
        .vpc_prefixes[0]
        .clone();

    assert_eq!(vpc_prefix.total_31_segments, 16);
    assert_eq!(vpc_prefix.available_31_segments, 16);
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_vpc_prefix_handling(pool: PgPool) {
    // This test requires there to be no default network segments created
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;

    // Make a VPC and prefix
    let vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            network_security_group_id: None,
            name: "test vpc 1".to_string(),
            tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let vpc_id: forge_uuid::vpc::VpcId = vpc.id.as_ref().unwrap().clone().try_into().unwrap();
    let vpc_prefix_id = create_tenant_overlay_prefix(&env, vpc_id).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let allocator = Ipv4PrefixAllocator::new(
        // 15 IPs
        vpc_prefix_id,
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        None,
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(&mut txn, vpc_id)
        .await
        .unwrap();

    let ns1 = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(IdColumn, &ns_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    let address1 = match ns1[0].prefixes[0].prefix {
        IpNetwork::V4(ipv4_network) => ipv4_network.network(),
        IpNetwork::V6(_) => panic!("cant be ipv6"),
    };

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let allocator = Ipv4PrefixAllocator::new(
        vpc_prefix_id,
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        None,
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(&mut txn, vpc_id)
        .await
        .unwrap();

    let ns2 = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(IdColumn, &ns_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    let address2 = match ns2[0].prefixes[0].prefix {
        IpNetwork::V4(ipv4_network) => ipv4_network.network(),
        IpNetwork::V6(_) => panic!("cant be ipv6"),
    };

    txn.commit().await.unwrap();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let allocator = Ipv4PrefixAllocator::new(
        vpc_prefix_id,
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        None,
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(&mut txn, vpc_id)
        .await
        .unwrap();

    let ns3 = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(IdColumn, &ns_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    let address3 = match ns3[0].prefixes[0].prefix {
        IpNetwork::V4(ipv4_network) => ipv4_network.network(),
        IpNetwork::V6(_) => panic!("cant be ipv6"),
    };

    txn.commit().await.unwrap();
    // The allocation should take care of already assigned prefixes and should not allocate twice.
    assert_eq!(Ipv4Addr::new(10, 217, 5, 224), address1);
    assert_eq!(Ipv4Addr::new(10, 217, 5, 226), address2);
    assert_eq!(Ipv4Addr::new(10, 217, 5, 228), address3);
    assert_ne!(address1, address2);
    assert_ne!(address1, address3);
    assert_ne!(address2, address3);

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let allocator = Ipv4PrefixAllocator::new(
        vpc_prefix_id,
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        Some(Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 234), 31).unwrap()),
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(&mut txn, vpc_id)
        .await
        .unwrap();

    let ns4 = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(IdColumn, &ns_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();

    let address4 = match ns4[0].prefixes[0].prefix {
        IpNetwork::V4(ipv4_network) => ipv4_network.network(),
        IpNetwork::V6(_) => panic!("cant be ipv6"),
    };

    txn.commit().await.unwrap();

    assert_eq!(Ipv4Addr::new(10, 217, 5, 236), address4);
}

async fn create_tenant_overlay_prefix(
    env: &TestEnv,
    vpc_id: forge_uuid::vpc::VpcId,
) -> VpcPrefixId {
    let mut txn = env.pool.begin().await.unwrap();
    let vpc_prefix_id = crate::db::vpc_prefix::NewVpcPrefix {
        id: uuid::Uuid::new_v4().into(),
        prefix: IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap()),
        name: "vpc_prefix_1".to_string(),
        vpc_id,
    }
    .persist(&mut txn)
    .await
    .unwrap()
    .id;
    txn.commit().await.unwrap();
    vpc_prefix_id
}

#[crate::sqlx_test]
async fn test_allocate_with_instance_type_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Create two new managed hosts in the DB and get the snapshot.
    let mh = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let mh2 = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    // Find the existing instance types in the test env
    let existing_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    let existing_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: existing_instance_type_ids,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    let good_id = existing_instance_types[0].id.clone();
    let bad_id = existing_instance_types[1].id.clone();

    // Associate the machine with an instance type
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: good_id.clone(),
                machine_ids: vec![
                    mh.host_snapshot.id.to_string(),
                    mh2.host_snapshot.id.to_string(),
                ],
            },
        ))
        .await
        .unwrap();

    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Try to create an instance type, but pretend like the
    // instance type of the machine changed by the time we
    // requested the allocation, and call with the wrong ID.
    // This should fail.
    let _ = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                network_security_group_id: None,
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
            }),
            instance_id: None,
            instance_type_id: Some(bad_id.clone()),
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap_err();

    // Try that again, but this time with the right ID
    // This should pass.
    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                network_security_group_id: None,
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
            }),
            instance_id: None,
            instance_type_id: Some(good_id.clone()),
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(good_id, instance.instance_type_id.unwrap());

    // Look-up the instance and make sure we really
    // stored the instance type.
    let instance = env
        .api
        .find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
            instance_ids: vec![instance.id.unwrap()],
        }))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop()
        .unwrap();

    assert_eq!(good_id, instance.instance_type_id.unwrap());

    // Try that one more time, but this time with no type id
    // to see if we inherit it from the machine.
    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh2.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                network_security_group_id: None,
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(good_id, instance.instance_type_id.unwrap());

    Ok(())
}

#[crate::sqlx_test]
async fn test_allocate_and_update_with_network_security_group(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    populate_network_security_groups(env.api.clone()).await;

    // NSG ID of and NSG for the default tenant provided by fixtures.
    let good_network_security_group_id = Some("fd3ab096-d811-11ef-8fe9-7be4b2483448".to_string());

    // NSG ID of not-the-default-tenant provided by fixtures.
    let bad_network_security_group_id = Some("ddfcabc4-92dc-41e2-874e-2c7eeb9fa156".to_string());

    // Create a new managed host in the DB and get the snapshot.
    let mh = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Try to create an instance, but send in a valid and
    // existing NSG ID that doesn't match the tenant of
    // instance being created.
    // This should fail.
    let _ = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: bad_network_security_group_id.clone(),
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap_err();

    // Try that once more, but with an NSG ID
    // that has the same tenant as the instance.
    let i = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: good_network_security_group_id.clone(),
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap()
        .into_inner();

    // Check that the instance actually has the ID we expect
    assert_eq!(
        i.config.unwrap().network_security_group_id,
        good_network_security_group_id
    );

    let instance_id = i.id.unwrap().clone();

    // Now update to remove the NSG attachment.
    let i = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(single_interface_network_config(segment_id)),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: None,
                }),
                instance_id: Some(instance_id.clone()),
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // Check that the instance no longer has an NSG ID
    assert!(i.config.unwrap().network_security_group_id.is_none());

    // Now try to update it again and try to add the NSG with the mismatched tenant org
    // Now update to remove the NSG attachment.
    let _ = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(single_interface_network_config(segment_id)),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: bad_network_security_group_id.clone(),
                }),
                instance_id: Some(instance_id.clone()),
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap_err();

    // Now try to update it again and but with a good NSG
    let i = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(single_interface_network_config(segment_id)),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: good_network_security_group_id.clone(),
                }),
                instance_id: Some(instance_id.clone()),
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // Check that the instance actually has the ID we expect
    assert_eq!(
        i.config.unwrap().network_security_group_id,
        good_network_security_group_id
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_network_details_migration(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // We'll try three cases here:
    // Instance with interfaces that have only network_segment_id, which should end up with a new network_details k/v.
    // Instance with interfaces that have both network_segment_id and network_details, which should be left unchanged.
    // Instance with vpc prefix, which should be left unchanged.

    // There won't be any cases of only network_details because sending in network_details ends up setting network_segment_id.

    // Create a new managed host in the DB and get the snapshot.
    let mh_without_network_details = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let mh_without_segment_id = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let mh_with_vpc_prefix = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Create an instance with only network_segment_id
    let i = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh_without_network_details.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(rpc::InstanceNetworkConfig {
                    interfaces: vec![rpc::InstanceInterfaceConfig {
                        function_type: rpc::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(segment_id.into()),
                        network_details: None,
                        device: None,
                        device_instance: 0,
                        virtual_function_id: None,
                    }],
                }),
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap()
        .into_inner();

    let i1_id = i.id.unwrap();

    // Remove the network_details that we auto-populate now.
    let mut conn = env.pool.acquire().await.unwrap();
    sqlx::query(
        "UPDATE instances i
    SET network_config=jsonb_set(
        network_config,
        '{interfaces}',
        (
            select jsonb_agg(ba.value) from (
                SELECT
                    ifc_ttable.value - 'network_details' as value
                FROM jsonb_array_elements(i.network_config #>'{interfaces}') as ifc_ttable
           ) as ba
        )
    );",
    )
    .execute(conn.as_mut())
    .await
    .unwrap();

    // Find the instance to confirm the state we expect.
    let i = env
        .api
        .find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
            instance_ids: vec![i1_id.clone()],
        }))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop()
        .unwrap();

    // Check that the instance actually has the ID we expect
    assert_eq!(
        i.config.clone().unwrap().network.unwrap().interfaces[0].network_segment_id,
        Some(segment_id.into())
    );

    // We expect that we've cleared the value with our raw query.
    assert!(
        i.config.unwrap().network.unwrap().interfaces[0]
            .network_details
            .is_none(),
    );

    // Create an instance with network_details
    let i = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh_without_segment_id.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(rpc::InstanceNetworkConfig {
                    interfaces: vec![rpc::InstanceInterfaceConfig {
                        function_type: rpc::InterfaceFunctionType::Physical as i32,
                        network_segment_id: None,
                        network_details: Some(
                            rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                                segment_id.into(),
                            ),
                        ),
                        device: None,
                        device_instance: 0,
                        virtual_function_id: None,
                    }],
                }),
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap()
        .into_inner();

    let i2_id = i.id.unwrap();

    // Check that the instance actually has the ID we expect
    assert_eq!(
        i.config.clone().unwrap().network.unwrap().interfaces[0].network_details,
        Some(rpc::forge::instance_interface_config::NetworkDetails::SegmentId(segment_id.into()))
    );

    assert_eq!(
        i.config.unwrap().network.unwrap().interfaces[0].network_segment_id,
        Some(segment_id.into())
    );

    // Create an instance with vpc-prefix
    let ip_prefix = "192.1.4.0/24";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let vpc_prefix = env
        .api
        .create_vpc_prefix(tonic::Request::new(rpc::forge::VpcPrefixCreationRequest {
            id: None,
            prefix: ip_prefix.into(),
            name: "Test VPC prefix".into(),
            vpc_id: Some(vpc_id.into()),
        }))
        .await
        .unwrap()
        .into_inner();

    let vpc_prefix_id = vpc_prefix.id.unwrap();

    let i = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh_with_vpc_prefix.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(rpc::InstanceNetworkConfig {
                    interfaces: vec![rpc::InstanceInterfaceConfig {
                        function_type: rpc::InterfaceFunctionType::Physical as i32,
                        network_segment_id: None,
                        network_details: Some(
                            rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(
                                vpc_prefix_id.clone(),
                            ),
                        ),
                        device: None,
                        device_instance: 0,
                        virtual_function_id: None,
                    }],
                }),
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
            allow_unhealthy_machine: false,
        }))
        .await
        .unwrap()
        .into_inner();

    let i3_id = i.id.unwrap();

    assert_eq!(
        i.config.clone().unwrap().network.unwrap().interfaces[0].network_details,
        Some(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(vpc_prefix_id))
    );

    // Run the migration
    let mut conn = env.pool.acquire().await.unwrap();
    sqlx::query(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/20250505194055_network_segment_id_to_network_details.sql"
    )))
    .execute(conn.as_mut())
    .await
    .unwrap();

    // Now go see if the instances are all still in an expected state.

    validate_post_migration_instance_network_config(&env, i1_id, Some(segment_id.into())).await;
    validate_post_migration_instance_network_config(&env, i2_id, Some(segment_id.into())).await;
    validate_post_migration_instance_network_config(&env, i3_id, None).await;

    Ok(())
}

pub async fn validate_post_migration_instance_network_config(
    env: &TestEnv,
    instance_id: rpc::common::Uuid,
    segment_id: Option<rpc::common::Uuid>,
) {
    let i = env
        .api
        .find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
            instance_ids: vec![instance_id],
        }))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop()
        .unwrap();

    match segment_id {
        // If we originated from network_segment_id or NetworkDetails::SegmentId
        // check that everything matches.
        Some(id) => {
            assert_eq!(
                i.config.clone().unwrap().network.unwrap().interfaces[0].network_details,
                Some(rpc::forge::instance_interface_config::NetworkDetails::SegmentId(id.clone()))
            );

            assert_eq!(
                i.config.unwrap().network.unwrap().interfaces[0].network_segment_id,
                Some(id)
            );
        }
        // If we originated from NetworkDetails::VpcPrefixId
        // we just need to confirm that it's still in that state.
        // The migration doesn't touch network_segment_id in the DB.
        None => {
            assert!(matches!(
                i.config.clone().unwrap().network.unwrap().interfaces[0].network_details,
                Some(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(_))
            ));
            assert!(
                i.config.unwrap().network.unwrap().interfaces[0]
                    .network_segment_id
                    .is_some(),
            );
        }
    }
}

#[crate::sqlx_test]
async fn test_allocate_and_update_network_config_instance(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (segment_id, segment_id2) = env.create_vpc_and_dual_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
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

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced,
        SyncState::Synced as i32
    );

    let new_network_config = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                    segment_id2.into(),
                ),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
        }],
    };

    // Now update to change network config.
    let _ = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(new_network_config),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: None,
                }),
                instance_id: instance.id,
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap();

    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced,
        SyncState::Pending as i32
    );

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let instance = crate::db::instance::Instance::find_by_id(
        &mut txn,
        uuid::Uuid::from_str(&instance.id.clone().unwrap().value)
            .unwrap()
            .into(),
    )
    .await
    .unwrap()
    .unwrap();

    txn.rollback().await.unwrap();

    assert!(instance.update_network_config_request.is_some());
    let update_req = instance.update_network_config_request.unwrap();
    let expected = NetworkDetails::NetworkSegment(segment_id2);

    assert_eq!(
        expected,
        update_req.new_config.interfaces[0]
            .network_details
            .clone()
            .unwrap(),
    );
}

#[crate::sqlx_test]
async fn test_allocate_and_update_network_config_instance_add_vf(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (segment_id, segment_id2) = env.create_vpc_and_dual_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
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

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced,
        SyncState::Synced as i32
    );

    let instance_id_rpc = instance.id.clone();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let instance = crate::db::instance::Instance::find_by_id(
        &mut txn,
        uuid::Uuid::from_str(&instance.id.clone().unwrap().value)
            .unwrap()
            .into(),
    )
    .await
    .unwrap()
    .unwrap();

    let current_ip = instance.config.network.interfaces[0]
        .ip_addrs
        .values()
        .collect_vec()
        .first()
        .copied()
        .unwrap();

    txn.rollback().await.unwrap();

    let new_network_config = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                        segment_id.into(),
                    ),
                ),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                        segment_id2.into(),
                    ),
                ),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
        ],
    };

    // Now update to change network config.
    let _ = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(new_network_config),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: None,
                }),
                instance_id: instance_id_rpc,
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap();

    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced,
        SyncState::Pending as i32
    );

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let instance = crate::db::instance::Instance::find_by_id(
        &mut txn,
        uuid::Uuid::from_str(&instance.id.clone().unwrap().value)
            .unwrap()
            .into(),
    )
    .await
    .unwrap()
    .unwrap();

    txn.rollback().await.unwrap();

    assert!(instance.update_network_config_request.is_some());
    let update_req = instance.update_network_config_request.unwrap();

    assert_eq!(
        NetworkDetails::NetworkSegment(segment_id),
        update_req.new_config.interfaces[0]
            .network_details
            .clone()
            .unwrap(),
    );

    assert_eq!(
        NetworkDetails::NetworkSegment(segment_id2),
        update_req.new_config.interfaces[1]
            .network_details
            .clone()
            .unwrap(),
    );

    // The first physical interface IP must not be changed.
    let updated_config_ip = instance.config.network.interfaces[0]
        .ip_addrs
        .values()
        .collect_vec()
        .first()
        .copied()
        .unwrap();

    assert_eq!(current_ip, updated_config_ip);
}

// IP should not be changed.
// deleted vf id must not be present.
#[crate::sqlx_test]
async fn test_update_instance_config_vpc_prefix_network_update_delete_vf(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let _segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.0.5.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: ip_prefix.into(),
        name: "Test VPC prefix".into(),
        vpc_id: Some(vpc_id.into()),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env
        .api
        .create_vpc_prefix(request)
        .await
        .unwrap()
        .into_inner();

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: Some(0),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: Some(1),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: Some(2),
            },
        ],
    };

    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(network.clone()),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let (instance_id, _instance) = TestInstance::new(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    let interfaces_status = instance.clone().status.unwrap().network.unwrap().interfaces;
    let old_addresses = interfaces_status
        .iter()
        .filter_map(|x| {
            if let Some(vf_id) = x.virtual_function_id {
                if vf_id != 1 {
                    Some(x.addresses.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .flatten()
        .sorted()
        .collect_vec();

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

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: Some(0),
            },
            // VF 1 is deleted.
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: Some(2),
            },
        ],
    };
    let mut updated_config_1 = initial_config.clone();
    updated_config_1.network = Some(network);
    let updated_metadata_1 = rpc::Metadata {
        name: "Name2".to_string(),
        description: "Desc2".to_string(),
        labels: vec![rpc::forge::Label {
            key: "Key1".to_string(),
            value: None,
        }],
    };

    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(updated_config_1.clone()),
                metadata: Some(updated_metadata_1.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // SyncState::Synced means network config update is not applicable.
    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced(),
        rpc::forge::SyncState::Pending
    );

    env.run_machine_state_controller_iteration().await;
    // Run network state machine handler here.
    env.run_network_segment_controller_iteration().await;

    env.run_machine_state_controller_iteration().await;
    network_configured(&env, &vec![dpu_machine_id]).await;
    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let state =
        crate::db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();
    let state = state.current_state();
    println!("{state:?}");
    assert!(matches!(
        state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));

    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    let interfaces = instance.config.unwrap().network.unwrap().interfaces;
    let mut vf_ids = interfaces
        .iter()
        .filter_map(|x| {
            if x.function_type == InterfaceFunctionType::Virtual as i32 {
                x.virtual_function_id
            } else {
                None
            }
        })
        .collect_vec();

    let interfaces_status = instance.status.unwrap().network.unwrap().interfaces;
    let addresses = interfaces_status
        .iter()
        .filter_map(|x| x.virtual_function_id.map(|_vf_id| x.addresses.clone()))
        .flatten()
        .sorted()
        .collect_vec();

    vf_ids.sort();
    let expected = vec![0, 2];

    assert_eq!(expected, vf_ids);
    assert_eq!(old_addresses, addresses);
}

#[crate::sqlx_test]
async fn test_allocate_and_update_network_config_instance_state_machine(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (segment_id, segment_id2) = env.create_vpc_and_dual_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let (instance_id, _instance) = TestInstance::new(&env)
        .single_interface_network_config(segment_id)
        .create(&[dpu_machine_id], &host_machine_id)
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

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced,
        SyncState::Synced as i32
    );

    let new_network_config = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                    segment_id2.into(),
                ),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
        }],
    };

    // Now update to change network config.
    let _ = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(new_network_config),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: None,
                }),
                instance_id: instance.id,
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap();

    // Instance should move to NetworkConfigUpdateState::WaitingForNetworkSegmentToBeReady
    env.run_machine_state_controller_iteration().await;
    // Instance should move to NetworkConfigUpdateState::WaitingForConfigSynced
    env.run_machine_state_controller_iteration().await;
    // and stay there only.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let current_state =
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();
    let current_state = current_state.current_state();
    println!("Current State: {}", current_state);
    assert!(matches!(
        current_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced
            }
        }
    ));
    txn.rollback().await.unwrap();

    // - forge-dpu-agent gets an instance network to configure, reports it configured
    network_configured(&env, &vec![dpu_machine_id]).await;
    // Move to ReleaseOldResources state.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::ReleaseOldResources
            }
        }
    ));
    txn.rollback().await.unwrap();
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.rollback().await.unwrap();
}

#[crate::sqlx_test]
async fn test_update_instance_config_vpc_prefix_network_update_state_machine(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let _segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.1.4.0/25";
    let vpc_id = common::api_fixtures::get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: ip_prefix.into(),
        name: "Test VPC prefix".into(),
        vpc_id: Some(vpc_id.into()),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env
        .api
        .create_vpc_prefix(request)
        .await
        .unwrap()
        .into_inner();

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: response
                .id
                .clone()
                .map(::rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
        }],
    };

    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(network.clone()),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let (instance_id, _instance) = TestInstance::new(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .create(&[dpu_machine_id], &host_machine_id)
        .await;

    let mut instances = env.find_instances(Some(instance_id.into())).await.instances;
    assert_eq!(instances.len(), 1);
    let instance = instances.remove(0);

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Synced
    );

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

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(::rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response
                    .id
                    .clone()
                    .map(::rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
        ],
    };
    let mut updated_config_1 = initial_config.clone();
    updated_config_1.network = Some(network);
    let updated_metadata_1 = rpc::Metadata {
        name: "Name2".to_string(),
        description: "Desc2".to_string(),
        labels: vec![rpc::forge::Label {
            key: "Key1".to_string(),
            value: None,
        }],
    };

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segments = NetworkSegment::find_ids(&mut txn, NetworkSegmentSearchFilter::default())
        .await
        .unwrap();

    let old_length = segments.len();
    txn.rollback().await.unwrap();

    let _instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(updated_config_1.clone()),
                metadata: Some(updated_metadata_1.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segments = NetworkSegment::find_ids(&mut txn, NetworkSegmentSearchFilter::default())
        .await
        .unwrap();

    let new_length = segments.len();
    txn.rollback().await.unwrap();

    // A new network segment must be created.
    assert_eq!(old_length + 1, new_length);

    // Instance should move to NetworkConfigUpdateState::WaitingForNetworkSegmentToBeReady
    env.run_machine_state_controller_iteration().await;
    // and stay there only.
    env.run_machine_state_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;
    // Instance should move to NetworkConfigUpdateState::WaitingForConfigSynced
    env.run_machine_state_controller_iteration().await;
    // and stay there only.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let current_state =
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();
    let current_state = current_state.current_state();
    println!("Current State: {}", current_state);
    assert!(matches!(
        current_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced
            }
        }
    ));
    txn.rollback().await.unwrap();

    // - forge-dpu-agent gets an instance network to configure, reports it configured
    network_configured(&env, &vec![dpu_machine_id]).await;
    // Move to ReleaseOldResources state.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::ReleaseOldResources
            }
        }
    ));
    txn.rollback().await.unwrap();
    env.run_machine_state_controller_iteration().await;
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.rollback().await.unwrap();
}

#[crate::sqlx_test]
async fn test_allocate_network_multi_dpu_vpc_prefix_id(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc = Vpc::find_by_name(&mut env.pool.begin().await.unwrap(), "test vpc 1")
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let vpc_prefix_id = create_tenant_overlay_prefix(&env, vpc.id).await;

    let network_config = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: 0,
                network_segment_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(
                        vpc_prefix_id.into(),
                    ),
                ),
                device: Some("BlueField SoC".to_string()),
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: 0,
                network_segment_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(
                        vpc_prefix_id.into(),
                    ),
                ),
                device: Some("BlueField SoC".to_string()),
                device_instance: 1,
                virtual_function_id: None,
            },
        ],
    };

    let config = rpc::InstanceConfig {
        tenant: Some(rpc::TenantConfig {
            tenant_organization_id: "abc".to_string(),
            user_data: None,
            custom_ipxe: "exit".to_string(),
            always_boot_with_custom_ipxe: false,
            phone_home_enabled: false,
            hostname: Some("xyz".to_string()),
            tenant_keyset_ids: vec![],
        }),
        os: Some(OperatingSystem {
            phone_home_enabled: false,
            run_provisioning_instructions_on_every_boot: false,
            user_data: Some("".to_string()),
            variant: Some(rpc::forge::operating_system::Variant::OsImageId(
                rpc::Uuid {
                    value: uuid::Uuid::new_v4().to_string(),
                },
            )),
        }),
        network: Some(network_config),
        infiniband: None,
        storage: None,
        network_security_group_id: None,
    };

    let mut config: InstanceConfig = config.try_into().unwrap();

    assert!(
        config
            .network
            .interfaces
            .iter()
            .all(|i| i.network_segment_id.is_none())
    );

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    allocate_network(&mut config.network, &mut txn)
        .await
        .unwrap();

    txn.commit().await.unwrap();
    assert!(
        config
            .network
            .interfaces
            .iter()
            .all(|i| i.network_segment_id.is_some())
    );

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let expected_ips = [
        Ipv4Addr::from_str("10.217.5.224").unwrap(),
        Ipv4Addr::from_str("10.217.5.226").unwrap(),
    ];
    let mut expected_ips_iter = expected_ips.iter();

    for iface in config.network.interfaces {
        let network_segment = NetworkSegment::find_by(
            &mut txn,
            ObjectColumnFilter::One(IdColumn, &iface.network_segment_id.unwrap()),
            NetworkSegmentSearchConfig::default(),
        )
        .await
        .unwrap();

        let np = network_segment[0].prefixes[0].prefix;
        match np {
            IpNetwork::V4(ipv4_network) => {
                assert_eq!(expected_ips_iter.next().unwrap(), &ipv4_network.network())
            }
            IpNetwork::V6(_) => panic!("Can not be ipv6."),
        }
    }
}
