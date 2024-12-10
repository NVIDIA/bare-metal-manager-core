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
    str::FromStr,
    time::{Duration, SystemTime},
};

use crate::{
    db::{
        dhcp_record::InstanceDhcpRecord,
        instance::Instance,
        instance_address::{InstanceAddress, UsedOverlayNetworkIpResolver},
        machine::{Machine, MachineSearchConfig},
        network_prefix::NetworkPrefix,
        network_segment::{IdColumn, NetworkSegment, NetworkSegmentSearchConfig},
        ObjectColumnFilter,
    },
    dhcp::allocation::UsedIpResolver,
    instance::{allocate_instance, allocate_network, InstanceAllocationRequest},
    model::{
        instance::{
            config::{
                infiniband::InstanceInfinibandConfig,
                network::{InstanceNetworkConfig, InterfaceFunctionId, NetworkDetails},
                storage::InstanceStorageConfig,
                InstanceConfig,
            },
            status::network::{
                InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation,
            },
        },
        machine::{
            machine_id::try_parse_machine_id, CleanupState, FailureDetails, InstanceState,
            MachineState, ManagedHostState, MeasuringState,
        },
        metadata::Metadata,
    },
    network_segment::allocate::Ipv4PrefixAllocator,
};
use ::rpc::forge::forge_server::Forge;
use chrono::Utc;
use common::api_fixtures::{
    create_managed_host, create_test_env, create_test_env_with_overrides, dpu, forge_agent_control,
    get_config,
    host::create_managed_host_with_ek,
    inject_machine_measurements,
    instance::{
        advance_created_instance_into_ready_state, create_instance, create_instance_with_hostname,
        create_instance_with_labels, default_os_config, default_tenant_config, delete_instance,
        single_interface_network_config, single_interface_network_config_with_vpc_prefix,
        FIXTURE_CIRCUIT_ID,
    },
    network_configured, network_configured_with_health,
    network_segment::{FIXTURE_NETWORK_SEGMENT_ID, FIXTURE_NETWORK_SEGMENT_ID_1},
    persist_machine_validation_result,
    tpm_attestation::{CA_CERT_SERIALIZED, EK_CERT_SERIALIZED},
    TestEnvOverrides,
};
use forge_uuid::instance::InstanceId;
use ipnetwork::{IpNetwork, Ipv4Network};
use itertools::Itertools;
use mac_address::MacAddress;

use rpc::{
    forge::{OperatingSystem, TpmCaCert, TpmCaCertId},
    InstanceReleaseRequest, Timestamp,
};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::ops::DerefMut;

use crate::tests::common::api_fixtures::instance::create_instance_with_config;
use crate::tests::common::api_fixtures::update_time_params;

use crate::tests::common;

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_id(*FIXTURE_NETWORK_SEGMENT_ID)
    );

    assert!(fetched_instance.observations.network.is_some());
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

    assert_eq!(
        format!("{}/32", &record.address()),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_measurement_assigned_ready_to_waiting_for_measurements_to_ca_failed_to_ready(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();

    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;
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

    let (host_machine_id, dpu_machine_id) =
        create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

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
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_id(*FIXTURE_NETWORK_SEGMENT_ID)
    );

    assert!(fetched_instance.observations.network.is_some());
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

    assert_eq!(
        format!("{}/32", &record.address()),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
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

    // from delete_instance()
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
    let machine = Machine::find_one(
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
    machine.update_reboot_time(&mut txn).await.unwrap();
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
    network_configured(&env, &dpu_machine_id).await;

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

    inject_machine_measurements(&env, host_machine_id.clone().into()).await;

    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    // check that it has failed as intended due to the lack of ca cert
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
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
            cleanup_state: CleanupState::HostCleanup,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
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
    machine.update_reboot_time(&mut txn).await.unwrap();
    machine.update_cleanup_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
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
    Machine::update_machine_validation_time(&host_machine_id, &mut txn)
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
    let machine = Machine::find_one(
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
    machine.update_reboot_time(&mut txn).await.unwrap();
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

    assert!(env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .is_empty());

    // end of delete_instance()

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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_allocate_instance_with_invalid_labels(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

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
            rpc::forge::Label {
                key: "key3".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key4".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key5".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key6".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key7".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key8".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key9".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key10".to_string(),
                value: None,
            },
            rpc::forge::Label {
                key: "key11".to_string(),
                value: None,
            },
        ],
    };

    let tenant_config = default_tenant_config();
    let config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
        storage: None,
    };

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: Some(instance_metadata),
        }))
        .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("Cannot have more than 10 labels"),
        "Error message should contain 'Cannot have more than 10 labels', but is {}",
        error
    );
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_allocate_instance_with_invalid_long_labels(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_metadata1 = rpc::forge::Metadata {
        name: "test_instance_with_labels".to_string(),
        description: "this instance must have labels.".to_string(),
        labels: vec![
            rpc::forge::Label {
                key: "Random257LongStringAZ7rfo6lZITregicb76ykFExk7b9rBjx5Y9T3h2CZnwPuMd8mdCCRXGKcScaiMHKdb81RUlKScU67J3bvVsRUzNRqBFT8akZqxWliFteFlpkAnxbUbRirNJjakt5lSOGv2Qs0BLRGpbqdIxCJiqTZJMJIZOWv3a2W5I9F4RGEn910rO54mrp5JODz3oS1Jp0M2ikc2WBJB70BcK0tETc8nBx6mp2hS3VUl4KemO57y6vqL
                ".to_string(),
                value: Some("value1".to_string()),
            },
        ],
    };

    let tenant_config = default_tenant_config();
    let config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
        storage: None,
    };

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config.clone()),
            metadata: Some(instance_metadata1),
        }))
        .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is too long "),
        "Error message should contain 'is too long ', but is {}",
        error
    );

    let instance_metadata2 = rpc::forge::Metadata {
        name: "test_instance_with_labels".to_string(),
        description: "this instance must have labels.".to_string(),
        labels: vec![
            rpc::forge::Label {
                key: "key1".to_string(),
                value: Some("Random257LongStringAZ7rfo6lZITregicb76ykFExk7b9rBjx5Y9T3h2CZnwPuMd8mdCCRXGKcScaiMHKdb81RUlKScU67J3bvVsRUzNRqBFT8akZqxWliFteFlpkAnxbUbRirNJjakt5lSOGv2Qs0BLRGpbqdIxCJiqTZJMJIZOWv3a2W5I9F4RGEn910rO54mrp5JODz3oS1Jp0M2ikc2WBJB70BcK0tETc8nBx6mp2hS3VUl4KemO57y6vqL".to_string()),
            },
        ],
    };

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config.clone()),
            metadata: Some(instance_metadata2),
        }))
        .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is too long"),
        "Error message should contain 'is too long', but is {}",
        error
    );

    let instance_metadata3 = rpc::forge::Metadata {
        name: "test_instance_with_labels".to_string(),
        description: "this instance must have labels.".to_string(),
        labels: vec![rpc::forge::Label {
            key: "".to_string(),
            value: None,
        }],
    };

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: Some(instance_metadata3),
        }))
        .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("Label key cannot be empty"),
        "Error message should contain 'Label key cannot be empty', but is {}",
        error
    );
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_hostname_creation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_hostname = "test-hostname";

    let (_instance_id, _instance) = create_instance_with_hostname(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        None,
        vec![],
        instance_hostname.to_string(),
        "org-nebulon".to_string(),
    )
    .await;

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
    let (_instance_id, _instance) = create_instance_with_hostname(
        &env,
        &new_dpu_machine_id,
        &new_host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        None,
        vec![],
        instance_hostname.to_string(),
        "org-nvidia".to_string(), //different org, should fail on the same one
    )
    .await;
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_dns_resolution(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID).into()),
                network_details: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID_1).into()),
                network_details: None,
            },
        ],
    });

    //Create instance with hostname
    let (_instance_id, _instance) = create_instance_with_hostname(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        None,
        vec![],
        "test-hostname".to_string(),
        "nvidia-org".to_string(),
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

    //DNS record domain always uses IP Address (for now)
    let dns_record = env
        .api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some("192-0-2-3.dwrt1.com.".to_string()),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!("192.0.2.3", &dns_record.rrs[0].rdata.clone().unwrap());

    //DHCP response uses hostname set during allocation
    assert_eq!(
        "test-hostname.dwrt1.com",
        response.tenant_interfaces[0].fqdn
    );
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_null_hostname(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    //Create instance with no hostname set
    let mut tenant_config = default_tenant_config();
    tenant_config.hostname = None;
    let instance_config = rpc::InstanceConfig {
        tenant: Some(tenant_config),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
        storage: None,
    };

    let (_instance_id, _instance) = create_instance_with_config(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        instance_config,
        None,
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

    //DNS record domain always uses dashed IP (for now)
    let dns_record = env
        .api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some("192-0-2-3.dwrt1.com.".to_string()),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!("192.0.2.3", &dns_record.rrs[0].rdata.clone().unwrap());

    //DHCP response uses dashed IP
    assert_eq!("192-0-2-3.dwrt1.com", response.tenant_interfaces[0].fqdn);
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_create_instance_with_provided_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let config = rpc::InstanceConfig {
        os: Some(default_os_config()),
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
        storage: None,
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
        storage: None,
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
        storage: None,
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
        ip: machine.interfaces()[0].addresses[0].to_string(),
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
    let snapshot = Instance::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap()
        .unwrap();

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
        }],
        observed_at: Utc::now(),
    };

    Instance::update_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();

    let snapshot = Instance::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
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
        }]
    );

    let mut txn = env.pool.begin().await.unwrap();
    updated_network_status.interfaces[0].mac_address =
        Some(MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]).into());
    Instance::update_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();

    let snapshot = Instance::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.observations.network.as_ref(),
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
    let snapshot = Instance::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
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
        });

    Instance::update_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let snapshot = Instance::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.observations.network.as_ref(),
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
        }]
    );

    // Drop the gateways and prefixes fields from the JSONB and ensure the rest of the
    // object is OK (to emulate older agents not sending gateways and prefixes in the status
    // observations).
    let mut txn = env.pool.begin().await.unwrap();
    let gateways_query =
        "UPDATE instances SET network_status_observation=jsonb_strip_nulls(jsonb_set(network_status_observation, '{interfaces,0,gateways}', 'null', false)) where id = $1::uuid returning id";
    let prefixes_query =
        "UPDATE instances SET network_status_observation=jsonb_strip_nulls(jsonb_set(network_status_observation, '{interfaces,0,prefixes}', 'null', false)) where id = $1::uuid returning id";

    let (_,): (InstanceId,) = sqlx::query_as(gateways_query)
        .bind(instance_id)
        .fetch_one(txn.deref_mut())
        .await
        .expect("Database error rewriting JSON");
    let (_,): (InstanceId,) = sqlx::query_as(prefixes_query)
        .bind(instance_id)
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
        }]
    );

    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]

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
            storage: InstanceStorageConfig::default(),
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
    let result = allocate_instance(
        request,
        &env.pool,
        env.config.host_health.hardware_health_reports,
        &env.api,
    )
    .await;
    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is of type Dpu and can not be converted into an instance"),
        "Error message should contain 'is of type Dpu and can not be converted into an instance', but is {}",
        error
    );
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
                network_details: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID_1).into()),
                network_details: None,
            },
        ],
    });

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
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

    // The create_network_segment fixture creates two network segments, backed by
    // FIXTURE_NETWORK_SEGMENT_ID (91609f10-c91d-470d-a260-6293ea0c1200, 192.0.2.0/24)
    // and FIXTURE_NETWORK_SEGMENT_ID_1 (4de5bdd6-1f28-4ed4-aba7-f52e292f0fe9, 192.0.3.0/24),
    // so after the instance is allocated with an InstanceNetworkConfig containing
    // interfaces in both segments, lets check the allocaitons to make sure it worked as
    // expected.
    //
    // TODO(chet): This will be where I also drop prefix allocation testing!

    // Check the allocated IP for the PF/primary interface.
    let allocated_ip_resolver = UsedOverlayNetworkIpResolver {
        segment_id: *FIXTURE_NETWORK_SEGMENT_ID,
    };
    let used_ips = allocated_ip_resolver.used_ips(&mut txn).await.unwrap();
    let used_prefixes = allocated_ip_resolver.used_prefixes(&mut txn).await.unwrap();
    assert_eq!(1, used_ips.len());
    assert_eq!(1, used_prefixes.len());
    assert_eq!("192.0.2.3", used_ips[0].to_string());
    assert_eq!("192.0.2.3/32", used_prefixes[0].to_string());

    // Check the allocated VF.
    let allocated_ip_resolver = UsedOverlayNetworkIpResolver {
        segment_id: *FIXTURE_NETWORK_SEGMENT_ID_1,
    };
    let used_ips = allocated_ip_resolver.used_ips(&mut txn).await.unwrap();
    let used_prefixes = allocated_ip_resolver.used_prefixes(&mut txn).await.unwrap();
    assert_eq!(1, used_ips.len());
    assert_eq!(1, used_prefixes.len());
    assert_eq!("192.0.3.3", used_ips[0].to_string());
    assert_eq!("192.0.3.3/32", used_prefixes[0].to_string());

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
    assert_eq!(network_config.tenant_interfaces[0].ip, "192.0.2.3");
    assert_eq!(network_config.tenant_interfaces[1].ip, "192.0.3.3");
    assert_eq!(network_config.dpu_network_pinger_type, None);
    // Ensure the VPC prefixes (which in this case are the two network segment
    // IDs referenced above) are both associated with both interfaces.
    let expected_vpc_prefixes = vec!["192.0.2.0/24".to_string(), "192.0.3.0/24".to_string()];
    assert_eq!(
        network_config.tenant_interfaces[0].vpc_prefixes,
        expected_vpc_prefixes
    );
    assert_eq!(
        network_config.tenant_interfaces[1].vpc_prefixes,
        expected_vpc_prefixes
    );
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_cannot_create_instance_on_unhealthy_dpu(
    _: PgPoolOptions,
    options: PgConnectOptions,
) -> eyre::Result<()> {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
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
            config: Some(rpc::InstanceConfig {
                os: Some(default_os_config()),
                tenant: Some(default_tenant_config()),
                network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
                infiniband: None,
                storage: None,
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
    assert_eq!(
        err.message(),
        "Host is not available for allocation due to health probe alert"
    );
    Ok(())
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
        storage: None,
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
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
        &dpu_machine_id,
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
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
            hostname: Some("test-instance".to_string()),
        }),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
        storage: None,
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
    assert_eq!(err.message(), "Duplicate Tenant KeySet ID found: bad_id");
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_create_instance_keyset_ids_max(_: PgPoolOptions, options: PgConnectOptions) {
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
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
        storage: None,
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
        .expect_err("More than 10 TenantKeyset IDs should not be accepted");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "More than 10 Tenant KeySet IDs are not allowed"
    );
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_allocate_instance_with_old_network_segemnt(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
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
        description: "this instance does not have labels.".to_string(),
        labels: vec![],
    };

    let mut nw_config = single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID);
    for interface in &mut nw_config.interfaces {
        interface.network_details = None;
    }

    let (instance_id, _instance) = create_instance_with_labels(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(nw_config),
        None,
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

    let network_config = fetched_instance.config.network.clone();
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
    }
    let mut expected_nw_config = InstanceNetworkConfig::for_segment_id(*FIXTURE_NETWORK_SEGMENT_ID);
    for interface in &mut expected_nw_config.interfaces {
        interface.network_details = None;
    }
    assert_eq!(network_config_no_addresses, expected_nw_config);
}

#[crate::sqlx_test(fixtures(
    "create_domain",
    "create_vpc",
    "create_vpc_prefix",
    "create_network_segment"
))]
async fn test_allocate_network_vpc_prefix_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;

    let x = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: 0,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(
                    rpc::common::Uuid {
                        value: "63fd2e18-5fff-400e-8861-1e7a6c862b7c".to_string(),
                    },
                ),
            ),
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
    };

    let mut config: InstanceConfig = config.try_into().unwrap();

    assert!(config.network.interfaces[0].network_segment_id.is_none());

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    allocate_network(&mut config.network, &mut txn, &env.api)
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

#[crate::sqlx_test(fixtures(
    "create_domain",
    "create_vpc",
    "create_vpc_prefix",
    "create_network_segment"
))]
async fn test_allocate_and_release_instance_vpc_prefix_id(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
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

    let vpc_prefix_id = uuid::Uuid::from_str("63fd2e18-5fff-400e-8861-1e7a6c862b7c").unwrap();
    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config_with_vpc_prefix(rpc::Uuid {
            value: vpc_prefix_id.to_string(),
        })),
        None,
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

    let fetched_instance = Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .unwrap_or_else(|| {
            panic!("find_by_relay_ip for loopback {dpu_loopback_ip} didn't find any instances")
        });
    assert_eq!(fetched_instance.machine_id, host_machine_id);
    assert_eq!(
        InstanceAddress::count_by_segment_id(
            &mut txn,
            fetched_instance.config.network.interfaces[0]
                .network_segment_id
                .unwrap()
        )
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
        iface.network_segment_id = None;
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_vpc_prefix_id(vpc_prefix_id)
    );

    assert!(fetched_instance.observations.network.is_some());
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

    let ns = NetworkSegment::find_by(
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

    // TODO: The MAC here doesn't matter. It's not used for lookup
    let parsed_mac = "ff:ff:ff:ff:ff:ff".parse::<MacAddress>().unwrap();
    let record = InstanceDhcpRecord::find_for_instance(
        &mut txn,
        parsed_mac,
        format!("vlan{}", ns[0].vlan_id.unwrap_or_default()),
        fetched_instance.clone(),
    )
    .await
    .unwrap();

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address().to_string(), "10.217.5.225");
    assert_eq!(
        &record.address(),
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );

    assert_eq!(
        format!("{}/32", &record.address()),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
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
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    assert_eq!(
        InstanceAddress::count_by_segment_id(
            &mut txn,
            fetched_instance.config.network.interfaces[0]
                .network_segment_id
                .unwrap()
        )
        .await
        .unwrap(),
        0
    );
    txn.commit().await.unwrap();
}

#[crate::sqlx_test(fixtures(
    "create_domain",
    "create_vpc",
    "create_vpc_prefix",
    "create_network_segment"
))]
async fn test_vpc_prefix_handling(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc_prefix_id = uuid::uuid!("63fd2e18-5fff-400e-8861-1e7a6c862b7c");

    let allocator = Ipv4PrefixAllocator::new(
        // 15 IPs
        vpc_prefix_id.into(),
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        None,
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(
            &mut txn,
            &env.api,
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
        )
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
        vpc_prefix_id.into(),
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        None,
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(
            &mut txn,
            &env.api,
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
        )
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
        vpc_prefix_id.into(),
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        None,
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(
            &mut txn,
            &env.api,
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
        )
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
        vpc_prefix_id.into(),
        Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap(),
        Some(Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 234), 31).unwrap()),
        31,
    );

    let (ns_id, _prefix) = allocator
        .allocate_network_segment(
            &mut txn,
            &env.api,
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
        )
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
