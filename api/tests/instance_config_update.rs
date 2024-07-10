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

pub mod common;

use common::api_fixtures::{
    create_managed_host, create_test_env,
    instance::{
        create_instance_with_config, default_tenant_config, single_interface_network_config,
    },
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

use carbide::db::ib_partition::IBPartitionId;
use carbide::db::network_segment::NetworkSegmentId;
use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

/// Compares an expected instance configuration with the actual instance configuration
///
/// We can't directly call `assert_eq` since carbide will fill in the OS details into
/// the TenantConfig fields if they are not directly specified.
fn assert_config_equals(
    actual: &rpc::forge::InstanceConfig,
    expected: &rpc::forge::InstanceConfig,
) {
    let mut expected = expected.clone();
    match &expected.os.as_ref().unwrap().variant {
        Some(rpc::forge::operating_system::Variant::Ipxe(ipxe)) => {
            let tenant = expected.tenant.as_mut().unwrap();
            tenant.custom_ipxe = ipxe.ipxe_script.clone();
            tenant.user_data = ipxe.user_data.clone();
            tenant.always_boot_with_custom_ipxe = expected
                .os
                .as_ref()
                .unwrap()
                .run_provisioning_instructions_on_every_boot;
            tenant.phone_home_enabled = expected.os.as_ref().unwrap().phone_home_enabled;
        }
        _ => panic!("Unexpected OS type"),
    }
    assert_eq!(expected, *actual);
}

/// Compares instance metadata for equality
///
/// Since metadata is transmitted as an unordered list, using `assert_eq!` won't
/// provide expected results
fn assert_metadata_equals(actual: &rpc::forge::Metadata, expected: &rpc::forge::Metadata) {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));
    expected.labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));
    assert_eq!(actual, expected);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_update_instance_config(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };

    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let (instance_id, _instance) = create_instance_with_config(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        initial_config.clone(),
        Some(initial_metadata.clone()),
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

    assert_config_equals(instance.config.as_ref().unwrap(), &initial_config);
    assert_metadata_equals(instance.metadata.as_ref().unwrap(), &initial_metadata);
    let initial_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(initial_config_version.version_nr(), 1);

    let updated_os_1 = rpc::forge::OperatingSystem {
        phone_home_enabled: true,
        run_provisioning_instructions_on_every_boot: true,
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe2".to_string(),
                user_data: Some("SomeRandomData2".to_string()),
            },
        )),
    };
    let mut updated_config_1 = initial_config.clone();
    updated_config_1.os = Some(updated_os_1);
    updated_config_1.tenant.as_mut().unwrap().tenant_keyset_ids =
        vec!["a".to_string(), "b".to_string()];
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
    assert_config_equals(instance.config.as_ref().unwrap(), &updated_config_1);
    assert_metadata_equals(instance.metadata.as_ref().unwrap(), &updated_metadata_1);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 2);

    let updated_os_2 = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe3".to_string(),
                user_data: Some("SomeRandomData3".to_string()),
            },
        )),
    };
    let mut updated_config_2 = initial_config.clone();
    updated_config_2.os = Some(updated_os_2);
    updated_config_2.tenant.as_mut().unwrap().tenant_keyset_ids = vec!["c".to_string()];
    let updated_metadata_2 = rpc::Metadata {
        name: "".to_string(),
        description: "".to_string(),
        labels: vec![
            rpc::forge::Label {
                key: "Key11".to_string(),
                value: Some("Value11".to_string()),
            },
            rpc::forge::Label {
                key: "Key12".to_string(),
                value: None,
            },
        ],
    };

    // Start a conditional update first that specifies the wrong last version.
    // This should fail.
    let status = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: Some(initial_config_version.version_string()),
                config: Some(updated_config_2.clone()),
                metadata: Some(updated_metadata_2.clone()),
            },
        ))
        .await
        .expect_err("RPC call should fail with PreconditionFailed error");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(),
         format!("An object of type instance was intended to be modified did not have the expected version {}", initial_config_version.version_string()),
         "Message is {}", status.message());

    // Using the correct current version should allow the update
    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: Some(updated_config_version.version_string()),
                config: Some(updated_config_2.clone()),
                metadata: Some(updated_metadata_2.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_config_equals(instance.config.as_ref().unwrap(), &updated_config_2);
    assert_metadata_equals(instance.metadata.as_ref().unwrap(), &updated_metadata_2);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 3);

    // Try to update a non-existing instance
    let unknown_instance = uuid::Uuid::new_v4();
    let status = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(unknown_instance.into()),
                if_version_match: None,
                config: Some(updated_config_2.clone()),
                metadata: Some(updated_metadata_2.clone()),
            },
        ))
        .await
        .expect_err("RPC call should fail with NotFound error");
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert_eq!(
        status.message(),
        format!("instance not found: {unknown_instance}"),
        "Message is {}",
        status.message()
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_reject_invalid_instance_config_updates(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };

    let valid_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let (instance_id, _instance) = create_instance_with_config(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        valid_config.clone(),
        Some(initial_metadata.clone()),
    )
    .await;

    // Try to update to an invalid OS
    let invalid_os = rpc::forge::OperatingSystem {
        phone_home_enabled: true,
        run_provisioning_instructions_on_every_boot: false,
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "".to_string(),
                user_data: Some("SomeRandomData2".to_string()),
            },
        )),
    };
    let mut invalid_os_config = valid_config.clone();
    invalid_os_config.os = Some(invalid_os);
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(invalid_os_config),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("Invalid OS should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "Invalid value: IpxeOperatingSystem::ipxe_script is empty"
    );

    // The tenant of an instance can not be updated
    let mut config_with_updated_tenant = valid_config.clone();
    config_with_updated_tenant
        .tenant
        .as_mut()
        .unwrap()
        .tenant_organization_id = "new_tenant".to_string();
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(config_with_updated_tenant),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("New tenant should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "Configuration value cannot be modified: TenantConfig::tenant_organization_id"
    );

    // The network configuration of an instance can not be updated
    let mut config_with_updated_network = valid_config.clone();
    config_with_updated_network
        .network
        .as_mut()
        .unwrap()
        .interfaces
        .push(rpc::forge::InstanceInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Virtual as _,
            network_segment_id: Some(NetworkSegmentId::from(uuid::Uuid::new_v4()).into()),
        });
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(config_with_updated_network),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("New network configuration should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "Configuration value cannot be modified: network"
    );

    // The infiniband configuration of an instance can not be updated
    let mut config_with_updated_ib = valid_config.clone();
    config_with_updated_ib.infiniband = Some(rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![rpc::forge::InstanceIbInterfaceConfig {
            vendor: None,
            device: "MT2910 Family [ConnectX-7]".to_string(),
            device_instance: 0,
            ib_partition_id: Some(IBPartitionId::from(uuid::Uuid::new_v4()).into()),
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            virtual_function_id: None,
        }],
    });
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(config_with_updated_ib),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("New infiniband configuration should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "Configuration value cannot be modified: infiniband"
    );

    // Try to update to duplicated tenant keyset IDs
    let mut duplicated_keysets_config = valid_config.clone();
    duplicated_keysets_config
        .tenant
        .as_mut()
        .unwrap()
        .tenant_keyset_ids = vec!["a".to_string(), "b".to_string(), "a".to_string()];
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(duplicated_keysets_config),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("Duplicate keyset IDs should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "Duplicate Tenant KeySet ID found: a");

    // Try to update to over max tenant keyset IDs
    let mut maxed_keysets_config = valid_config.clone();
    maxed_keysets_config
        .tenant
        .as_mut()
        .unwrap()
        .tenant_keyset_ids = vec![
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
    ];
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(instance_id.into()),
                if_version_match: None,
                config: Some(maxed_keysets_config),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("Over max keyset config should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "More than 10 Tenant KeySet IDs are not allowed"
    );

    // // Try to update to invalid metadata
    // let invalid_metadata_no_key = rpc::forge::Metadata {
    //     name: "abc".to_string(),
    //     description: "def".to_string(),
    //     labels: vec![rpc::forge::Label { key: "".to_string(), value: None }]
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_no_key),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(
    //     err.message(),
    //     "Invalid value: TBD"
    // );

    // // Try to update to invalid metadata
    // let invalid_metadata_duplicated_keys = rpc::forge::Metadata {
    //     name: "abc".to_string(),
    //     description: "def".to_string(),
    //     labels: vec![
    //         rpc::forge::Label {
    //             key: "a".to_string(),
    //             value: None,
    //         },
    //         rpc::forge::Label {
    //             key: "a".to_string(),
    //             value: Some("other".to_string()),
    //         },
    //     ],
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_duplicated_keys),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(err.message(), "Invalid value: TBD");

    // // Try to update to invalid metadata
    // let invalid_metadata_overlong_name = rpc::forge::Metadata {
    //     name: "0123456789012345678901234567890123456789012345678901234567890123456789".to_string(),
    //     description: "def".to_string(),
    //     labels: vec![],
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_overlong_name),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(err.message(), "Invalid value: TBD");

    // let invalid_metadata_overlong_description = rpc::forge::Metadata {
    //     name: "instance".to_string(),
    //     description: "0123456789012345678901234567890123456789012345678901234567890123456789".to_string(),
    //     labels: vec![],
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_overlong_description),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(err.message(), "Invalid value: TBD");

    // let invalid_metadata_invalid_chars_in_name_or_description = rpc::forge::Metadata {
    //     name: "\x03asdf\0".to_string(),
    //     description: "a\u{211D}".to_string(),
    //     labels: vec![],
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_invalid_chars_in_name_or_description),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(err.message(), "Invalid value: TBD");

    // let invalid_metadata_overlong_key_value = rpc::forge::Metadata {
    //     name: "a".to_string(),
    //     description: "b".to_string(),
    //     labels: vec![
    //         rpc::forge::Label {
    //             key: "0123456789012345678901234567890123456789012345678901234567890123456789".to_string(),
    //             value: Some("0123456789012345678901234567890123456789012345678901234567890123456789".to_string())
    //         }
    //     ],
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_overlong_key_value),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(err.message(), "Invalid value: TBD");

    // let invalid_metadata_overlong_key_value = rpc::forge::Metadata {
    //     name: "a".to_string(),
    //     description: "b".to_string(),
    //     labels: vec![
    //         rpc::forge::Label {
    //             key: "\x03asdf\0".to_string(),
    //             value: Some("a\u{211D}".to_string())
    //         }
    //     ],
    // };
    // let err = env
    //     .api
    //     .update_instance_config(tonic::Request::new(
    //         rpc::forge::InstanceConfigUpdateRequest {
    //             instance_id: Some(instance_id.into()),
    //             if_version_match: None,
    //             config: Some(valid_config.clone()),
    //             metadata: Some(invalid_metadata_overlong_key_value),
    //         },
    //     ))
    //     .await
    //     .expect_err("Invalid metadata should not be accepted");
    // assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // assert_eq!(err.message(), "Invalid value: TBD");
}
