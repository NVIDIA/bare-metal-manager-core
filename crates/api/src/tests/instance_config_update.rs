/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use carbide_uuid::network::NetworkSegmentId;
use common::api_fixtures::instance::{default_tenant_config, single_interface_network_config};
use common::api_fixtures::{create_managed_host, create_test_env};
use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;
use rpc::forge::instance_interface_config::NetworkDetails;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tonic::Request;

use crate::tests::common::api_fixtures::{create_managed_host_multi_dpu, get_vpc_fixture_id};
use crate::tests::common::{self};

/// Compares an expected instance configuration with the actual instance configuration
///
/// We can't directly call `assert_eq` since carbide will fill in details into various fields
/// that are not expected
fn assert_config_equals(
    actual: &rpc::forge::InstanceConfig,
    expected: &rpc::forge::InstanceConfig,
) {
    let mut expected = expected.clone();
    let mut actual = actual.clone();
    if let Some(network) = &mut expected.network {
        network.interfaces.iter_mut().for_each(|x| {
            if let Some(NetworkDetails::VpcPrefixId(_)) = x.network_details {
                x.network_segment_id = None;
            }
        });
    }
    if let Some(network) = &mut actual.network {
        network.interfaces.iter_mut().for_each(|x| {
            if let Some(NetworkDetails::VpcPrefixId(_)) = x.network_details {
                x.network_segment_id = None;
            }
        });
    }
    assert_eq!(expected, actual);
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

#[crate::sqlx_test]
async fn test_update_instance_config(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };

    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    assert_config_equals(instance.config().inner(), &initial_config);
    assert_metadata_equals(instance.metadata(), &initial_metadata);
    let initial_config_version = instance.config_version();
    assert_eq!(initial_config_version.version_nr(), 1);

    let updated_os_1 = rpc::forge::OperatingSystem {
        phone_home_enabled: true,
        run_provisioning_instructions_on_every_boot: true,
        user_data: Some("SomeRandomData2".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
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
                instance_id: Some(tinstance.id),
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

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Pending
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
        rpc::forge::TenantState::Provisioning
    );

    // Phone home to transition from provisioning to configuring state
    env.api
        .update_instance_phone_home_last_contact(tonic::Request::new(
            rpc::forge::InstancePhoneHomeLastContactRequest {
                instance_id: Some(tinstance.id),
            },
        ))
        .await
        .unwrap();

    // Find our instance details again, which should now
    // be updated.
    let instance = tinstance.rpc_instance().await;

    // Post-phone-home, sync should still be pending, but state Configuring.
    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // And we should be ready from the tenant's perspective.
    assert_eq!(
        instance.status().tenant(),
        rpc::forge::TenantState::Configuring
    );

    // Update the network
    mh.network_configured(&env).await;

    // Find our instance details again, which should now
    // be updated.
    let instance = tinstance.rpc_instance().await;

    // Post-configure, we should now be synced.
    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    // And we should be ready from the tenant's perspective.
    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    let updated_os_2 = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData3".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe3".to_string(),
                user_data: Some("SomeRandomData3".to_string()),
            },
        )),
    };
    let mut updated_config_2 = initial_config.clone();
    updated_config_2.os = Some(updated_os_2);
    updated_config_2.tenant.as_mut().unwrap().tenant_keyset_ids = vec!["c".to_string()];
    let updated_metadata_2 = rpc::Metadata {
        name: "Name12".to_string(),
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
                instance_id: Some(tinstance.id),
                if_version_match: Some(initial_config_version.version_string()),
                config: Some(updated_config_2.clone()),
                metadata: Some(updated_metadata_2.clone()),
            },
        ))
        .await
        .expect_err("RPC call should fail with PreconditionFailed error");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        status.message(),
        format!(
            "An object of type instance was intended to be modified did not have the expected version {}",
            initial_config_version.version_string()
        ),
        "Message is {}",
        status.message()
    );

    // Using the correct current version should allow the update
    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(tinstance.id),
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

#[crate::sqlx_test]
async fn test_reject_invalid_instance_config_updates(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };

    let valid_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(valid_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    // Try to update to an invalid OS
    let invalid_os = rpc::forge::OperatingSystem {
        phone_home_enabled: true,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData2".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
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
                instance_id: Some(tinstance.id),
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
        "Invalid value: InlineIpxe::ipxe_script is empty"
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
                instance_id: Some(tinstance.id),
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
        .clear();

    // instance network config update is allowed now.
    config_with_updated_network
        .network
        .as_mut()
        .unwrap()
        .interfaces
        .push(rpc::forge::InstanceInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Virtual as _,
            network_segment_id: Some(NetworkSegmentId::new()),
            network_details: None,
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
        });
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                config: Some(config_with_updated_network),
                metadata: Some(initial_metadata.clone()),
            },
        ))
        .await
        .expect_err("New network configuration should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .starts_with("Invalid value: Missing Physical Function")
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
                instance_id: Some(tinstance.id),
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
                instance_id: Some(tinstance.id),
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

    // Try to update to invalid metadata
    for (invalid_metadata, expected_err) in common::metadata::invalid_metadata_testcases(true) {
        let err = env
            .api
            .update_instance_config(tonic::Request::new(
                rpc::forge::InstanceConfigUpdateRequest {
                    instance_id: Some(tinstance.id),
                    if_version_match: None,
                    config: Some(valid_config.clone()),
                    metadata: Some(invalid_metadata.clone()),
                },
            ))
            .await
            .expect_err(&format!(
                "Invalid metadata of type should not be accepted: {invalid_metadata:?}"
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
async fn test_update_instance_config_vpc_prefix_no_network_update(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.1.4.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env
        .api
        .create_vpc_prefix(request)
        .await
        .unwrap()
        .into_inner();

    let mut network = single_interface_network_config(segment_id);
    network.interfaces.iter_mut().for_each(|x| {
        x.network_segment_id = None;
        x.network_details = response.id.map(NetworkDetails::VpcPrefixId);
    });
    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(network.clone()),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    assert_config_equals(instance.config().inner(), &initial_config);
    assert_metadata_equals(instance.metadata(), &initial_metadata);
    let initial_config_version = instance.config_version();
    assert_eq!(initial_config_version.version_nr(), 1);

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
                instance_id: Some(tinstance.id),
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

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // SyncState::Synced means network config update is not applicable.
    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().network().configs_synced(),
        rpc::forge::SyncState::Synced
    );
}

#[crate::sqlx_test]
async fn test_update_instance_config_vpc_prefix_network_update(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let _segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.1.4.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
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
            network_details: response.id.map(NetworkDetails::VpcPrefixId),
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
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    assert_config_equals(instance.config().inner(), &initial_config);
    assert_metadata_equals(instance.metadata(), &initial_metadata);
    let initial_config_version = instance.config_version();
    assert_eq!(initial_config_version.version_nr(), 1);

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
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

    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                config: Some(updated_config_1.clone()),
                metadata: Some(updated_metadata_1.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_metadata_equals(instance.metadata.as_ref().unwrap(), &updated_metadata_1);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 2);

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // SyncState::Synced means network config update is not applicable.
    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().network().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // Since already a network update request is in queue, this should be rejected.
    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: response.id.map(NetworkDetails::VpcPrefixId),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
        }],
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

    let res = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                config: Some(updated_config_1.clone()),
                metadata: Some(updated_metadata_1.clone()),
            },
        ))
        .await;
    assert!(res.is_err());
}

#[crate::sqlx_test]
async fn test_update_instance_config_vpc_prefix_network_update_post_instance_delete(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let _segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.1.4.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
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
            network_details: response.id.map(NetworkDetails::VpcPrefixId),
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
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    // Trigger instance deletion.
    env.api
        .release_instance(tonic::Request::new(rpc::InstanceReleaseRequest {
            id: Some(tinstance.id),
            issue: None,
            is_repair_tenant: None,
        }))
        .await
        .expect("Delete instance failed.");

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
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

    assert!(
        env.api
            .update_instance_config(tonic::Request::new(
                rpc::forge::InstanceConfigUpdateRequest {
                    instance_id: Some(tinstance.id),
                    if_version_match: None,
                    config: Some(updated_config_1.clone()),
                    metadata: Some(updated_metadata_1.clone()),
                },
            ))
            .await
            .is_err()
    );
}

#[crate::sqlx_test]
async fn test_update_instance_config_vpc_prefix_network_update_multidpu(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let _segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host_multi_dpu(&env, 2).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.1.4.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
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
            network_details: response.id.map(NetworkDetails::VpcPrefixId),
            device: Some("DPU1".to_string()),
            device_instance: 0,
            virtual_function_id: None,
        }],
    };

    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(network.clone()),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    assert_config_equals(instance.config().inner(), &initial_config);
    assert_metadata_equals(instance.metadata(), &initial_metadata);
    let initial_config_version = instance.config_version();
    assert_eq!(initial_config_version.version_nr(), 1);

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
                device: Some("DPU1".to_string()),
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
                device: Some("DPU1".to_string()),
                device_instance: 1,
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

    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                config: Some(updated_config_1.clone()),
                metadata: Some(updated_metadata_1.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_metadata_equals(instance.metadata.as_ref().unwrap(), &updated_metadata_1);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 2);

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // SyncState::Synced means network config update is not applicable.
    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().network().configs_synced(),
        rpc::forge::SyncState::Pending
    );
}

#[crate::sqlx_test]
async fn test_update_instance_config_vpc_prefix_network_update_multidpu_different_vpc_prefix(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let _segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host_multi_dpu(&env, 2).await;

    let initial_os = rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData1".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe1".to_string(),
                user_data: Some("SomeRandomData1".to_string()),
            },
        )),
    };
    let ip_prefix = "192.1.4.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env
        .api
        .create_vpc_prefix(request)
        .await
        .unwrap()
        .into_inner();

    let ip_prefix1 = "192.0.5.0/25";
    let new_vpc_prefix1 = rpc::forge::VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix1.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix1".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request1 = Request::new(new_vpc_prefix1);
    let response1 = env
        .api
        .create_vpc_prefix(request1)
        .await
        .unwrap()
        .into_inner();

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: response.id.map(NetworkDetails::VpcPrefixId),
            device: Some("DPU1".to_string()),
            device_instance: 0,
            virtual_function_id: None,
        }],
    };

    let initial_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(network.clone()),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let initial_metadata = rpc::Metadata {
        name: "Name1".to_string(),
        description: "Desc1".to_string(),
        labels: vec![],
    };

    let tinstance = mh
        .instance_builer(&env)
        .config(initial_config.clone())
        .metadata(initial_metadata.clone())
        .build()
        .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().configs_synced(),
        rpc::forge::SyncState::Synced
    );

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    assert_config_equals(instance.config().inner(), &initial_config);
    assert_metadata_equals(instance.metadata(), &initial_metadata);
    let initial_config_version = instance.config_version();
    assert_eq!(initial_config_version.version_nr(), 1);

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response.id.map(NetworkDetails::VpcPrefixId),
                device: Some("DPU1".to_string()),
                device_instance: 0,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: response1.id.map(NetworkDetails::VpcPrefixId),
                device: Some("DPU1".to_string()),
                device_instance: 1,
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

    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                config: Some(updated_config_1.clone()),
                metadata: Some(updated_metadata_1.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_metadata_equals(instance.metadata.as_ref().unwrap(), &updated_metadata_1);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 2);

    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced(),
        rpc::forge::SyncState::Pending
    );

    // SyncState::Synced means network config update is not applicable.
    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance.status().network().configs_synced(),
        rpc::forge::SyncState::Pending
    );
}
