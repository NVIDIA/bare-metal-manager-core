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

use common::api_fixtures::instance::{default_tenant_config, single_interface_network_config};
use common::api_fixtures::{create_managed_host, create_test_env};
use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::tests::common;

#[crate::sqlx_test]
async fn test_update_instance_operating_system(_: PgPoolOptions, options: PgConnectOptions) {
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

    let config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(initial_os.clone()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
    };

    let tinstance = mh.instance_builer(&env).config(config).build().await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(instance.status().tenant(), rpc::forge::TenantState::Ready);

    let os = instance.config().os();
    assert_eq!(os, &initial_os);
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

    let instance = env
        .api
        .update_instance_operating_system(tonic::Request::new(
            rpc::forge::InstanceOperatingSystemUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                os: Some(updated_os_1.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let os = instance.config.as_ref().unwrap().os.as_ref().unwrap();
    assert_eq!(os, &updated_os_1);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 2);

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

    // Start a conditional update first that specifies the wrong last version.
    // This should fail.
    let status = env
        .api
        .update_instance_operating_system(tonic::Request::new(
            rpc::forge::InstanceOperatingSystemUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: Some(initial_config_version.version_string()),
                os: Some(updated_os_2.clone()),
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
        .update_instance_operating_system(tonic::Request::new(
            rpc::forge::InstanceOperatingSystemUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: Some(updated_config_version.version_string()),
                os: Some(updated_os_2.clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let os = instance.config.as_ref().unwrap().os.as_ref().unwrap();
    assert_eq!(os, &updated_os_2);
    let updated_config_version = instance.config_version.parse::<ConfigVersion>().unwrap();
    assert_eq!(updated_config_version.version_nr(), 3);

    // Try to update a non-existing instance
    let unknown_instance = uuid::Uuid::new_v4();
    let status = env
        .api
        .update_instance_operating_system(tonic::Request::new(
            rpc::forge::InstanceOperatingSystemUpdateRequest {
                instance_id: Some(unknown_instance.into()),
                if_version_match: None,
                os: Some(updated_os_2.clone()),
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

    // Try to update to an invalid OS
    let invalid_os = rpc::forge::OperatingSystem {
        phone_home_enabled: true,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData2".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "".to_string(),
                user_data: None,
            },
        )),
    };

    let err = env
        .api
        .update_instance_operating_system(tonic::Request::new(
            rpc::forge::InstanceOperatingSystemUpdateRequest {
                instance_id: Some(tinstance.id),
                if_version_match: None,
                os: Some(invalid_os),
            },
        ))
        .await
        .expect_err("Invalid OS should not be accepted");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "Invalid value: InlineIpxe::ipxe_script is empty"
    );
}
