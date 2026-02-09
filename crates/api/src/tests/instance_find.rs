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

use ::rpc::forge as rpc;
use base64::prelude::*;
use carbide_uuid::instance::InstanceId;
use rpc::forge_server::Forge;

use crate::tests::common::api_fixtures::instance::default_tenant_config;
use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};

#[crate::sqlx_test]
async fn test_find_instance_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Find an existing instance type in the test env
    let instance_type_id = env
        .api
        .find_instance_type_ids(tonic::Request::new(rpc::FindInstanceTypeIdsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids
        .first()
        .unwrap()
        .to_owned();

    for i in 0..10 {
        let mh = create_managed_host(&env).await;

        if i % 2 == 0 {
            // Associate the machine with the instance type
            let _ = env
                .api
                .associate_machines_with_instance_type(tonic::Request::new(
                    rpc::AssociateMachinesWithInstanceTypeRequest {
                        instance_type_id: instance_type_id.clone(),
                        machine_ids: vec![mh.id.to_string()],
                    },
                ))
                .await
                .unwrap();

            mh.instance_builer(&env)
                .single_interface_network_config(segment_id)
                .build()
                .await;
        } else {
            mh.instance_builer(&env)
                .single_interface_network_config(segment_id)
                .metadata(rpc::Metadata {
                    name: format!("instance_{i}{i}{i}").to_string(),
                    description: format!("instance_{i}{i}{i} with label").to_string(),
                    labels: vec![rpc::Label {
                        key: "label_test_key".to_string(),
                        value: Some(format!("label_value_{i}").to_string()),
                    }],
                })
                .build()
                .await;
        }
    }
    let mut txn = env.pool.begin().await.unwrap();
    let vpc_id = db::network_segment::find_by_name(&mut txn, "TENANT")
        .await
        .unwrap()
        .vpc_id
        .unwrap();

    // test_data contains a bunch of standard inputs thanks to the fact all
    // we need to do is call `find_instance_ids` over and over with different
    // rpc::InstanceSearchFilter inputs, and includes the expected length
    // of results.
    let test_data = [
        // Test getting all IDs.
        (
            "request_all",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: None,
                tenant_org_id: None,
                vpc_id: None,
                instance_type_id: None,
            }),
            10,
        ),
        // Test getting all based on instance type.
        (
            "request_instance_type_id",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: None,
                tenant_org_id: None,
                vpc_id: None,
                instance_type_id: Some(instance_type_id.clone()),
            }),
            5,
        ),
        // Test getting IDs based on label key.
        (
            "request_label_key",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: None,
                }),
                tenant_org_id: None,
                vpc_id: None,
                instance_type_id: None,
            }),
            5,
        ),
        // Test getting IDs based on label value.
        (
            "request_label_value",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "".to_string(),
                    value: Some("label_value_1".to_string()),
                }),
                tenant_org_id: None,
                vpc_id: None,
                instance_type_id: None,
            }),
            1,
        ),
        // Test getting IDs based on label key and value.
        (
            "request_label_key_and_value",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: Some("label_value_3".to_string()),
                }),
                tenant_org_id: None,
                vpc_id: None,
                instance_type_id: None,
            }),
            1,
        ),
        // Test getting IDs based on tenant_org_id.
        (
            "request_tenant_org_id",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: None,
                tenant_org_id: Some(default_tenant_config().tenant_organization_id),
                vpc_id: None,
                instance_type_id: None,
            }),
            10,
        ),
        // Test getting IDs based on tenant_org_id and label key.
        (
            "request_tenant_org_and_label_key",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: None,
                }),
                tenant_org_id: Some(default_tenant_config().tenant_organization_id),
                vpc_id: None,
                instance_type_id: None,
            }),
            5,
        ),
        // Test getting IDs based on tenant_org_id and label value.
        (
            "request_tenant_org_and_label_value",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "".to_string(),
                    value: Some("label_value_1".to_string()),
                }),
                tenant_org_id: Some(default_tenant_config().tenant_organization_id),
                vpc_id: None,
                instance_type_id: None,
            }),
            1,
        ),
        // Test getting IDs based on tenant_org_id and label key AND value.
        (
            "request_tenant_org_and_label_key_value",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: Some("label_value_1".to_string()),
                }),
                tenant_org_id: Some(default_tenant_config().tenant_organization_id),
                vpc_id: None,
                instance_type_id: None,
            }),
            1,
        ),
        // Test getting IDs based on vpc_id only. In this case,
        // since there's only one VPC being created (based on FIXTURE_VPC_ID),
        // we expect all 10 instances to be in the VPC.
        //
        // TODO(chet): Consider updating fixtures so there's a
        // NETWORK_SEGMENT_ID_2 to allow for FIXTURE_VPC_ID_1 so
        // we can test multiple VPCs here (and other places).
        (
            "request_vpc_id_only",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: None,
                tenant_org_id: None,
                vpc_id: Some(vpc_id.to_string()),
                instance_type_id: None,
            }),
            10,
        ),
        // Test getting IDs based on vpc_id and label key.
        (
            "request_vpc_id_and_label_key",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: None,
                }),
                tenant_org_id: None,
                vpc_id: Some(vpc_id.to_string()),
                instance_type_id: None,
            }),
            5,
        ),
        // Test getting IDs based on vpc_id and label key AND value.
        (
            "request_vpc_id_and_label_key_value",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: Some("label_value_1".to_string()),
                }),
                tenant_org_id: None,
                vpc_id: Some(vpc_id.to_string()),
                instance_type_id: None,
            }),
            1,
        ),
        // Test providing both vpc_id AND tenant_org_id.
        (
            "request_tenant_org_and_vpc_id",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: None,
                tenant_org_id: Some(default_tenant_config().tenant_organization_id),
                vpc_id: Some(vpc_id.to_string()),
                instance_type_id: None,
            }),
            10,
        ),
        // Test providing VPC ID + tenant org ID + label filtering.
        // Getting really crazy now!
        (
            "request_label_and_tenant_org_and_vpc_id",
            tonic::Request::new(rpc::InstanceSearchFilter {
                label: Some(rpc::Label {
                    key: "label_test_key".to_string(),
                    value: None,
                }),
                tenant_org_id: Some(default_tenant_config().tenant_organization_id),
                vpc_id: Some(vpc_id.to_string()),
                instance_type_id: None,
            }),
            5,
        ),
    ];

    // And now loop over the test cases and see how they do.
    for (name, req, expected) in test_data.into_iter() {
        assert_eq!(
            env.api
                .find_instance_ids(req)
                .await
                .map(|response| response.into_inner())
                .unwrap()
                .instance_ids
                .len(),
            expected,
            "assertion failed during test loop: {name}",
        );
    }
}

#[crate::sqlx_test]
async fn test_find_instances_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    for i in 0..10 {
        let mh = create_managed_host(&env).await;

        if i % 2 == 0 {
            mh.instance_builer(&env)
                .single_interface_network_config(segment_id)
                .build()
                .await;
        } else {
            mh.instance_builer(&env)
                .single_interface_network_config(segment_id)
                .metadata(rpc::Metadata {
                    name: format!("instance_{i}{i}{i}").to_string(),
                    description: format!("instance_{i}{i}{i} with label").to_string(),
                    labels: vec![rpc::Label {
                        key: "label_test_key".to_string(),
                        value: Some(format!("label_value_{i}").to_string()),
                    }],
                })
                .build()
                .await;
        }
    }

    let request_ids = tonic::Request::new(rpc::InstanceSearchFilter {
        label: Some(rpc::Label {
            key: "label_test_key".to_string(),
            value: None,
        }),
        tenant_org_id: None,
        vpc_id: None,
        instance_type_id: None,
    });

    let instance_id_list = env
        .api
        .find_instance_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_id_list.instance_ids.len(), 5);

    let request_instances = tonic::Request::new(rpc::InstancesByIdsRequest {
        instance_ids: instance_id_list.instance_ids.clone(),
    });

    let instance_list = env
        .api
        .find_instances_by_ids(request_instances)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_list.instances.len(), 5);

    // validate we got instances with specified ids
    let mut instances_copy = instance_list.instances;
    for _ in 0..5 {
        let instance = instances_copy.remove(0);
        let instance_id = instance.id.unwrap();
        assert!(instance_id_list.instance_ids.contains(&instance_id));
        assert!(instance.tpm_ek_certificate.is_some());
        BASE64_STANDARD
            .decode(instance.tpm_ek_certificate.unwrap())
            .unwrap();
    }
}

#[crate::sqlx_test()]
async fn test_find_instances_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // create vector of IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let instance_ids: Vec<InstanceId> = (1..=end_index)
        .map(|_| uuid::Uuid::new_v4().into())
        .collect();

    let request = tonic::Request::new(rpc::InstancesByIdsRequest { instance_ids });

    let response = env.api.find_instances_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        format!(
            "no more than {} IDs can be accepted",
            env.config.max_find_by_ids
        )
    );
}

#[crate::sqlx_test()]
async fn test_find_instances_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let request = tonic::Request::new(rpc::InstancesByIdsRequest::default());

    let response = env.api.find_instances_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        "at least one ID must be provided",
    );
}

#[crate::sqlx_test]
async fn test_find_instances_by_machine_id_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let request = tonic::Request::new(dpu_machine_id);
    let response = env.api.find_instance_by_machine_id(request).await;
    // validate
    assert!(response.is_ok(),);
    assert_eq!(response.unwrap().into_inner().instances.len(), 0);
}
