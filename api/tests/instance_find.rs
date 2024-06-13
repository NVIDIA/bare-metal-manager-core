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

use crate::common::api_fixtures::{
    create_managed_host, create_test_env,
    instance::{create_instance, create_instance_with_labels, single_interface_network_config},
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};
use ::rpc::forge as rpc;
use rpc::forge_server::Forge;

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_instance_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..10 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

        if i % 2 == 0 {
            let (_instance_id, _instance) = create_instance(
                &env,
                &dpu_machine_id,
                &host_machine_id,
                Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
                None,
                vec![],
            )
            .await;
        } else {
            let (_instance_id, _instance) = create_instance_with_labels(
                &env,
                &dpu_machine_id,
                &host_machine_id,
                Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
                None,
                vec![],
                rpc::Metadata {
                    name: format!("instance_{}{}{}", i, i, i).to_string(),
                    description: format!("instance_{}{}{} with label", i, i, i).to_string(),
                    labels: vec![rpc::Label {
                        key: "label_test_key".to_string(),
                        value: Some(format!("label_value_{}", i).to_string()),
                    }],
                },
            )
            .await;
        }
    }

    // test getting all ids
    let request_all = tonic::Request::new(rpc::InstanceSearchConfig { label: None });

    let instance_ids_all = env
        .api
        .find_instance_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_ids_all.instance_ids.len(), 10);

    // test getting ids based on label key
    let request_lbl_key = tonic::Request::new(rpc::InstanceSearchConfig {
        label: Some(rpc::Label {
            key: "label_test_key".to_string(),
            value: None,
        }),
    });

    let instance_ids_lbl_key = env
        .api
        .find_instance_ids(request_lbl_key)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_ids_lbl_key.instance_ids.len(), 5);

    // test getting ids based on label value
    let request_lbl_val = tonic::Request::new(rpc::InstanceSearchConfig {
        label: Some(rpc::Label {
            key: "".to_string(),
            value: Some("label_value_1".to_string()),
        }),
    });

    let instance_ids_lbl_val = env
        .api
        .find_instance_ids(request_lbl_val)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_ids_lbl_val.instance_ids.len(), 1);

    // test getting ids based on label key and value
    let request_lbl_key_val = tonic::Request::new(rpc::InstanceSearchConfig {
        label: Some(rpc::Label {
            key: "label_test_key".to_string(),
            value: Some("label_value_3".to_string()),
        }),
    });

    let instance_ids_lbl_key_val = env
        .api
        .find_instance_ids(request_lbl_key_val)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_ids_lbl_key_val.instance_ids.len(), 1);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_instances_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..10 {
        let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

        if i % 2 == 0 {
            let (_instance_id, _instance) = create_instance(
                &env,
                &dpu_machine_id,
                &host_machine_id,
                Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
                None,
                vec![],
            )
            .await;
        } else {
            let (_instance_id, _instance) = create_instance_with_labels(
                &env,
                &dpu_machine_id,
                &host_machine_id,
                Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
                None,
                vec![],
                rpc::Metadata {
                    name: format!("instance_{}{}{}", i, i, i).to_string(),
                    description: format!("instance_{}{}{} with label", i, i, i).to_string(),
                    labels: vec![rpc::Label {
                        key: "label_test_key".to_string(),
                        value: Some(format!("label_value_{}", i).to_string()),
                    }],
                },
            )
            .await;
        }
    }

    let request_ids = tonic::Request::new(rpc::InstanceSearchConfig {
        label: Some(rpc::Label {
            key: "label_test_key".to_string(),
            value: None,
        }),
    });

    let instance_id_list = env
        .api
        .find_instance_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_id_list.instance_ids.len(), 5);

    let request_instances = tonic::Request::new(instance_id_list.clone());

    let instance_list = env
        .api
        .find_instances_by_ids(request_instances)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(instance_list.instances.len(), 5);

    // validate we got instances with specified ids
    let mut instances_copy = instance_list.instances.clone();
    for _ in 0..5 {
        let instance = instances_copy.remove(0);
        let instance_id = instance.id.unwrap();
        assert!(instance_id_list.instance_ids.contains(&instance_id));
    }
}
