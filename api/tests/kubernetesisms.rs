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
use kube::api::PostParams;
use kube::{Api, Client};
use log::LevelFilter;

use carbide::db::constants::FORGE_KUBE_NAMESPACE;
use carbide::vpc_resources::leaf;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
#[ignore]
async fn create_leaf_in_kube() {
    let client = Client::try_default()
        .await
        .expect("Unable to connect to kubernetes");
    let namespace = FORGE_KUBE_NAMESPACE;

    let leafname = uuid::Uuid::new_v4().to_string();

    let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);
    let leaf_spec = leaf::Leaf::new(
        leafname.as_str(),
        leaf::LeafSpec {
            control: Some(leaf::LeafControl {
                maintenance_mode: Some(true),
                management_ip: Some("4.3.2.1".to_string()),
                ssh_credential_kv_path: None,
                vendor: None,
            }),
            host_admin_i_ps: None,
            host_interfaces: None,
        },
    );

    leafs
        .create(&PostParams::default(), &leaf_spec)
        .await
        .expect("Could not create leaf");

    let leaf = leafs
        .get(leafname.as_str())
        .await
        .expect("Could not retrieve new leaf");

    assert_eq!(
        leaf.spec.control.unwrap().management_ip.unwrap(),
        "4.3.2.1".to_string()
    );

    assert!(leaf.status.is_none())
}
