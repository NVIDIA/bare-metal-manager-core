/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::IpAddr;
use std::str::FromStr;

use kube::runtime::wait::Condition;
use log::LevelFilter;

use carbide::db::vpc_resource_leaf::{NewVpcResourceLeaf, VpcResourceLeaf};
use carbide::kubernetes::ConditionReadyMatcher;
use carbide::vpc_resources::leaf;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

const FIXTURE_CREATED_MACHINE_ID: &str =
    "fm100dt37B6YIKCXOOKMSFIB3A3RSBKXTNS6437JFZVKX3S43LZQ3QSKUCA";

#[ignore]
#[sqlx::test]
async fn new_leafs_are_in_new_state(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(FIXTURE_CREATED_MACHINE_ID.parse().unwrap())
        .persist(&mut txn)
        .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    assert!(VpcResourceLeaf::find(&mut txn, leaf.id()).await.is_ok());

    Ok(())
}

#[sqlx::test]
async fn find_leaf_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(FIXTURE_CREATED_MACHINE_ID.parse().unwrap())
        .persist(&mut txn)
        .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    let leaf = VpcResourceLeaf::find(&mut txn, leaf.id()).await?;
    assert_eq!(leaf.id(), &FIXTURE_CREATED_MACHINE_ID.parse().unwrap());

    Ok(())
}

#[sqlx::test]
async fn find_leaf_and_update_loopback_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new(FIXTURE_CREATED_MACHINE_ID.parse().unwrap())
        .persist(&mut txn)
        .await?;
    assert!(leaf.loopback_ip_address().is_none());

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let address = IpAddr::from_str("1.2.3.4")?;

    let mut new_leaf = VpcResourceLeaf::find(&mut txn, leaf.id()).await?;

    new_leaf
        .update_loopback_ip_address(&mut txn, address)
        .await?;

    assert_eq!(
        new_leaf.loopback_ip_address().map(|ip| ip.to_string()),
        Some("1.2.3.4".to_string())
    );

    Ok(())
}

///
/// we took a leaf object from the Kube API so that we could be sure
/// we're operating with one "just like the real one" in our tests
fn get_default_leaf() -> leaf::Leaf {
    let json = r#"{"apiVersion":"networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1",
    "kind":"Leaf","metadata":{"creationTimestamp":"2022-09-23T21:01:18Z",
    "finalizers":["leaf.networkfabric.vpc.forge/finalizer"],"generation":3,
    "managedFields":[{"apiVersion":"networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1",
    "fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:finalizers":{".":{},
    "v:\"leaf.networkfabric.vpc.forge/finalizer\"":{}}}},"manager":"manager","operation":"Update",
    "time":"2022-09-23T21:01:18Z"},{"apiVersion":"networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1",
    "fieldsType":"FieldsV1","fieldsV1":{"f:status":{".":{},"f:asn":{},"f:conditions":{},"f:hostAdminDHCPServer":{},
    "f:hostAdminIPs":{".":{},"f:pf0hpf":{}},"f:loopbackIP":{}}},"manager":"manager","operation":"Update","subresource":
    "status","time":"2022-09-23T21:04:40Z"},{"apiVersion":"networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1",
    "fieldsType":"FieldsV1","fieldsV1":{"f:spec":{".":{},"f:control":{".":{},"f:managementIP":{},"f:vendor":{}},
    "f:hostAdminIPs":{".":{},"f:pf0hpf":{}},"f:hostInterfaces":{".":{},"f:08-C0-EB-CB-0D-E6":{}}}},"manager":"unknown",
    "operation":"Update","time":"2022-09-23T21:18:18Z"}],"name":"a469ee48-2f5c-41e4-a0ca-60160e5915a7","namespace":
    "forge-system","resourceVersion":"40682169","uid":"19d6148d-c01f-4cd2-8f7e-3438a608b131"},"spec":{"control":
    {"managementIP":"10.180.221.200","vendor":"DPU"},"hostAdminIPs":{"pf0hpf":"10.180.124.16"},"hostInterfaces":
    {"08-C0-EB-CB-0D-E6":"pf0hpf"}},"status":{"asn":4240186200,"conditions":[{"lastTransitionTime":
    "2022-09-29T16:40:49Z","status":"True","type":"Liveness"}],"hostAdminDHCPServer":"10.180.32.74",
    "hostAdminIPs":{"pf0hpf":"11.180.124.16"},"loopbackIP":"10.180.96.223"}}"#;

    serde_json::from_str(json).unwrap()
}

#[test]
fn test_serialize() {
    let mut leaf = get_default_leaf();

    let matcher = ConditionReadyMatcher {
        matched_name: "my_cool_name".to_string(),
    };

    assert!(!matcher.matches_object(Option::<&leaf::Leaf>::None));
    assert!(!matcher.matches_object(Some(&leaf)));
    leaf.metadata.name = Some("my_cool_name".to_string());
    assert!(matcher.matches_object(Some(&leaf)));
}
