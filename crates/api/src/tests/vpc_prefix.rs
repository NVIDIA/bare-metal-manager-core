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

use rpc::forge::forge_server::Forge;
use rpc::forge::{
    PrefixMatchType, VpcPrefixCreationRequest, VpcPrefixDeletionRequest, VpcPrefixSearchQuery,
};
use sqlx::PgPool;
use tonic::Request;

use crate::tests::common::api_fixtures::{create_test_env, get_vpc_fixture_id};

#[crate::sqlx_test]
async fn test_create_and_delete_vpc_prefix_deprecated_fields(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let ip_prefix = "192.0.2.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: ip_prefix.into(),
        name: "Test VPC prefix".into(),
        vpc_id: Some(vpc_id),
        ..Default::default()
    };
    let request = Request::new(new_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    let vpc_prefix = response.expect("Could not create VPC prefix").into_inner();

    assert_eq!(
        vpc_prefix.prefix.as_str(),
        ip_prefix,
        "The prefix after resource creation was different from what we requested"
    );

    let id = vpc_prefix
        .id
        .expect("The id field on the new VPC prefix is missing (this should be impossible)");

    let delete_by_id = VpcPrefixDeletionRequest { id: Some(id) };
    let request = Request::new(delete_by_id);
    let response = env.api.delete_vpc_prefix(request).await;
    let _deletion_result = response.expect("Could not delete VPC prefix").into_inner();

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_and_delete_vpc_prefix(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let ip_prefix = "192.0.2.0/25";
    let vpc_id = get_vpc_fixture_id(&env).await;
    let new_vpc_prefix = VpcPrefixCreationRequest {
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
    let response = env.api.create_vpc_prefix(request).await;
    let vpc_prefix = response.expect("Could not create VPC prefix").into_inner();

    assert_eq!(
        vpc_prefix.prefix.as_str(),
        ip_prefix,
        "The prefix after resource creation was different from what we requested"
    );

    let id = vpc_prefix
        .id
        .expect("The id field on the new VPC prefix is missing (this should be impossible)");

    let delete_by_id = VpcPrefixDeletionRequest { id: Some(id) };
    let request = Request::new(delete_by_id);
    let response = env.api.delete_vpc_prefix(request).await;
    let _deletion_result = response.expect("Could not delete VPC prefix").into_inner();

    Ok(())
}

#[crate::sqlx_test]
async fn test_overlapping_vpc_prefixes(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let ip_prefix = "192.0.2.128/25";
    let overlapping_ip_prefix = "192.0.2.192/26";

    let new_vpc_prefix = VpcPrefixCreationRequest {
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
    let response = env.api.create_vpc_prefix(request).await;
    assert!(response.is_ok());

    let overlapping_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: overlapping_ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Overlapping VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(overlapping_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    assert!(response.is_err());

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_create_with_invalid_metadata(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let ip_prefix = "192.0.2.0/24";

    let new_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    let error = response
        .expect_err("expected create create vpc prefix to fail")
        .to_string();
    assert!(
        error.contains("Invalid value"),
        "Error message should contain 'Invalid value', but is {error}"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_invalid_vpc_prefixes(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    for (prefix, description) in [
        (
            "198.51.100.0/24",
            "This VPC prefix is not within the site prefixes",
        ),
        (
            "2001:db8::/64",
            "This IPv6 VPC prefix is also not within the site prefixes",
        ),
        (
            "192.0.2.255/25",
            "This VPC prefix is not specified in canonical form (bits after the prefix are set to 1)",
        ),
    ] {
        let bad_vpc_prefix = VpcPrefixCreationRequest {
            id: None,
            prefix: String::new(),
            name: String::new(),
            vpc_id: Some(vpc_id),

            config: Some(rpc::forge::VpcPrefixConfig {
                prefix: prefix.into(),
            }),
            metadata: Some(rpc::forge::Metadata {
                name: description.into(),
                ..Default::default()
            }),
        };
        let request = Request::new(bad_vpc_prefix);
        let response = env.api.create_vpc_prefix(request).await;

        assert!(
            response.is_err(),
            "A prefix ({prefix}) with description \"{description}\" was accepted when it should have been rejected"
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_search(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let p1 = "192.0.2.0/25";
    let p2 = "192.0.2.128/25";
    let create_p1 = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig { prefix: p1.into() }),
        metadata: Some(rpc::forge::Metadata {
            name: "VPC prefix p1".into(),
            ..Default::default()
        }),
    };
    let create_p2 = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        name: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig { prefix: p2.into() }),
        metadata: Some(rpc::forge::Metadata {
            name: "VPC prefix p2".into(),
            ..Default::default()
        }),
    };
    let p1_request = Request::new(create_p1);
    let p2_request = Request::new(create_p2);
    let p1_response = env.api.create_vpc_prefix(p1_request).await;
    let p2_response = env.api.create_vpc_prefix(p2_request).await;
    let p1 = p1_response
        .expect("Couldn't create a VPC prefix ({p1})")
        .into_inner();
    let p2 = p2_response
        .expect("Couldn't create a VPC prefix ({p2})")
        .into_inner();

    // Search for each prefix by exact prefix match.
    for (prefix, vpc_prefix_id) in [(p1.prefix.as_str(), p1.id), (p2.prefix.as_str(), p2.id)] {
        dbg!(&vpc_prefix_id);
        dbg!(vpc_id);
        let prefix_query = VpcPrefixSearchQuery {
            vpc_id: Some(vpc_id),
            tenant_prefix_id: None,
            name: None,
            prefix_match: Some(prefix.into()),
            prefix_match_type: Some(PrefixMatchType::PrefixExact as i32),
        };
        let search_request = Request::new(prefix_query);
        let search_response = env.api.search_vpc_prefixes(search_request).await;
        let vpc_prefix_id_list = search_response
            .expect("Couldn't execute VPC prefix search")
            .into_inner();
        // Each search should return a single ID matching the ID we already
        // know.
        let expected = vpc_prefix_id_list.vpc_prefix_ids.as_slice();
        let found = vpc_prefix_id.as_slice();
        assert_eq!(
            expected, found,
            "When searching for an exact prefix {prefix}, we expected a single \
            VPC prefix ID ({expected:?}) but found {found:?}",
        );
    }

    // Search for each prefix by an address it contains.
    for (prefix, vpc_prefix_id) in [
        // A bare address should be treated the same as an explicit /32.
        ("192.0.2.85", p1.id),
        ("192.0.2.170/32", p2.id),
    ] {
        dbg!(&vpc_prefix_id);
        dbg!(vpc_id);
        let prefix_query = VpcPrefixSearchQuery {
            vpc_id: Some(vpc_id),
            tenant_prefix_id: None,
            name: None,
            prefix_match: Some(prefix.into()),
            prefix_match_type: Some(PrefixMatchType::PrefixContains as i32),
        };
        let search_request = Request::new(prefix_query);
        let search_response = env.api.search_vpc_prefixes(search_request).await;
        let vpc_prefix_id_list = search_response
            .expect("Couldn't execute VPC prefix search")
            .into_inner();
        // Each search should return a single ID matching the ID we already
        // know.
        let expected = vpc_prefix_id_list.vpc_prefix_ids.as_slice();
        let found = vpc_prefix_id.as_slice();
        assert_eq!(
            expected, found,
            "When searching for a contained prefix {prefix}, we expected a \
            single VPC prefix ID ({expected:?}) but found {found:?}",
        );
    }

    // Search for both prefixes by searching for a network prefix containing
    // both of them.
    let prefix = "192.0.2.0/24";
    let prefix_query = VpcPrefixSearchQuery {
        vpc_id: Some(vpc_id),
        tenant_prefix_id: None,
        name: None,
        prefix_match: Some(prefix.into()),
        prefix_match_type: Some(PrefixMatchType::PrefixContainedBy as i32),
    };
    let search_request = Request::new(prefix_query);
    let search_response = env.api.search_vpc_prefixes(search_request).await;
    let vpc_prefix_id_list = search_response
        .expect("Couldn't execute VPC prefix search")
        .into_inner();
    let returned_vpc_prefix_ids = vpc_prefix_id_list.vpc_prefix_ids;
    for expected_vpc_prefix in [&p1, &p2] {
        let expected_id = expected_vpc_prefix.id.unwrap();
        let expected_prefix = expected_vpc_prefix.prefix.as_str();
        assert!(
            returned_vpc_prefix_ids.contains(&expected_id),
            "We expected to find the VPC prefix id {expected_id} for prefix {expected_prefix} in the search results ({returned_vpc_prefix_ids:?}), but it was absent"
        );
    }

    Ok(())
}
