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

use common::api_fixtures::{create_managed_host, create_test_env};

use crate::CarbideError;
use crate::handlers::client_resolution::resolve_machine_interface;
use crate::tests::common;
use crate::tests::common::api_fixtures::instance::{
    default_os_config, default_tenant_config, single_interface_network_config,
};

// A client_ip that matches a row in machine_interface_addresses (the
// common admin/host case) should resolve directly to that interface.
#[crate::sqlx_test]
async fn test_resolve_machine_interface_via_direct_admin_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[mh.host().id])
        .await
        .unwrap();
    let host_iface = &interfaces[&mh.host().id][0];
    let admin_ip = host_iface.addresses[0];
    let expected_interface_id = host_iface.id;
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let resolved = resolve_machine_interface(txn.as_mut(), admin_ip)
        .await
        .expect("admin IP should resolve to its machine_interface");
    txn.rollback().await.unwrap();

    assert_eq!(resolved.id, expected_interface_id);
}

// A client_ip that maps to a tenant-allocated instance_address (rather
// than a machine_interface_addresses entry) should resolve to the
// host's admin machine_interface via instance -> host_machine_id ->
// host_interfaces. This is the "PXE-booting an assigned host over its
// tenant network" path that the find_by_ip fallback was added for.
#[crate::sqlx_test]
async fn test_resolve_machine_interface_via_instance_address(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[mh.host().id])
        .await
        .unwrap();
    let expected_interface_id = interfaces[&mh.host().id][0].id;
    txn.rollback().await.unwrap();

    let config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
        spxconfig: None,
    };
    let tinstance = mh.instance_builer(&env).config(config).build().await;

    // Look up the tenant IP carbide-api allocated to the instance.
    let mut txn = env.pool.begin().await.unwrap();
    let inst_addr = db::instance_address::find_by_instance_id_and_segment_id(
        txn.as_mut(),
        &tinstance.id,
        &segment_id,
    )
    .await
    .unwrap()
    .expect("instance should have a tenant address on the segment");
    let tenant_ip = inst_addr.address;

    let resolved = resolve_machine_interface(txn.as_mut(), tenant_ip)
        .await
        .expect("tenant IP should resolve to the host's admin machine_interface");
    txn.rollback().await.unwrap();

    // The resolved interface is the host's admin interface -- the same one
    // we'd have hit if the request had come in on the admin IP directly.
    assert_eq!(resolved.id, expected_interface_id);
}

// A client_ip that isn't in either table should NotFound cleanly.
#[crate::sqlx_test]
async fn test_resolve_machine_interface_unknown_ip_returns_not_found(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mut txn = env.pool.begin().await.unwrap();
    let result = resolve_machine_interface(txn.as_mut(), "203.0.113.99".parse().unwrap()).await;
    txn.rollback().await.unwrap();

    let err = result.expect_err("expected NotFound for unknown client IP");
    match err {
        CarbideError::NotFoundError { kind, .. } => {
            assert_eq!(kind, "Client", "expected NotFound kind=Client, got {kind}")
        }
        other => panic!("expected NotFoundError, got {other:?}"),
    }
}
