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

use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use carbide_uuid::machine::MachineInterfaceId;
use db::{self, ObjectColumnFilter, network_segment};
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::machine_interface_address::MachineInterfaceAssociation;
use model::site_explorer::ExploredManagedHost;
use rpc::forge_server::Forge;
use tonic::Code;

use crate::tests::common;
use crate::tests::common::api_fixtures::{TestEnv, create_managed_host, create_test_env};

fn req(
    bmc_mac: &MacAddress,
    dry_run: bool,
) -> tonic::Request<rpc::EraseHostMetadataByBmcMacRequest> {
    tonic::Request::new(rpc::EraseHostMetadataByBmcMacRequest {
        bmc_mac: bmc_mac.to_string(),
        dry_run,
    })
}

/// Create a real `machine_interfaces` row for `mac` on the admin segment (no live
/// machine), returning its id and assigned IP.
async fn seed_interface(env: &TestEnv, mac: MacAddress) -> (MachineInterfaceId, IpAddr) {
    let mut txn = env.pool.begin().await.unwrap();
    let segment = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(network_segment::IdColumn, env.admin_segment_ref()),
        model::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);
    let iface = db::machine_interface::create(
        &mut txn,
        std::slice::from_ref(&segment),
        &mac,
        true,
        AddressSelectionStrategy::NextAvailableIp,
        None,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();
    let ip = *iface
        .addresses
        .first()
        .expect("interface must have an address");
    (iface.id, ip)
}

async fn seed_managed_host(env: &TestEnv, host_bmc_ip: IpAddr) {
    let host = ExploredManagedHost {
        host_bmc_ip,
        dpus: vec![],
    };
    let mut txn = env.pool.begin().await.unwrap();
    db::explored_managed_host::update(txn.as_mut(), &[&host])
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

fn bmc_credential_key(mac: MacAddress) -> CredentialKey {
    CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: mac,
        },
    }
}

async fn seed_bmc_credential(env: &TestEnv, mac: MacAddress) {
    env.api
        .credential_manager
        .set_credentials(
            &bmc_credential_key(mac),
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "notforprod".to_string(),
            },
        )
        .await
        .unwrap();
}

// The full leftover set for a MAC -- interface (with boot override), exploration
// report, managed host, retained boot row and vault credential -- is reported by
// dry-run without deletion, then fully erased by a real run.
#[crate::sqlx_test]
async fn test_erase_removes_all_leftover_records(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();

    let (iface_id, ip) = seed_interface(&env, bmc_mac).await;

    let mut txn = env.pool.begin().await.unwrap();
    // A boot override on the interface: its FK to machine_interfaces has no cascade,
    // so erase must clear it before deleting the interface.
    db::machine_boot_override::create(txn.as_mut(), iface_id, Some("pxe-script".to_string()), None)
        .await
        .unwrap();
    // Give the interface a boot_interface_id so its deletion produces a
    // retained_boot_interfaces row -- which erase must then clear.
    sqlx::query("UPDATE machine_interfaces SET boot_interface_id = $1 WHERE id = $2")
        .bind("NIC.Integrated.1")
        .bind(iface_id)
        .execute(txn.as_mut())
        .await
        .unwrap();
    // Convergence markers for both credential types keyed by this MAC.
    db::credential_rotation::record_device_converged(
        txn.as_mut(),
        bmc_mac,
        db::credential_rotation::CredentialRotationType::HostUefi,
    )
    .await
    .unwrap();
    db::credential_rotation::record_device_converged(
        txn.as_mut(),
        bmc_mac,
        db::credential_rotation::CredentialRotationType::Bmc,
    )
    .await
    .unwrap();
    common::endpoint::insert_endpoint_with_bmc_mac(txn.as_mut(), &ip.to_string(), bmc_mac)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    seed_managed_host(&env, ip).await;
    seed_bmc_credential(&env, bmc_mac).await;

    // Dry-run reports every record and clears nothing.
    let dry = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, true))
        .await
        .unwrap()
        .into_inner();
    assert!(dry.dry_run);
    assert_eq!(dry.machine_interface_ids, vec![iface_id.to_string()]);
    assert_eq!(dry.explored_endpoint_ips, vec![ip.to_string()]);
    assert_eq!(dry.explored_managed_host_ips, vec![ip.to_string()]);
    assert!(
        dry.bmc_credentials_cleared,
        "dry-run must report creds exist"
    );

    let mut txn = env.pool.begin().await.unwrap();
    assert_eq!(
        db::machine_interface::find_by_mac_address(txn.as_mut(), bmc_mac)
            .await
            .unwrap()
            .len(),
        1,
        "dry-run must not delete the interface"
    );
    txn.rollback().await.unwrap();
    assert!(
        env.api
            .credential_manager
            .get_credentials(&bmc_credential_key(bmc_mac))
            .await
            .unwrap()
            .is_some(),
        "dry-run must not delete credentials"
    );

    // Real run erases everything.
    let done = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .unwrap()
        .into_inner();
    assert!(!done.dry_run);
    assert!(done.bmc_credentials_cleared);

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::machine_interface::find_by_mac_address(txn.as_mut(), bmc_mac)
            .await
            .unwrap()
            .is_empty(),
        "interface must be gone"
    );
    assert!(
        db::explored_endpoints::find_by_mac_address(txn.as_mut(), bmc_mac)
            .await
            .unwrap()
            .is_empty(),
        "endpoint must be gone"
    );
    assert!(
        db::explored_managed_host::find_by_ips(txn.as_mut(), vec![ip])
            .await
            .unwrap()
            .is_empty(),
        "managed host must be gone"
    );
    assert!(
        db::machine_boot_override::find_optional(txn.as_mut(), iface_id)
            .await
            .unwrap()
            .is_none(),
        "boot override must be gone"
    );
    assert!(
        db::retained_boot_interface::find_by_mac(txn.as_mut(), bmc_mac, None)
            .await
            .unwrap()
            .is_none(),
        "retained boot row must be cleared for a clean slate"
    );
    let marker_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_credential_rotation WHERE device_mac = $1")
            .bind(bmc_mac)
            .fetch_one(txn.as_mut())
            .await
            .unwrap();
    assert_eq!(marker_count, 0, "convergence markers must be cleared");
    txn.rollback().await.unwrap();
    assert!(
        env.api
            .credential_manager
            .get_credentials(&bmc_credential_key(bmc_mac))
            .await
            .unwrap()
            .is_none(),
        "vault credential must be gone"
    );
}

// An explored managed-host row left behind with no exploration report is still
// cleaned via the MAC's interface IP -- the case the feature exists for. No live
// BMC call is made, so an off/relocated host is handled from cached data alone.
#[crate::sqlx_test]
async fn test_erase_orphan_managed_host_with_no_endpoint(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:01").unwrap();

    let (_iface_id, ip) = seed_interface(&env, bmc_mac).await;
    seed_managed_host(&env, ip).await;

    let done = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(done.explored_managed_host_ips, vec![ip.to_string()]);

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::explored_managed_host::find_by_ips(txn.as_mut(), vec![ip])
            .await
            .unwrap()
            .is_empty(),
        "orphan managed host must be erased"
    );
    assert!(
        db::machine_interface::find_by_mac_address(txn.as_mut(), bmc_mac)
            .await
            .unwrap()
            .is_empty(),
        "interface must be erased"
    );
    txn.rollback().await.unwrap();
}

// Dry-run reports credential presence without clearing; a real run clears them.
#[crate::sqlx_test]
async fn test_erase_dry_run_reports_then_clears_bmc_credentials(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:02").unwrap();
    seed_bmc_credential(&env, bmc_mac).await;

    let dry = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, true))
        .await
        .unwrap()
        .into_inner();
    assert!(dry.bmc_credentials_cleared, "dry-run reports creds present");
    assert!(
        env.api
            .credential_manager
            .get_credentials(&bmc_credential_key(bmc_mac))
            .await
            .unwrap()
            .is_some(),
        "dry-run must not clear credentials"
    );

    env.api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .unwrap();
    assert!(
        env.api
            .credential_manager
            .get_credentials(&bmc_credential_key(bmc_mac))
            .await
            .unwrap()
            .is_none(),
        "real run must clear credentials"
    );
}

// A completely unknown MAC is a safe no-op: empty record lists, no error.
#[crate::sqlx_test]
async fn test_erase_unknown_mac_is_noop(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();

    let response = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .unwrap()
        .into_inner();

    assert!(response.machine_interface_ids.is_empty());
    assert!(response.explored_endpoint_ips.is_empty());
    assert!(response.explored_managed_host_ips.is_empty());
    assert!(!response.bmc_credentials_cleared);
}

// A malformed MAC is rejected as InvalidArgument, not Internal.
#[crate::sqlx_test]
async fn test_erase_invalid_mac_is_invalid_argument(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let err = env
        .api
        .erase_host_metadata_by_bmc_mac(tonic::Request::new(
            rpc::EraseHostMetadataByBmcMacRequest {
                bmc_mac: "not-a-mac".to_string(),
                dry_run: true,
            },
        ))
        .await
        .expect_err("malformed MAC must be rejected");
    assert_eq!(err.code(), Code::InvalidArgument);
}

// When a live machine still owns the BMC endpoint, erase-metadata refuses and
// points the operator at force-delete instead.
#[crate::sqlx_test]
async fn test_erase_refuses_when_machine_exists(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();
    let host_machine = env.find_machine(host_machine_id).await.remove(0);
    let bmc_mac = host_machine
        .bmc_info
        .expect("host must have BMC info")
        .mac
        .expect("host BMC must have a MAC");

    let err = env
        .api
        .erase_host_metadata_by_bmc_mac(tonic::Request::new(
            rpc::EraseHostMetadataByBmcMacRequest {
                bmc_mac,
                dry_run: true,
            },
        ))
        .await
        .expect_err("must refuse to erase metadata for a live machine");
    assert_eq!(err.code(), Code::InvalidArgument);
}

// An interface owned by a switch (not a host machine) is refused -- this cleanup
// tool must never touch a switch/power-shelf BMC.
#[crate::sqlx_test]
async fn test_erase_refuses_switch_owned_interface(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:03").unwrap();
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None)
        .await
        .unwrap();

    let (iface_id, _ip) = seed_interface(&env, bmc_mac).await;
    let mut txn = env.pool.begin().await.unwrap();
    db::machine_interface::associate_bmc_interface(
        &iface_id,
        MachineInterfaceAssociation::Switch(switch_id),
        txn.as_mut(),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let err = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .expect_err("must refuse a switch-owned interface");
    assert_eq!(err.code(), Code::InvalidArgument);
}

// erase-metadata never touches expected machines -- NICo does not own that data.
#[crate::sqlx_test]
async fn test_erase_preserves_expected_machine(pool: sqlx::PgPool) {
    use model::expected_machine::{ExpectedMachine, ExpectedMachineData};

    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:04").unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    db::expected_machine::create(
        txn.as_mut(),
        ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac,
            data: ExpectedMachineData {
                bmc_username: "ADMIN".into(),
                bmc_password: "notforprod".into(),
                serial_number: "SN-ERASE-TEST".into(),
                ..Default::default()
            },
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // Give erase something real to do so it exercises the full path.
    let (_iface_id, _ip) = seed_interface(&env, bmc_mac).await;

    env.api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::expected_machine::find_by_bmc_mac_address(txn.as_mut(), bmc_mac)
            .await
            .unwrap()
            .is_some(),
        "expected machine must be preserved"
    );
    txn.rollback().await.unwrap();
}

// A stale interface IP for the requested MAC that has since been reassigned to a
// different, staged host must not take that host's managed-host row (or endpoint)
// down. The stale interface is still cleaned; the other host is protected.
#[crate::sqlx_test]
async fn test_erase_protects_reused_ip_of_another_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let stale_mac = MacAddress::from_str("aa:bb:cc:dd:ee:05").unwrap();
    let other_mac = MacAddress::from_str("aa:bb:cc:dd:ee:06").unwrap();

    // Old host's leftover interface at some IP.
    let (_iface_id, ip) = seed_interface(&env, stale_mac).await;

    // That IP now belongs to a different, not-yet-ingested host: its BMC advertises
    // `other_mac`, and it has a staged managed-host row at the same IP.
    let mut txn = env.pool.begin().await.unwrap();
    common::endpoint::insert_endpoint_with_bmc_mac(txn.as_mut(), &ip.to_string(), other_mac)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    seed_managed_host(&env, ip).await;

    let done = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&stale_mac, false))
        .await
        .unwrap()
        .into_inner();
    assert!(
        done.explored_managed_host_ips.is_empty(),
        "must not report the other host's managed-host row"
    );

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::machine_interface::find_by_mac_address(txn.as_mut(), stale_mac)
            .await
            .unwrap()
            .is_empty(),
        "the stale interface is still cleaned"
    );
    assert!(
        !db::explored_managed_host::find_by_ips(txn.as_mut(), vec![ip])
            .await
            .unwrap()
            .is_empty(),
        "the other host's managed-host row must be protected"
    );
    assert!(
        !db::explored_endpoints::find_all_by_ip(ip, txn.as_mut())
            .await
            .unwrap()
            .is_empty(),
        "the other host's endpoint must be protected"
    );
    txn.rollback().await.unwrap();
}

// An interface attached to a DPU machine is refused, like the switch case.
#[crate::sqlx_test]
async fn test_erase_refuses_dpu_owned_interface(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:07").unwrap();

    let (iface_id, _ip) = seed_interface(&env, bmc_mac).await;
    let mut txn = env.pool.begin().await.unwrap();
    db::machine_interface::associate_interface_with_dpu_machine(
        &iface_id,
        &dpu_machine_id,
        txn.as_mut(),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let err = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&bmc_mac, false))
        .await
        .expect_err("must refuse a DPU-owned interface");
    assert_eq!(err.code(), Code::InvalidArgument);
}

// An endpoint that mentions the requested MAC only on a host *system* NIC, while its
// BMC (Manager) advertises a different MAC, belongs to another host and must be
// protected -- even though the JSONB search matches it.
#[crate::sqlx_test]
async fn test_erase_protects_endpoint_owned_by_another_bmc(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let requested_mac = MacAddress::from_str("aa:bb:cc:dd:ee:08").unwrap();
    let other_bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:09").unwrap();
    let ip = "141.219.24.20";

    let mut txn = env.pool.begin().await.unwrap();
    common::endpoint::insert_endpoint_system_mac_other_bmc(
        txn.as_mut(),
        ip,
        requested_mac,
        other_bmc_mac,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let done = env
        .api
        .erase_host_metadata_by_bmc_mac(req(&requested_mac, false))
        .await
        .unwrap()
        .into_inner();
    assert!(
        done.explored_endpoint_ips.is_empty(),
        "an endpoint owned by another BMC must not be reported or deleted"
    );

    let ip_addr = IpAddr::from_str(ip).unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        !db::explored_endpoints::find_all_by_ip(ip_addr, txn.as_mut())
            .await
            .unwrap()
            .is_empty(),
        "the other BMC's endpoint must be left intact"
    );
    txn.rollback().await.unwrap();
}
