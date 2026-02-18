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

use carbide_uuid::machine::MachineId;
use common::api_fixtures::{create_managed_host, create_test_env};
use const_format::concatcp;
use rpc::forge::forge_server::Forge;
use sqlx::{Postgres, Row};

use crate::tests::common;
use crate::tests::common::rpc_builder::DhcpDiscovery;

// These should probably go in a common place for both
// this and tests/integration/api_server.rs to share.
const DOMAIN_NAME: &str = "dwrt1.com";
const DNS_ADM_SUBDOMAIN: &str = concatcp!("adm.", DOMAIN_NAME);
const DNS_BMC_SUBDOMAIN: &str = concatcp!("bmc.", DOMAIN_NAME);

#[crate::sqlx_test]
async fn test_dns(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let api = &env.api;

    // Database should have 0 rows in the dns_records view.
    assert_eq!(0, get_dns_record_count(&env.pool).await);

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let interface1 = api
        .discover_dhcp(DhcpDiscovery::builder(&mac_address, "192.0.2.1").tonic_request())
        .await
        .unwrap()
        .into_inner();

    let fqdn1 = interface1.fqdn;
    let ip1 = interface1.address;
    let mac_address = "F1:FF:FF:FF:FF:FF".to_string();
    let interface2 = api
        .discover_dhcp(DhcpDiscovery::builder(&mac_address, "192.0.2.1").tonic_request())
        .await
        .unwrap()
        .into_inner();

    let fqdn2 = interface2.fqdn;
    let ip2 = interface2.address;

    tracing::info!("FQDN1: {}", fqdn1);
    let dns_record = api
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qname: fqdn1 + ".",
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qtype: "A".to_string(),
                real_remote: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    tracing::info!("DNS Record: {:?}", dns_record);
    tracing::info!("IP: {}", ip1);
    assert_eq!(
        ip1.split('/').collect::<Vec<&str>>()[0],
        &*dns_record.records[0].content
    );
    assert_eq!(
        dns_record.records[0].qtype, "A",
        "IPv4 record should have qtype A"
    );

    let dns_record = api
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qtype: "A".to_string(),
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qname: fqdn2 + ".",
                real_remote: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        ip2.split('/').collect::<Vec<&str>>()[0],
        &*dns_record.records[0].content,
    );
    assert_eq!(
        dns_record.records[0].qtype, "A",
        "IPv4 record should have qtype A"
    );

    // Create a managed host to make sure that the MachineId DNS
    // records for the Host and DPU are created + end up in the
    // dns_records view.
    let (host_id, dpu_id) = create_managed_host(&env).await.into();
    let api = &env.api;

    // And now check to make sure the DNS records exist and,
    // of course, that they are correct.
    let machine_ids: [MachineId; 2] = [host_id, dpu_id];
    for machine_id in machine_ids.iter() {
        let mut txn = env.pool.begin().await.unwrap();

        // First, check the BMC record by querying the MachineTopology
        // data for the current machine ID.
        tracing::info!(machine_id = %machine_id, subdomain = %DNS_BMC_SUBDOMAIN, "Checking BMC record");
        let topologies = db::machine_topology::find_by_machine_ids(&mut txn, &[*machine_id])
            .await
            .unwrap();
        let topology = &topologies.get(machine_id).unwrap()[0];
        let bmc_record = api
            .lookup_record(tonic::Request::new(
                rpc::protos::dns::DnsResourceRecordLookupRequest {
                    qname: format!("{}.{}.", machine_id, DNS_BMC_SUBDOMAIN),
                    zone_id: uuid::Uuid::new_v4().to_string(),
                    local: None,
                    remote: None,
                    qtype: "A".to_string(),
                    real_remote: None,
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            topology.topology().bmc_info.ip.as_ref().unwrap().as_str(),
            &*bmc_record.records[0].content
        );
        assert_eq!(
            bmc_record.records[0].qtype, "A",
            "BMC record should have qtype A"
        );

        // And now check the ADM (Admin IP) record by querying the
        // MachineInterface data for the given machineID.
        tracing::info!(machine_id = %machine_id, subdomain = %DNS_ADM_SUBDOMAIN, "Checking ADM record");
        let interface =
            db::machine_interface::get_machine_interface_primary(&machine_id.clone(), &mut txn)
                .await
                .unwrap();
        let adm_record = api
            .lookup_record(tonic::Request::new(
                rpc::protos::dns::DnsResourceRecordLookupRequest {
                    qname: format!("{}.{}.", machine_id, DNS_ADM_SUBDOMAIN),
                    zone_id: uuid::Uuid::new_v4().to_string(),
                    local: None,
                    remote: None,
                    qtype: "A".to_string(),
                    real_remote: None,
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            format!("{}", interface.addresses[0]).as_str(),
            &*adm_record.records[0].content
        );
        assert_eq!(
            adm_record.records[0].qtype, "A",
            "ADM record should have qtype A"
        );
        txn.rollback().await.unwrap();
    }

    // Database should ultimately have 10 rows:
    // - 4x from the DHCP discovery testing.
    // - 6x from the managed host testing.
    //      - 2x fancy names
    //      - 2x admin machine ID names
    //      - 2x bmc machine ID names
    assert_eq!(10, get_dns_record_count(&env.pool).await);

    let status = api
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qname: "".to_string(),
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qtype: "A".to_string(),
                real_remote: None,
            },
        ))
        .await
        .expect_err("Query should return an error");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(status.message(), "qname cannot be empty");

    // Querying for something unknown should return an empty records Vec
    for name in [
        "unknown".to_string(),
        format!("unknown.{DNS_BMC_SUBDOMAIN}."),
    ] {
        let status = api
            .lookup_record(tonic::Request::new(
                rpc::protos::dns::DnsResourceRecordLookupRequest {
                    qname: name.clone(),
                    zone_id: uuid::Uuid::new_v4().to_string(),
                    local: None,
                    remote: None,
                    qtype: "A".to_string(),
                    real_remote: None,
                },
            ))
            .await
            .unwrap()
            .into_inner();

        tracing::info!("Status: {:?}", status);
        assert_eq!(status.records.len(), 0);
    }
}

// test_dns_aaaa verifies that IPv6 addresses in the machine_interface_addresses
// table produce AAAA DNS records (not A records) in the dns_records view.
#[crate::sqlx_test]
async fn test_dns_aaaa(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let api = &env.api;

    let (host_id, _dpu_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await.unwrap();

    // Get the primary interface for this host — it already has an IPv4 address
    // from the managed host creation flow.
    let interface = db::machine_interface::get_machine_interface_primary(&host_id, &mut txn)
        .await
        .unwrap();
    assert!(
        !interface.addresses.is_empty(),
        "interface should have at least one IPv4 address"
    );

    let ipv6_addr: IpAddr = "fd00::1".parse().unwrap();

    // Insert an IPv6 address directly for this interface. This simulates what
    // would happen in a dual-stack environment once DHCPv6 is implemented.
    sqlx::query("INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1, $2)")
        .bind(interface.id)
        .bind(ipv6_addr)
        .execute(&mut *txn)
        .await
        .unwrap();

    txn.commit().await.unwrap();

    // Query the ADM DNS record for this host — should now return both A and
    // AAAA records since the interface has both IPv4 and IPv6 addresses.
    let adm_qname = format!("{}.{}.", host_id, DNS_ADM_SUBDOMAIN);
    let dns_response = api
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qname: adm_qname.clone(),
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qtype: "ANY".to_string(),
                real_remote: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // We should have at least 2 records: the original IPv4 (A) + our IPv6 (AAAA).
    assert!(
        dns_response.records.len() >= 2,
        "expected at least 2 records (A + AAAA), got {}",
        dns_response.records.len()
    );

    // Find the AAAA record and verify it.
    let aaaa_record = dns_response
        .records
        .iter()
        .find(|r| r.qtype == "AAAA")
        .expect("should have an AAAA record");
    assert_eq!(aaaa_record.content, "fd00::1");

    // Also verify the A record is still present and correct.
    let a_record = dns_response
        .records
        .iter()
        .find(|r| r.qtype == "A")
        .expect("should still have an A record");
    let a_ip: IpAddr = a_record.content.parse().unwrap();
    assert!(a_ip.is_ipv4(), "A record content should be an IPv4 address");

    // Also check the shortname view — the same interface's hostname should
    // produce both A and AAAA records via dns_records_shortname_combined.
    let shortname_qname = format!("{}.{}.", interface.hostname, DOMAIN_NAME);
    let shortname_response = api
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qname: shortname_qname,
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qtype: "ANY".to_string(),
                real_remote: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let shortname_aaaa = shortname_response
        .records
        .iter()
        .find(|r| r.qtype == "AAAA")
        .expect("shortname view should also have an AAAA record");
    assert_eq!(shortname_aaaa.content, "fd00::1");

    let shortname_a = shortname_response
        .records
        .iter()
        .find(|r| r.qtype == "A")
        .expect("shortname view should still have an A record");
    assert!(shortname_a.content.parse::<IpAddr>().unwrap().is_ipv4());
}

// test_dns_aaaa_legacy verifies that the legacy DNS RPC (LookupRecordLegacy)
// correctly returns AAAA records for IPv6 addresses. This exercises the legacy
// compat adapter in handlers/dns.rs which converts numeric q_type (28 = AAAA)
// to the string-based format used by the new lookup_record handler.
#[crate::sqlx_test]
async fn test_dns_aaaa_legacy(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let api = &env.api;

    let (host_id, _dpu_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await.unwrap();
    let interface = db::machine_interface::get_machine_interface_primary(&host_id, &mut txn)
        .await
        .unwrap();

    let ipv6_addr: IpAddr = "fd00::1".parse().unwrap();
    sqlx::query("INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1, $2)")
        .bind(interface.id)
        .bind(ipv6_addr)
        .execute(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let adm_qname = format!("{}.{}.", host_id, DNS_ADM_SUBDOMAIN);

    // Test the legacy RPC with q_type=1 (A record).
    let legacy_a_response = api
        .lookup_record_legacy(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some(adm_qname.clone()),
            q_class: Some(1),
            q_type: Some(1), // A
        }))
        .await
        .unwrap()
        .into_inner();

    // The legacy response returns all matching records regardless of q_type
    // (it delegates to lookup_record which returns all types for ANY).
    // At minimum, the IPv4 address should be present.
    assert!(
        !legacy_a_response.rrs.is_empty(),
        "legacy A query should return records"
    );
    let a_rdata = legacy_a_response.rrs.iter().find(|rr| {
        rr.rdata
            .as_ref()
            .and_then(|r| r.parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_ipv4())
    });
    assert!(
        a_rdata.is_some(),
        "legacy A query should include an IPv4 record"
    );

    // Test the legacy RPC with q_type=28 (AAAA record).
    let legacy_aaaa_response = api
        .lookup_record_legacy(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some(adm_qname.clone()),
            q_class: Some(1),
            q_type: Some(28), // AAAA
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(
        !legacy_aaaa_response.rrs.is_empty(),
        "legacy AAAA query should return records"
    );
    let aaaa_rdata = legacy_aaaa_response
        .rrs
        .iter()
        .find(|rr| rr.rdata.as_deref() == Some("fd00::1"));
    assert!(
        aaaa_rdata.is_some(),
        "legacy AAAA query should include the fd00::1 record"
    );
}

// Get the current number of rows in the dns_records view,
// which is expected to start at 0, and then progress, as
// the test continues.
//
// TODO(chet): Find a common place for this and the same exact
// function in api-test/tests/integration/main.rs to exist, instead
// of it being in two places.
pub async fn get_dns_record_count(pool: &sqlx::Pool<Postgres>) -> i64 {
    let mut txn = pool.begin().await.unwrap();
    let query = "SELECT COUNT(*) as row_cnt FROM dns_records";
    let rows = sqlx::query::<_>(query).fetch_one(&mut *txn).await.unwrap();
    rows.try_get("row_cnt").unwrap()
}
