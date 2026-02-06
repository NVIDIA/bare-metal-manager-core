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
