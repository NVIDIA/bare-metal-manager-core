use rpc::forge::{forge_server::Forge, DhcpDiscovery};
use sqlx::Row;

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dns(pool: sqlx::PgPool) {
    let api = common::api_fixtures::create_test_env(pool.clone())
        .await
        .api;

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let interface1 = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let fqdn1 = interface1.fqdn;
    let ip1 = interface1.address;
    let mac_address = "F1:FF:FF:FF:FF:FF".to_string();
    let interface2 = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let fqdn2 = interface2.fqdn;
    let ip2 = interface2.address;

    let dns_record = api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some(fqdn1 + "."),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        ip1.split('/').collect::<Vec<&str>>()[0],
        &dns_record.rrs[0].rdata.clone().unwrap()
    );

    let dns_record = api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some(fqdn2 + "."),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        ip2.split('/').collect::<Vec<&str>>()[0],
        &dns_record.rrs[0].rdata.clone().unwrap()
    );

    // Database should have only 2 rows.
    let mut txn = pool.begin().await.unwrap();
    let query = "SELECT COUNT(*) as row_cnt FROM dns_records";
    let rows = sqlx::query::<_>(query).fetch_one(&mut txn).await.unwrap();
    let rows_count: i64 = rows.try_get("row_cnt").unwrap();

    assert_eq!(2, rows_count);
}
