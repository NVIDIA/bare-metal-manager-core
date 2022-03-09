mod common;

use std::any::Any;
use std::str::FromStr;

use carbide::db::MachineIdsFilter::All;
use carbide::{
    db::{Domain, NetworkSegment, NewDomain, NewNetworkSegment},
    CarbideResult,
};
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::LevelFilter;
use std::sync::Once;

fn setup() {
    Once::new().call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
async fn test_create_segment_with_domain() {
    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");

    let my_domain = "dwrt.com";

    let new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn)
    .await;

    txn.commit().await.unwrap();

    let domain = Domain::find_by_name(&mut txn2, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    // TODO - Find a domain based on UUID and use that on subdomain_id
    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain.unwrap().id().to_owned()),
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("192.0.2.1/24").expect("can't parse network")),
        prefix_ipv6: Some(Ipv6Network::from_str("2001:db8:f::/64").expect("can't parse network")),
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
    .persist(&mut txn2)
    .await
    .expect("Unable to create network segment");

    assert!(matches!(&segment, NetworkSegment));
    assert!(matches!(segment.subdomain_id, domain))
}

#[tokio::test]
async fn test_create_segment_no_domain() {
    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: None,
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("192.0.2.1/24").expect("can't parse network")),
        prefix_ipv6: Some(Ipv6Network::from_str("2001:db8:f::/64").expect("can't parse network")),
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    assert!(matches!(segment, NetworkSegment));
}
