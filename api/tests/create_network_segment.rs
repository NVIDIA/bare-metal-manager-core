mod common;

use std::str::FromStr;

use ipnetwork::{Ipv4Network, Ipv6Network};

use carbide::{
    db::{NetworkSegment, NewNetworkSegment},
    CarbideResult,
};

use log::LevelFilter;

#[tokio::test]
async fn test_create_segment() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: CarbideResult<NetworkSegment> = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain: "m.nvmetal.net".to_string(),
        mtu: Some(1500i32),
        subnet_ipv4: Some(Ipv4Network::from_str("192.0.2.1/24").expect("can't parse network")),
        subnet_ipv6: Some(Ipv6Network::from_str("2001:db8:f::/64").expect("can't parse network")),
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
    .persist(&mut txn)
    .await;

    assert!(segment.is_ok());
    assert_eq!(segment.unwrap().mtu, 1500);
}
