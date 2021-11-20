mod common;

use carbide::db::Machine;
use carbide::db::NetworkSegment;
use carbide::db::NewNetworkSegment;

use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use std::net::Ipv4Addr;
use std::str::FromStr;

use log::LevelFilter;

use mac_address::MacAddress;

use std::sync::Once;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
async fn test_machine_discovery() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let _segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain: "m.nvmetal.net".to_string(),
        mtu: Some(1500i32),
        subnet_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        subnet_ipv6: Some(Ipv6Network::from_str("2001:db8:f::/64").expect("can't parse network")),
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let machine = Machine::discover(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        "10.0.0.1".parse().unwrap(),
    )
    .await
    .expect("Unable to create machine");

    assert_eq!(
        machine
            .interfaces()
            .iter()
            .filter_map(|interface| interface.address_ipv4())
            .collect::<Vec<&Ipv4Addr>>(),
        vec![&Ipv4Addr::from_str("10.0.0.4").unwrap()]
    );
}
