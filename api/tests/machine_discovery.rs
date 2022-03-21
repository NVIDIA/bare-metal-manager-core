use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Once;

use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::CarbideResult;
use carbide::db::{Machine, NewDomain};
use carbide::db::Domain;
use carbide::db::NetworkSegment;
use carbide::db::NewNetworkSegment;

mod common;

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
async fn test_machine_discovery_no_domain() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = common::TestDatabaseManager::new()
        .await
        .expect("Could not create second database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");


    txn.commit().await.unwrap();

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: None,
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        prefix_ipv6: Some(Ipv6Network::from_str("2001:db8:f::/64").expect("can't parse network")),
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(4096),
    }
        .persist(&mut txn2)
        .await
        .expect("Unable to create network segment");

    let machine = Machine::discover(
        &mut txn2,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        "10.0.0.1".parse().unwrap(),
    )
        .await
        .expect("Unable to create machine");

    let interface = machine
        .interfaces()
        .iter()
        .find(|i| i.segment_id() == segment.id)
        .unwrap();

    assert_eq!(interface.address_ipv4(), Some(&Ipv4Addr::new(10, 0, 0, 4)));

    assert_eq!(
        interface.address_ipv6(),
        Some(&Ipv6Addr::from_str("2001:db8:f::1000").unwrap())
    );
}

#[tokio::test]
async fn test_machine_discovery_with_domain() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = common::TestDatabaseManager::new()
        .await
        .expect("Could not create second database manager")
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

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain).unwrap().map(|d| d.id().to_owned()),
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        prefix_ipv6: Some(Ipv6Network::from_str("2001:db8:f::/64").expect("can't parse network")),
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(4096),
    }
        .persist(&mut txn2)
        .await
        .expect("Unable to create network segment");

    let machine = Machine::discover(
        &mut txn2,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        "10.0.0.1".parse().unwrap(),
    )
        .await
        .expect("Unable to create machine");

    let interface = machine
        .interfaces()
        .iter()
        .find(|i| i.segment_id() == segment.id)
        .unwrap();

    assert_eq!(interface.address_ipv4(), Some(&Ipv4Addr::new(10, 0, 0, 4)));

    assert_eq!(
        interface.address_ipv6(),
        Some(&Ipv6Addr::from_str("2001:db8:f::1000").unwrap())
    );
}