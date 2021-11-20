mod common;

use carbide::db::AddressSelectionStrategy;
use carbide::db::Machine;
use carbide::db::MachineInterface;
use carbide::db::NetworkSegment;
use carbide::CarbideError;

use carbide::db::NewNetworkSegment;
use ipnetwork::Ipv4Network;

use log::LevelFilter;

use std::str::FromStr;
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
async fn prevent_duplicate_mac_addresses() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain: "test.example.com".to_string(),
        mtu: Some(1500i32),
        subnet_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        subnet_ipv6: None,
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = Machine::discover(&mut txn, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to create machine");

    let duplicate_interface = MachineInterface::create(
        &mut txn,
        &new_machine,
        &new_segment,
        &test_mac,
        &AddressSelectionStrategy::Automatic(false),
        &AddressSelectionStrategy::Empty,
    )
    .await;

    assert!(matches!(
        duplicate_interface,
        Err(CarbideError::NetworkSegmentDuplicateMacAddress(_))
    ));
}
