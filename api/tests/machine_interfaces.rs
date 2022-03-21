use std::str::FromStr;
use std::sync::Once;

use ipnetwork::Ipv4Network;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::CarbideError;
use carbide::db::{AbsentSubnetStrategy, AddressSelectionStrategy, Machine, MachineInterface, NetworkSegment, NewNetworkSegment};

use crate::common::TestDatabaseManager;

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
async fn only_one_primary_interface_per_machine() {
    setup();

    let pool = TestDatabaseManager::new()
        .await
        .expect("Unable to create database pool")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create txn");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: None,
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        prefix_ipv6: None,
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
        .persist(&mut txn)
        .await
        .expect("Unable to create network segment");


    txn.commit().await.unwrap();

    let new_machine = Machine::create(&mut txn2)
        .await
        .expect("Unable to create machine");


    let machine_interface = MachineInterface::create(
        &mut txn2,
        &new_machine,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        &AddressSelectionStrategy::Automatic(AbsentSubnetStrategy::Fail),
        &AddressSelectionStrategy::Empty,
    )
        .await
        .expect("Unable to create machine interface");

    txn2.commit().await.unwrap();

    let machine_interface2 = MachineInterface::create(
        &mut txn3,
        &new_machine,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        &AddressSelectionStrategy::Automatic(AbsentSubnetStrategy::Fail),
        &AddressSelectionStrategy::Empty,
    )
        .await;

    txn3.commit().await.unwrap();

    assert!(matches!(
        machine_interface2,
        Err(CarbideError::OnePrimaryInterface())
    ));
}

#[tokio::test]
async fn many_non_primary_interfaces_per_machine() {
    setup();

    let pool = TestDatabaseManager::new()
        .await
        .expect("Unable to create database pool")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create txn");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: None,
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        prefix_ipv6: None,
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
        .persist(&mut txn)
        .await
        .expect("Unable to create network segment");


    txn.commit().await.unwrap();

    let new_machine = Machine::create(&mut txn2)
        .await
        .expect("Unable to create machine");


    let machine_interface = MachineInterface::create(
        &mut txn2,
        &new_machine,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        &AddressSelectionStrategy::Automatic(AbsentSubnetStrategy::Fail),
        &AddressSelectionStrategy::Empty,
    )
        .await
        .expect("Unable to create machine interface");

    txn2.commit().await.unwrap();

    let machine_interface2 = MachineInterface::create(
        &mut txn3,
        &new_machine,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        false,
        &AddressSelectionStrategy::Automatic(AbsentSubnetStrategy::Fail),
        &AddressSelectionStrategy::Empty,
    )
        .await;

    txn3.commit().await.unwrap();

    assert!(matches!(
        machine_interface2,
        MachineInterface,
    ));
}
