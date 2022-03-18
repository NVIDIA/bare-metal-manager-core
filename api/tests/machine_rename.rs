mod common;

use std::str::FromStr;
use carbide::db::{AbsentSubnetStrategy, AddressSelectionStrategy, Domain, Machine, MachineInterface, NetworkSegment, NewDomain, NewNetworkSegment};

use log::LevelFilter;

use std::sync::Once;
use ipnetwork::Ipv4Network;
use mac_address::MacAddress;
use carbide::CarbideResult;

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
async fn test_machine_rename() {
    setup();

    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut new_machine = Machine::create(&mut txn)
        .await
        .expect("Unable to create machine");

    let new_domain: CarbideResult<Domain> = NewDomain {
        name: "foobar.com".to_string(),
    }
        .persist(&mut txn)
        .await;

    txn.commit().await.unwrap();

    let domain = Domain::find_by_name(&mut txn2, "foobar.com".to_string())
        .await
        .expect("Could not find domain in DB");


    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: Some(domain).unwrap().map(|d| d.id().to_owned()),
        mtu: Some(1500i32),
        prefix_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").expect("can't parse network")),
        prefix_ipv6: None,
        gateway_ipv4: Some("192.168.0.1/32".parse().unwrap()),
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(3),
    }
        .persist(&mut txn2)
        .await
        .expect("Unable to create network segment");

    let mut machine_interface = MachineInterface::create(
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


    //let original_modified = machine.updated();

    //txn.commit().await.unwrap();


     machine_interface.update_hostname(&mut txn2, "peppersmacker2")
        .await
        .expect("Could not update hostname");

    txn2.commit().await.unwrap();

//    assert_ne!(original_modified, machine.updated());
    assert_eq!(machine_interface.hostname(), "peppersmacker2");
}
