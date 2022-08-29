use std::str::FromStr;
use std::sync::Once;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::domain::{Domain, NewDomain};
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;

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

    let new_domain: Domain = NewDomain {
        name: "foobar.com".to_string(),
    }
    .persist(&mut txn)
    .await
    .expect("Unable top create domain");

    txn.commit().await.unwrap();

    let domain = Domain::find_by_name(&mut txn2, new_domain.name().to_owned())
        .await
        .expect("Could not find domain in DB");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn2)
    .await
    .expect("Unable to create VPC");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: Some(domain).unwrap().map(|d| d.id().to_owned()),
        mtu: Some(1500i32),
        vpc_id: Some(vpc.id),

        prefixes: vec![
            NewNetworkPrefix {
                prefix: "2001:db8:f::/64".parse().unwrap(),
                gateway: None,
                num_reserved: 100,
            },
            NewNetworkPrefix {
                prefix: "192.0.2.0/24".parse().unwrap(),
                gateway: "192.0.2.1".parse().ok(),
                num_reserved: 2,
            },
        ],
    }
    .persist(&mut txn2)
    .await
    .expect("Unable to create network segment");

    let mut machine_interface = MachineInterface::create(
        &mut txn2,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    machine_interface
        .update_hostname(&mut txn2, "peppersmacker400")
        .await
        .expect("Could not update hostname");

    txn2.commit().await.unwrap();

    assert_eq!(machine_interface.hostname(), "peppersmacker400");
}
