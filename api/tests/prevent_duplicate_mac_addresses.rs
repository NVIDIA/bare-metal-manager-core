use std::str::FromStr;
use std::sync::Once;

use ipnetwork::Ipv4Network;
use log::LevelFilter;

use carbide::{CarbideError, CarbideResult};
use carbide::db::{AbsentSubnetStrategy, NewDomain};
use carbide::db::AddressSelectionStrategy;
use carbide::db::Domain;
use carbide::db::Machine;
use carbide::db::MachineInterface;
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
async fn prevent_duplicate_mac_addresses() {
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

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = Machine::discover(&mut txn2, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to create machine");

    let duplicate_interface = MachineInterface::create(
        &mut txn2,
        &new_machine,
        &new_segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        &AddressSelectionStrategy::Automatic(AbsentSubnetStrategy::Fail),
        &AddressSelectionStrategy::Empty,
    )
        .await;

    assert!(matches!(
        duplicate_interface,
        Err(CarbideError::NetworkSegmentDuplicateMacAddress(_))
    ));
}
