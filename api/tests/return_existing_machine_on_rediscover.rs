mod common;

use carbide::db::{Machine, Domain, NewNetworkSegment, NewDomain};

use log::LevelFilter;

use std::sync::Once;
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
async fn return_existing_machine_on_rediscover() {
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

    let domain = Domain::find_by_name(&mut txn2, my_domain.to_string()).await.expect("Could not find domain in DB");

    NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id:  Some(domain).unwrap().map(|d|d.id().to_owned()),
        mtu: Some(1500i32),
        prefix_ipv4: Some("10.0.0.0/24".parse().unwrap()),
        prefix_ipv6: None,
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(0),
        gateway_ipv4: Some("10.0.0.1".parse().unwrap()),
    }
    .persist(&mut txn2)
    .await
    .expect("unable to create network");

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = Machine::discover(&mut txn2, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to create machine");

    let existing_machine = Machine::discover(&mut txn2, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to re-discover machine with same mac address");

    assert_eq!(new_machine.id(), existing_machine.id());
}
