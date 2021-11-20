mod common;

use carbide::db::Machine;

use carbide::db::NewNetworkSegment;

use log::LevelFilter;

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
async fn return_existing_machine_on_rediscover() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain: "test.example.com".to_string(),
        mtu: Some(1500i32),
        subnet_ipv4: Some("10.0.0.0/24".parse().unwrap()),
        subnet_ipv6: None,
        reserve_first_ipv4: Some(3),
        reserve_first_ipv6: Some(0),
        gateway_ipv4: Some("10.0.0.1".parse().unwrap()),
    }
    .persist(&mut txn)
    .await
    .expect("unable to create network");

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = Machine::discover(&mut txn, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to create machine");

    let existing_machine = Machine::discover(&mut txn, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to re-discover machine with same mac address");

    assert_eq!(new_machine.id(), existing_machine.id());
}
