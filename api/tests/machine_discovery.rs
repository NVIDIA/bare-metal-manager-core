mod common;

use carbide::db::Machine;
use carbide::db::NetworkSegment;
use ip_network::Ipv4Network;
use std::net::Ipv4Addr;
use std::str::FromStr;

use log::LevelFilter;

use eui48::MacAddress;

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

    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create a database pool");
    let mut dbc = db
        .pool
        .get()
        .await
        .expect("Could not get a DB pool connection");
    let mut txn = dbc
        .transaction()
        .await
        .expect("Could not create new transaction");

    let _ = NetworkSegment::create(
        &txn,
        "test-network",
        "test.example.com",
        &1500,
        Some(Ipv4Network::from_str_truncate("10.0.0.0/24").unwrap()),
        None,
        &3,
        &0,
    )
    .await
    .expect("unable to create network");

    let machine = Machine::discover(
        &mut txn,
        MacAddress::parse_str("ff:ff:ff:ff:ff:ff").unwrap(),
        "10.0.0.1".parse().unwrap(),
    )
    .await
    .expect("Unable to create machine");

    txn.commit().await.unwrap();

    assert_eq!(
        machine
            .interfaces()
            .iter()
            .filter_map(|interface| interface.address_ipv4())
            .collect::<Vec<&Ipv4Addr>>(),
        vec![&Ipv4Addr::from_str("10.0.0.1").unwrap()]
    );
}
