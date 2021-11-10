mod common;

use carbide::db::AddressSelectionStrategy;
use carbide::db::Machine;
use carbide::db::MachineInterface;
use carbide::db::NetworkSegment;
use carbide::CarbideError;

use ip_network::Ipv4Network;

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
async fn prevent_duplicate_mac_addresses() {
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

    let new_segment = NetworkSegment::create(
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

    let test_mac = MacAddress::parse_str("ff:ff:ff:ff:ff:ff").unwrap();

    let new_machine = Machine::discover(&mut txn, test_mac, "10.0.0.1".parse().unwrap())
        .await
        .expect("Unable to create machine");

    let duplicate_interface = MachineInterface::create(
        &txn,
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
