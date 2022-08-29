use std::sync::Once;

use log::LevelFilter;
use carbide::db::machine::Machine;

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
async fn test_find_all_machines_when_there_arent_any() {
    setup();

    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create a database pool");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Could create a transaction on database pool");

    let machines = Machine::find(&mut txn, carbide::db::UuidKeyedObjectFilter::All)
        .await
        .unwrap();

    assert!(machines.is_empty());
}
