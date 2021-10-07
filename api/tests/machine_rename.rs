mod common;

use carbide::db::Machine;

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
async fn test_machine_rename() {
    setup();

    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create a database pool");
    let mut dbc = db
        .pool
        .get()
        .await
        .expect("Could not get a DB pool connection");
    let txn = dbc
        .transaction()
        .await
        .expect("Could not create new transaction");

    let mut machine = Machine::create(&txn, String::from("peppersmacker.nvidia.com"))
        .await
        .expect("Unable to create machine");

    let original_modified = machine.modified();

    txn.commit().await.unwrap();

    let txn2 = dbc
        .transaction()
        .await
        .expect("Could not create new (second) transaction");

    machine
        .update_fqdn(&txn2, "peppersmacker2.nvidia.com")
        .await
        .expect("Could not update FQDN");

    txn2.commit().await.unwrap();

    assert_ne!(original_modified, machine.modified());
    //assert!(original_modified < machine.modified());
    assert_eq!(machine.fqdn(), "peppersmacker2.nvidia.com");
}
