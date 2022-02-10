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

    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut machine = Machine::create(&mut txn, String::from("peppersmacker.nvidia.com"))
        .await
        .expect("Unable to create machine");

    let original_modified = machine.updated();

    txn.commit().await.unwrap();

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    machine
        .update_fqdn(&mut txn2, "peppersmacker2.nvidia.com")
        .await
        .expect("Could not update FQDN");

    assert_ne!(original_modified, machine.updated());
    assert_eq!(machine.fqdn(), "peppersmacker2.nvidia.com");
}
