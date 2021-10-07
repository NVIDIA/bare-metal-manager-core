mod common;

use carbide::db::Machine;
use carbide::db::MachineState;

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
async fn test_new_machine_state() {
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

    let machine = Machine::create(&txn, String::from("peppersmacker.nvidia.com"))
        .await
        .expect("Unable to create machine");

    assert_eq!(
        machine.current_state(&txn).await.unwrap(),
        MachineState::New
    );

    txn.commit().await.unwrap();
}
