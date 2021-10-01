mod common;

use carbide::db::Machine;
use carbide::db::MachineState;
use carbide::CarbideError;

use log::LevelFilter;

use std::sync::Once;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Warn)
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


    let mut machine =
        Machine::create(&txn, String::from("peppersmacker.nvidia.com"))
            .await
            .expect("Unable to create machine");

    let original_modified = machine.modified();

    txn.commit().await.unwrap();
    
    let txn2 = dbc.transaction().await.expect("Could not create new (second) transaction");

    machine
        .update_fqdn(&txn2, "peppersmacker2.nvidia.com")
        .await
        .expect("Could not update FQDN");


    txn2.commit().await.unwrap();

    assert_ne!(original_modified, machine.modified());
    //assert!(original_modified < machine.modified());
    assert_eq!(machine.fqdn(), "peppersmacker2.nvidia.com");
}

#[tokio::test]
async fn test_find_all_machines_when_there_arent_any() {
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

    let machines = Machine::find(&txn).await.unwrap();

    assert!(machines.is_empty());
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

    let machine = Machine::create(
        &txn,
        String::from("peppersmacker.nvidia.com"),
    )
    .await
    .expect("Unable to create machine");

    assert_eq!(machine.current_state(&txn).await.unwrap(), MachineState::New);

    txn.commit().await.unwrap();

}

#[tokio::test]
async fn test_fsm_invalid_advance() {
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

    let machine = Machine::create(
        &txn,
        String::from("peppersmacker.nvidia.com"),
    )
    .await
    .expect("Unable to create machine");

    // Can't commission from new
    assert!(matches!(
        machine.commission(&txn).await.unwrap_err(),
        CarbideError::MachineStateTransitionViolation { .. }
    ));

    txn.commit().await.unwrap();
}

#[tokio::test]
async fn test_machine_discover() {
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

    let machine = Machine::create(
        &txn,
        String::from("peppersmacker.nvidia.com"),
    )
    .await
    .expect("Unable to create machine");

    // Can't commission from new
    assert!(matches!(
        machine.commission(&txn).await.unwrap_err(),
        CarbideError::MachineStateTransitionViolation { .. }
    ));

    txn.commit().await.unwrap();
}
