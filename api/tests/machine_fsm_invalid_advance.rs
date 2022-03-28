use std::sync::Once;

use log::LevelFilter;

use carbide::db::Machine;
use carbide::CarbideError;

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
async fn test_fsm_invalid_advance() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine = Machine::create(&mut txn)
        .await
        .expect("Unable to create machine");

    // Can't commission from new
    assert!(matches!(
        machine.commission(&mut txn).await.unwrap_err(),
        CarbideError::MachineStateTransitionViolation { .. }
    ));

    txn.commit().await.unwrap();
}
