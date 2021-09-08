mod common;

use carbide::db::Machine;

use log::LevelFilter;

//#[tokio::test]
//async fn test_machine_rename() {
//
//    let db = common::TestDatabaseManager::new().await.unwrap();
//    let pool = db.pool.clone();
//
//    let mut machine =
//        carbide::models::Machine::create(&pool, String::from("peppersmacker.nvidia.com"))
//            .await
//            .expect("Unable to create machine");
//
//    let original_modified = machine.modified();
//
//    machine
//        .update_fqdn(&pool, "peppersmacker2.nvidia.com")
//        .await
//        .expect("Could not update FQDN");
//
//    assert!(original_modified < machine.modified());
//    assert_eq!(machine.fqdn(), "peppersmacker2.nvidia.com");
//}

#[tokio::test]
async fn test_find_all_machines_when_there_arent_any() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Debug)
        .init();

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

    //assert!(machine.commission(&txn).await.is_err());
}

//#[tokio::test]
//async fn test_new_machine_state() {
//    pretty_env_logger::formatted_timed_builder()
//        .filter_level(LevelFilter::Debug)
//        .init();
//
//    let db = common::TestDatabaseManager::new().await.unwrap();
//    let mut dbc = db.pool.get().await.unwrap();
//    let txn = dbc.transaction().await.unwrap();
//
//    let machine = carbide::models::Machine::create(
//        &txn,
//        String::from("peppersmacker.nvidia.com"),
//    )
//    .await
//    .expect("Unable to create machine");
//
//
//    assert_eq!(machine.current_state(&txn).await.unwrap(), carbide::models::MachineState::New);
//
//    txn.commit().await.unwrap();
//
//    //assert!(machine.commission(&txn).await.is_err());
//}

//#[tokio::test]
//async fn test_fsm_invalid_advance() {
//    pretty_env_logger::formatted_timed_builder()
//        .filter_level(LevelFilter::Warn)
//        .init();
//
//    let db = common::TestDatabaseManager::new().await.unwrap();
//
//    let machine = carbide::models::Machine::create(
//        db.pool.clone(),
//        String::from("peppersmacker.nvidia.com"),
//    )
//    .await
//    .expect("Unable to create machine");
//
//    // Can't commission from new
//    assert!(matches!(
//        machine.commission().await.unwrap_err(),
//        CarbideError::MachineStateTransitionViolation { .. }
//    ))
//}

//#[tokio::test]
//async fn test_machine_discover() {
//    pretty_env_logger::formatted_timed_builder()
//        .filter_level(LevelFilter::Warn)
//        .init();
//
//    let db = common::TestDatabaseManager::new().await.unwrap();
//
//    let mut connection = db.pool.get().await.unwrap();
//
//    let txn = connection.transaction().await.unwrap();
//
//    let machine = carbide::models::Machine::create(
//        &txn,
//        String::from("peppersmacker.nvidia.com"),
//    )
//    .await
//    .expect("Unable to create machine");
//
//    // Can't commission from new
//    assert!(matches!(
//        machine.commission(&txn).await.unwrap_err(),
//        CarbideError::MachineStateTransitionViolation { .. }
//    ))
//}
