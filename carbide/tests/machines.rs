mod common;

use carbide::CarbideError;

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

//#[tokio::test]
//async fn test_new_machine_state() {
//    pretty_env_logger::formatted_timed_builder()
//        .filter_level(LevelFilter::Debug)
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
//    assert_eq!(machine.current_state().await.unwrap(), MachineState::New);
//
//    assert!(machine.commission().await.is_err())
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

#[tokio::test]
async fn test_machine_discover() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Warn)
        .init();

    let db = common::TestDatabaseManager::new().await.unwrap();

    let mut connection = db.pool.get().await.unwrap();

    let txn = connection.transaction().await.unwrap();

    let machine = carbide::models::Machine::create(
        &txn,
        String::from("peppersmacker.nvidia.com"),
    )
    .await
    .expect("Unable to create machine");

    // Can't commission from new
    assert!(matches!(
        machine.commission(&txn).await.unwrap_err(),
        CarbideError::MachineStateTransitionViolation { .. }
    ))
}
