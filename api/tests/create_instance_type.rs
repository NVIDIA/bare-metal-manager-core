mod common;

use std::str::FromStr;

use carbide::{
    db::{InstanceType, NewInstanceType},
    CarbideResult,
};

use log::LevelFilter;

#[tokio::test]
async fn test_create_segment() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: CarbideResult<InstanceType> = NewInstanceType {
        short_name: "integration_test".to_string(),
        description: "integration_test_description".to_string(),
        active: true
    }
        .persist(&mut txn)
        .await;

    txn.commit().await;

    assert!(matches!(segment.unwrap(), InstanceType));
}
