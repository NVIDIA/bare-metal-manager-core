mod common;

use std::fmt::format;

use carbide::{
    db::{InstanceType, NewInstanceType},
    CarbideResult,
};

use log::LevelFilter;
use carbide::db::{DeactivateInstanceType, UpdateInstanceType};

#[tokio::test]
async fn test_instance_type_crud () {
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

    let unwrapped = &segment.unwrap();
    assert!(matches!(unwrapped, InstanceType));

    let updatedType = UpdateInstanceType {
        id: unwrapped.id,
        short_name: format!("{0}_updated", unwrapped.short_name).to_string(),
        description: format!("{0}_updated", unwrapped.description).to_string(),
        active: true
    }
        .update(&mut txn)
        .await;

    assert!(matches!(updatedType.unwrap(), InstanceType));

    let deletedType = DeactivateInstanceType {
        id: unwrapped.id,
    }
        .deactivate(&mut txn)
        .await;

    assert!(matches!(deletedType.unwrap(), InstanceType));
}
