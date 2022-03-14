use log::LevelFilter;
use uuid::Uuid;

use carbide::{
    db::{NewProject, Project},
    CarbideResult,
};

use crate::common::TestDatabaseManager;

mod common;

#[tokio::test]
async fn create_project() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let project: CarbideResult<Project> = NewProject {
        name: "Metal".to_string(),
        organization: Some(Uuid::new_v4()),
    }
    .persist(&mut txn)
    .await;

    assert!(matches!(project.unwrap(), Project));

    let project: CarbideResult<Project> = NewProject {
        name: "Metal no Org".to_string(),
        organization: None,
    }
    .persist(&mut txn)
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(project.unwrap(), Project));
}
