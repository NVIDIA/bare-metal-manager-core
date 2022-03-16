use log::LevelFilter;
use uuid::Uuid;

use carbide::db::{DeleteProject, UpdateProject};
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

    let unwrapped = &project.unwrap();
    assert!(matches!(unwrapped, Project));
    assert!(unwrapped.deleted.is_none());

    txn.commit().await.unwrap();

    // create another transaction to ensure the updated field is updated properly
    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let updatedProject = UpdateProject {
        id: unwrapped.id,
        name: unwrapped.name.to_string(),
        organization: Some(Uuid::new_v4()),
    }
    .update(&mut txn)
    .await;

    assert!(matches!(updatedProject.unwrap(), Project));

    let project = DeleteProject { id: unwrapped.id }.delete(&mut txn).await;

    txn.commit().await.unwrap();

    let project = &project.unwrap();

    assert!(matches!(project, Project));
    assert!(project.deleted.is_some());
}
