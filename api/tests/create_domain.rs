use log::LevelFilter;

use carbide::{
    db::{Domain, NewDomain},
    CarbideResult,
};

use crate::common::TestDatabaseManager;

mod common;

#[tokio::test]
async fn create_domain() {
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

    let domain: CarbideResult<Domain> = NewDomain {
        name: "nv.metal.net".to_string(),
    }
    .persist(&mut txn)
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(domain.unwrap(), Domain));
}
