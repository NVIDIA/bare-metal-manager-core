use carbide::db::domain::{Domain, NewDomain};
use carbide::{CarbideError, CarbideResult};

use crate::common::TestDatabaseManager;

mod common;

#[tokio::test]
async fn create_valid_domain() {
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nv.metal.net".to_string();

    let domain = NewDomain { name: test_name }.persist(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(domain, Ok(_)));
}

#[tokio::test]
async fn create_invalid_domain_case() {
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "DwRt".to_string();

    let domain: CarbideResult<Domain> = NewDomain { name: test_name }.persist(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(domain, Err(CarbideError::InvalidDomainName(_))));
}

#[tokio::test]
async fn create_invalid_domain_regex() {
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let domain: CarbideResult<Domain> = NewDomain {
        name: "ihaveaspace.com ".to_string(),
    }
    .persist(&mut txn)
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(domain, Err(CarbideError::InvalidDomainName(_))));
}
