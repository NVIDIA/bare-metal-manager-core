use std::sync::Once;
use log::LevelFilter;

use carbide::{
    db::{Domain, NewDomain},
    CarbideResult, CarbideError
};

use crate::common::TestDatabaseManager;

mod common;

fn setup() {
    Once::new().call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

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

    let domain: CarbideResult<Domain> = NewDomain {
        name: "nv.metal.net".to_string(),
    }
    .persist(&mut txn)
    .await;

    txn.commit().await.unwrap();

    assert!(matches!(domain.unwrap(), Domain));
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

    let domain: CarbideResult<Domain> = NewDomain {
        name: "DwRt".to_string(),
    }
        .persist(&mut txn)
        .await;

    txn.commit().await.unwrap();
    assert!(matches!(
        domain,
        Err(CarbideError::InvalidDomainName(domain))
    ));
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
    assert!(matches!(
        domain,
        Err(CarbideError::InvalidDomainName(domain))
    ));
}