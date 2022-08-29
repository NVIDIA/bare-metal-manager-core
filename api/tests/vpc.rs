use log::LevelFilter;

use carbide::db::vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc};
use carbide::db::UuidKeyedObjectFilter;
use carbide::CarbideResult;

use crate::common::TestDatabaseManager;

mod common;

#[tokio::test]
async fn create_vpc() {
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

    let _vpc = NewVpc {
        name: "Metal".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await;

    let vpc = NewVpc {
        name: "Metal no Org".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await;

    let unwrapped = &vpc.unwrap();
    assert!(unwrapped.deleted.is_none());

    txn.commit().await.unwrap();

    // create another transaction to ensure the updated field is updated properly
    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let _updated_vpc = UpdateVpc {
        id: unwrapped.id,
        name: unwrapped.name.to_string(),
        organization: String::new(),
    }
    .update(&mut txn)
    .await
    .unwrap();

    let vpc = DeleteVpc { id: unwrapped.id }.delete(&mut txn).await;

    txn.commit().await.unwrap();

    let vpc = &vpc.unwrap();

    assert!(vpc.deleted.is_some());
}

#[tokio::test]
async fn find_vpc_by_id() {
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc: CarbideResult<Vpc> = NewVpc {
        name: "Metal no Org".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await;

    txn.commit().await.unwrap();

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let unwrapped = &vpc.unwrap();

    let some_vpc = Vpc::find(&mut txn2, UuidKeyedObjectFilter::One(unwrapped.id))
        .await
        .unwrap();

    assert_eq!(1, some_vpc.len());
    let first = some_vpc.first().unwrap();
    assert_eq!(first, unwrapped);
}
