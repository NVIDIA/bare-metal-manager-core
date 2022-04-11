use log::LevelFilter;
use uuid::Uuid;

use carbide::db::{DeleteVpc, UpdateVpc};
use carbide::{
    db::{NewVpc, Vpc},
    CarbideResult,
};

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

    let vpc: CarbideResult<Vpc> = NewVpc {
        name: "Metal".to_string(),
        organization: Some(Uuid::new_v4()),
    }
    .persist(&mut txn)
    .await;

    assert!(matches!(vpc.unwrap(), _Vpc));

    let vpc: CarbideResult<Vpc> = NewVpc {
        name: "Metal no Org".to_string(),
        organization: None,
    }
    .persist(&mut txn)
    .await;

    let unwrapped = &vpc.unwrap();
    assert!(matches!(unwrapped, _Vpc));
    assert!(unwrapped.deleted.is_none());

    txn.commit().await.unwrap();

    // create another transaction to ensure the updated field is updated properly
    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let updatedVpc = UpdateVpc {
        id: unwrapped.id,
        name: unwrapped.name.to_string(),
        organization: Some(Uuid::new_v4()),
    }
    .update(&mut txn)
    .await;

    assert!(matches!(updatedVpc.unwrap(), _Vpc));

    let vpc = DeleteVpc { id: unwrapped.id }.delete(&mut txn).await;

    txn.commit().await.unwrap();

    let vpc = &vpc.unwrap();

    assert!(matches!(vpc, _Vpc));
    assert!(vpc.deleted.is_some());
}
