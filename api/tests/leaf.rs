use std::net::IpAddr;
use std::str::FromStr;

use carbide::db::vpc_resource_leaf::{NewVpcResourceLeaf, VpcResourceLeaf};
use carbide::CarbideResult;

use crate::common::TestDatabaseManager;

mod common;

#[tokio::test]
async fn new_leafs_are_in_new_state() {
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let leaf = NewVpcResourceLeaf::new()
        .persist(&mut txn)
        .await
        .expect("Could not create new leaf");

    txn.commit().await.expect("Could not create new leaf");

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc_resource_leaf = VpcResourceLeaf::find(&mut txn2, leaf.id().to_owned())
        .await
        .expect("Could not find newly created leaf");

    let current_state = vpc_resource_leaf
        .current_state(&mut txn2)
        .await
        .expect("Could not get current state of leaf");

    log::info!("Current state - {}", current_state);

    // assert!(matches!(current_state, VpcResourceState::New));
}

#[tokio::test]
async fn find_leaf_by_id() {
    if let Err(e) = pretty_env_logger::try_init() {
        eprintln!("An error occured {}", e)
    }
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let leaf: CarbideResult<VpcResourceLeaf> = NewVpcResourceLeaf::new().persist(&mut txn).await;

    txn.commit()
        .await
        .expect("Unable to create new VpcResourceLeaf");

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let _unwrapped = &leaf.expect("Unable to unmarshal leaf from Result");

    let some_leaf = VpcResourceLeaf::find(&mut txn2, _unwrapped.id().to_owned()).await;

    assert!(matches!(some_leaf, _unwrapped));
}

#[tokio::test]
async fn find_leaf_and_update_loopback_ip() {
    if let Err(e) = pretty_env_logger::try_init() {
        eprintln!("An error occurred {}", e)
    }
    let db = TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let leaf: CarbideResult<VpcResourceLeaf> = NewVpcResourceLeaf::new().persist(&mut txn).await;

    txn.commit()
        .await
        .expect("Unable to create new VpcResourceLeaf");

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let _unwrapped = &leaf.expect("Unable to unmarshal leaf from Result");

    let address = IpAddr::from_str("1.2.3.4").unwrap();
    let mut new_leaf = VpcResourceLeaf::find(&mut txn2, _unwrapped.id().to_owned())
        .await
        .unwrap();
    new_leaf
        .update_loopback_ip_address(&mut txn2, address)
        .await
        .unwrap();

    let address_string = new_leaf.loopback_ip_address().unwrap().to_string();
    assert_eq!(address_string, "1.2.3.4".to_string());
}
