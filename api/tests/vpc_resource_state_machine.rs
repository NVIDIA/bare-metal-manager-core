use log::LevelFilter;

use carbide::db::vpc_resource_leaf::NewVpcResourceLeaf;
use carbide::CarbideError;

mod common;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
async fn vpc_resource_state_machine_advance_from_db_events() {
    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let leaf = NewVpcResourceLeaf::new()
        .persist(&mut txn)
        .await
        .expect("Unable to create VPC Leaf REsource");

    txn.commit().await.unwrap();

    leaf.advance(&mut txn2, &rpc::VpcResourceStateMachineInput::Submit)
        .await
        .unwrap();
    leaf.advance(&mut txn2, &rpc::VpcResourceStateMachineInput::Accept)
        .await
        .unwrap();
    leaf.advance(&mut txn2, &rpc::VpcResourceStateMachineInput::Wait)
        .await
        .unwrap();
    leaf.advance(&mut txn2, &rpc::VpcResourceStateMachineInput::VpcSuccess)
        .await
        .unwrap();

    let state = leaf.current_state(&mut txn2).await.unwrap();
    assert!(matches!(
        state,
        carbide::db::vpc_resource_state::VpcResourceState::Ready
    ));
}

#[tokio::test]
async fn vpc_resource_state_machine_fail_state() {
    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let leaf = NewVpcResourceLeaf::new()
        .persist(&mut txn)
        .await
        .expect("Unable to create VPC Leaf REsource");

    txn.commit().await.unwrap();

    leaf.advance(&mut txn2, &rpc::VpcResourceStateMachineInput::Fail)
        .await
        .unwrap();

    let state = leaf.current_state(&mut txn2).await.unwrap();
    assert!(matches!(
        state,
        carbide::db::vpc_resource_state::VpcResourceState::Broken
    ));
}

#[tokio::test]
async fn vpc_resource_test_fsm_invalid_advance() {
    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc_leaf = NewVpcResourceLeaf::new()
        .persist(&mut txn)
        .await
        .expect("Unable to create vpc_resource_leaf");

    let state = vpc_leaf.current_state(&mut txn).await.unwrap();
    assert!(matches!(
        state,
        carbide::db::vpc_resource_state::VpcResourceState::New
    ));

    assert!(matches!(
        vpc_leaf
            .advance(&mut txn, &rpc::VpcResourceStateMachineInput::VpcSuccess)
            .await
            .unwrap_err(),
        CarbideError::InvalidState { .. }
    ));
}
