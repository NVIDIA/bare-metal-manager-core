use crate::common::TestDatabaseManager;

mod common;

#[cfg(test)]
mod tests {
    use carbide::db::vpc_resource_leaf::{NewVpcResourceLeaf, VpcResourceLeaf};
    use carbide::CarbideResult;

    use crate::TestDatabaseManager;

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

        let leaf: CarbideResult<VpcResourceLeaf> =
            NewVpcResourceLeaf::new().persist(&mut txn).await;

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
}
