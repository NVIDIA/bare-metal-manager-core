use log::LevelFilter;
use sqlx::{Postgres,  Transaction};
use rpc::v0 as rpc;

use carbide::{
    db::{Tag, TagCreate, TagDelete, TagsList},
    CarbideResult,
};
use crate::common::TestDatabaseManager;

mod common;

async fn test_create(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagResult> {
    let request = TagCreate {
        tag: Some(Tag {
            slug: "testtag".to_string(),
            name: Some("Test Tag".to_string())
        })
    };

    request.create(txn).await
}

async fn test_delete(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagResult> {
    let request = TagDelete {
        tag: Some(Tag {
            slug: "testtag".to_string(),
            name: None
        })
    };
    request.delete(txn).await
}

async fn test_list(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagsListResult> {
    TagsList::find_all(txn).await
}

#[tokio::test]
async fn tag_create_and_list() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    {
        let mut txn = pool.begin()
                            .await
                            .expect("Unable to create transaction on database pool");
        {
            let ret_val = test_create(&mut txn).await;
            assert!(ret_val.unwrap().result);
        }
        txn.commit().await.unwrap();
    }

    {
        let mut txn = pool.begin()
                        .await
                        .expect("Unable to create transaction on database pool");
        let ret_val = test_list(&mut txn).await;
        assert!(ret_val.is_ok());

        let ret_val = ret_val.unwrap();
        assert_eq!(ret_val.tags[0].slug, "testtag".to_string());
        assert_eq!(ret_val.tags[0].name.to_owned().unwrap(), "Test Tag".to_string());

    }
}

#[tokio::test]
async fn tag_deletion() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    // Create tag first to delete.
    {
        let mut txn = pool.begin()
                            .await
                            .expect("Unable to create transaction on database pool");
        {
            let ret_val = test_create(&mut txn).await;
            assert!(ret_val.unwrap().result);
        }
        txn.commit().await.unwrap();
    }

    // Delete it now.
    {
        let mut txn = pool.begin()
                            .await
                            .expect("Unable to create transaction on database pool");
        {
            let ret_val = test_delete(&mut txn).await;
            assert!(ret_val.unwrap().result);
        }
        txn.commit().await.unwrap();
    }

}
