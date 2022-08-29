use sqlx::Postgres;

use carbide::db::auth::SshKeyValidationRequest;
use carbide::CarbideError;
use rpc::forge::v0 as rpc;

mod common;

async fn create_user(txn: &mut sqlx::Transaction<'_, Postgres>) -> Result<(), String> {
    let _: (String,) = sqlx::query_as(
        r#"INSERT INTO ssh_public_keys (username, role, pubkeys)
            VALUES('testuser', 'administrator', '{"testkey"}') 
            returning username"#,
    )
    .fetch_one(txn)
    .await
    .unwrap();

    Ok(())
}

#[tokio::test]
async fn test_auth() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    create_user(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let uauth = SshKeyValidationRequest {
        user: "testuser".to_string(),
        pubkey: "testkey".to_string(),
    };
    let response = uauth.verify_user(&mut txn).await.unwrap();

    assert!(response.is_authenticated);
    assert_eq!(
        rpc::UserRoles::from_i32(response.role).unwrap(),
        rpc::UserRoles::Administrator
    );
}

#[tokio::test]
async fn test_auth_fail() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    create_user(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let uauth = SshKeyValidationRequest {
        user: "testuser".to_string(),
        pubkey: "testkey1".to_string(),
    };
    let response = uauth.verify_user(&mut txn).await.unwrap();

    assert!(!response.is_authenticated);
}

#[tokio::test]
async fn test_auth_fail_no_user() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let uauth = SshKeyValidationRequest {
        user: "testuser".to_string(),
        pubkey: "testkey1".to_string(),
    };
    let response = uauth.verify_user(&mut txn).await;

    assert!(matches!(response, Err(CarbideError::DatabaseError(_))));
}
