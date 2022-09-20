use carbide::db::auth::SshKeyValidationRequest;
use carbide::CarbideError;
use rpc::forge::v0 as rpc;

#[sqlx::test(fixtures("user_ssh_key"))]
async fn test_auth(pool: sqlx::PgPool) -> sqlx::Result<()> {
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

    Ok(())
}

#[sqlx::test(fixtures("user_ssh_key"))]
async fn test_auth_fail(pool: sqlx::PgPool) {
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

#[sqlx::test]
async fn test_auth_fail_no_user(pool: sqlx::PgPool) {
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
