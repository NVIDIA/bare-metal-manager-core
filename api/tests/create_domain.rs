use carbide::db::domain::{Domain, NewDomain};
use carbide::{CarbideError, CarbideResult};

use uuid::Uuid;

#[sqlx::test]
async fn create_delete_valid_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nv.metal.net".to_string();

    let domain = NewDomain { name: test_name }.persist(&mut txn).await;

    assert!(matches!(domain, Ok(_)));

    let delete_result = domain.unwrap().delete(&mut txn).await;

    assert!(matches!(delete_result, Ok(_)));

    let domains = Domain::find(&mut txn, carbide::db::UuidKeyedObjectFilter::All)
        .await
        .unwrap();

    txn.commit().await.unwrap();

    assert!(domains.is_empty());
}

#[sqlx::test]
async fn create_invalid_domain_case(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "DwRt".to_string();

    let domain: CarbideResult<Domain> = NewDomain { name: test_name }.persist(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(domain, Err(CarbideError::InvalidDomainName(_))));
}

#[sqlx::test]
async fn create_invalid_domain_regex(pool: sqlx::PgPool) {
    let mut txn = pool
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

#[sqlx::test]
async fn find_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nvfind.metal.net".to_string();

    let domain = NewDomain { name: test_name }.persist(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(domain.is_ok());

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let domains = Domain::find(&mut txn, carbide::db::UuidKeyedObjectFilter::All)
        .await
        .unwrap();

    let &uuid = domains[0].id();

    // find ALL should give us the one we created
    assert_eq!(domains.len(), 1);

    let domains = Domain::find(&mut txn, carbide::db::UuidKeyedObjectFilter::One(uuid))
        .await
        .unwrap();

    // find one, using the id returned in the created domain object
    assert_eq!(domains.len(), 1);

    let bad_uuid = Uuid::new_v4();

    let domains = Domain::find(&mut txn, carbide::db::UuidKeyedObjectFilter::One(bad_uuid))
        .await
        .unwrap();

    txn.commit().await.unwrap();

    // Try a find One on a bogus/non-existent UUID
    assert!(domains.is_empty());
}

#[sqlx::test]
async fn update_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nv.metal.net".to_string();

    let domain = NewDomain { name: test_name }.persist(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(domain.is_ok());

    let updated_name = "updated.metal.net".to_string();

    let mut updated_domain = domain.unwrap();

    updated_domain.name = updated_name;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let update_result = updated_domain.update(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(update_result, Ok(_)));
}
