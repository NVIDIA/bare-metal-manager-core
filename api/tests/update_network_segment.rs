use log::LevelFilter;
use sqlx::prelude::*;
use std::sync::Once;

use carbide::db::network_segment::NetworkSegment;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("network_segment_complete"))]
async fn test_update_network_segment_name(pool: sqlx::PgPool) -> sqlx::Result<()> {
    setup();
    let mut connection = pool.acquire().await?;
    let mut txn = connection.begin().await?;

    let id = uuid::uuid!("c11169d9-ad20-4705-8707-4e62a3ad4731");

    let mut segments = NetworkSegment::find(&mut txn, carbide::db::UuidKeyedObjectFilter::One(id))
        .await
        .unwrap();

    assert_eq!(segments.len(), 1);

    segments[0].name = "foobar".to_string();

    let update_result = segments[0].update(&mut txn).await;

    assert!(matches!(update_result, Ok(_)));
    match update_result {
        Ok(s) => println!("segment: {s:?}"),
        Err(e) => println!("error updating: {e:?}"),
    }
    txn.commit().await.unwrap();

    Ok(())
}

#[sqlx::test(fixtures("network_segment_complete"))]
async fn test_update_network_segment_vpc(pool: sqlx::PgPool) -> sqlx::Result<()> {
    setup();
    let mut connection = pool.acquire().await?;
    let mut txn = connection.begin().await?;

    let id = uuid::uuid!("c11169d9-ad20-4705-8707-4e62a3ad4731");
    let _original_vpc = uuid::uuid!("885906cf-cfd0-477f-91e1-38b9a65c8c28");

    let updated_vpc_id = uuid::uuid!("6ff68e7a-c54e-42a0-8ae2-8e63180c97af");

    let mut segments = NetworkSegment::find(&mut txn, carbide::db::UuidKeyedObjectFilter::One(id))
        .await
        .unwrap();

    assert_eq!(segments.len(), 1);

    segments[0].vpc_id = Option::from(updated_vpc_id);

    let update_result = segments[0].update(&mut txn).await;

    assert!(matches!(update_result, Ok(_)));
    match update_result {
        Ok(s) => println!("segment: {s:?}"),
        Err(e) => println!("error updating: {e:?}"),
    }
    txn.commit().await.unwrap();

    Ok(())
}
#[sqlx::test(fixtures("network_segment_complete"))]
async fn test_update_network_segment_domain(pool: sqlx::PgPool) -> sqlx::Result<()> {
    setup();
    let mut connection = pool.acquire().await?;
    let mut txn = connection.begin().await?;

    let id = uuid::uuid!("c11169d9-ad20-4705-8707-4e62a3ad4731");
    let _original_domain = uuid::uuid!("7687f939-727c-431e-a474-e15d70a9a728");
    let updated_domain_id = uuid::uuid!("04d015b9-56e9-4e1b-84f0-5574893cd576");

    let mut segments = NetworkSegment::find(&mut txn, carbide::db::UuidKeyedObjectFilter::One(id))
        .await
        .unwrap();

    assert_eq!(segments.len(), 1);

    segments[0].subdomain_id = Option::from(updated_domain_id);

    let update_result = segments[0].update(&mut txn).await;

    assert!(matches!(update_result, Ok(_)));
    match update_result {
        Ok(s) => println!("segment: {s:?}"),
        Err(e) => println!("error updating: {e:?}"),
    }
    txn.commit().await.unwrap();

    Ok(())
}

#[sqlx::test(fixtures("network_segment_complete"))]
async fn test_update_network_segment_all(pool: sqlx::PgPool) -> sqlx::Result<()> {
    setup();
    let mut connection = pool.acquire().await?;
    let mut txn = connection.begin().await?;

    let id = uuid::uuid!("c11169d9-ad20-4705-8707-4e62a3ad4731");
    let _original_domain = uuid::uuid!("7687f939-727c-431e-a474-e15d70a9a728");
    let updated_domain_id = uuid::uuid!("04d015b9-56e9-4e1b-84f0-5574893cd576");
    let _original_vpc = uuid::uuid!("885906cf-cfd0-477f-91e1-38b9a65c8c28");
    let updated_vpc_id = uuid::uuid!("6ff68e7a-c54e-42a0-8ae2-8e63180c97af");

    let mut segments = NetworkSegment::find(&mut txn, carbide::db::UuidKeyedObjectFilter::One(id))
        .await
        .unwrap();

    assert_eq!(segments.len(), 1);

    segments[0].name = "silyasaurus".to_string();
    segments[0].subdomain_id = Option::from(updated_domain_id);
    segments[0].vpc_id = Option::from(updated_vpc_id);

    let update_result = segments[0].update(&mut txn).await;

    assert!(matches!(update_result, Ok(_)));
    match update_result {
        Ok(s) => println!("segment: {s:?}"),
        Err(e) => println!("error updating: {e:?}"),
    }
    txn.commit().await.unwrap();

    Ok(())
}
