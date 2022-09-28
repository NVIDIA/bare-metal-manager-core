use carbide::db::network_segment::NetworkSegment;
use log::LevelFilter;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Warn)
        .init();
}

const SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_update_network_segment_name(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let mut segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);

    segments[0].name = "foobar".to_string();
    segments[0].update(&mut txn).await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    let segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].name, "foobar".to_string());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_update_network_segment_vpc(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let updated_vpc_id = uuid::uuid!("d5001c6f-c55a-4fa8-bbbe-f989977469b5");

    let mut segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);

    segments[0].vpc_id = Option::from(updated_vpc_id);
    segments[0].update(&mut txn).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].vpc_id, Option::from(updated_vpc_id));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_update_network_segment_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let updated_domain_id = uuid::uuid!("48db2509-3b88-4db6-b77b-aa389d370e02");

    let mut segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);

    segments[0].subdomain_id = Option::from(updated_domain_id);
    segments[0].update(&mut txn).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].subdomain_id, Option::from(updated_domain_id));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_update_network_segment_all(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let updated_domain_id = uuid::uuid!("48db2509-3b88-4db6-b77b-aa389d370e02");
    let updated_vpc_id = uuid::uuid!("d5001c6f-c55a-4fa8-bbbe-f989977469b5");

    let mut segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);

    segments[0].name = "sillyasaurus".to_string();
    segments[0].subdomain_id = Option::from(updated_domain_id);
    segments[0].vpc_id = Option::from(updated_vpc_id);
    segments[0].update(&mut txn).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let segments = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(SEGMENT_ID),
    )
    .await?;

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].name, "sillyasaurus".to_string());
    assert_eq!(segments[0].subdomain_id, Option::from(updated_domain_id));
    assert_eq!(segments[0].vpc_id, Option::from(updated_vpc_id));

    Ok(())
}
