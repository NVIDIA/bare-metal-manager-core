use log::LevelFilter;

use carbide::db::vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc};
use carbide::db::UuidKeyedObjectFilter;

const FIXTURE_CREATED_VPC_ID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test]
async fn create_vpc(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    NewVpc {
        name: "Forge".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await?;

    let vpc = NewVpc {
        name: "Forge no Org".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await?;

    assert!(matches!(vpc.deleted, None));

    txn.commit().await?;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let _updated_vpc = UpdateVpc {
        id: vpc.id,
        name: vpc.name.to_string(),
        organization: String::new(),
    }
    .update(&mut txn)
    .await?;

    let vpc = DeleteVpc { id: vpc.id }.delete(&mut txn).await?;

    assert!(matches!(vpc.deleted, Some(_)));

    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(vpc.id)).await?;

    txn.commit().await?;

    assert!(vpcs.is_empty());

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn find_vpc_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let some_vpc = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(FIXTURE_CREATED_VPC_ID)).await?;

    assert_eq!(1, some_vpc.len());

    let first = some_vpc.first();

    assert!(matches!(first, Some(x) if x.id == FIXTURE_CREATED_VPC_ID));

    Ok(())
}
