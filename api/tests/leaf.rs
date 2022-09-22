use log::LevelFilter;
use std::net::IpAddr;
use std::str::FromStr;

use carbide::db::vpc_resource_leaf::{NewVpcResourceLeaf, VpcResourceLeaf};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[ignore]
#[sqlx::test]
async fn new_leafs_are_in_new_state(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new().persist(&mut txn).await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    let vpc_resource_leaf = VpcResourceLeaf::find(&mut txn, leaf.id().to_owned()).await?;
    let current_state = vpc_resource_leaf.current_state(&mut txn).await?;

    log::info!("Current state - {}", current_state);

    //assert!(matches!(current_state, VpcResourceState::New));

    Ok(())
}

#[sqlx::test]
async fn find_leaf_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new().persist(&mut txn).await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    VpcResourceLeaf::find(&mut txn, leaf.id().to_owned()).await?;

    Ok(())
}

#[sqlx::test]
async fn find_leaf_and_update_loopback_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let leaf = NewVpcResourceLeaf::new().persist(&mut txn).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let address = IpAddr::from_str("1.2.3.4")?;

    let mut new_leaf = VpcResourceLeaf::find(&mut txn, leaf.id().to_owned()).await?;

    new_leaf
        .update_loopback_ip_address(&mut txn, address)
        .await?;

    assert_eq!(
        new_leaf.loopback_ip_address().map(|ip| ip.to_string()),
        Some("1.2.3.4".to_string())
    );

    Ok(())
}
