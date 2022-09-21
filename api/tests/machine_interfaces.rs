use carbide::db::network_segment::NetworkSegment;
use log::LevelFilter;
use mac_address::MacAddress;
use sqlx::{Connection, Postgres};
use std::str::FromStr;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::machine::Machine;
use carbide::db::machine_interface::MachineInterface;
use carbide::CarbideError;

const FIXTURE_NETWORK_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

async fn get_fixture_network_segment(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<NetworkSegment, Box<dyn std::error::Error>> {
    carbide::db::network_segment::NetworkSegment::find(
        txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
    )
    .await?
    .pop()
    .ok_or_else(|| {
        format!(
            "Can't find the Network Segment by well-known-uuid: {}",
            FIXTURE_NETWORK_SEGMENT_ID
        )
        .into()
    })
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn only_one_primary_interface_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    let new_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let new_machine = Machine::create(&mut txn, new_interface)
        .await
        .expect("Unable to create machine");

    txn.commit().await.unwrap();

    let mut txn = pool.begin().await?;

    let mut should_failed_machine_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let output = should_failed_machine_interface
        .associate_interface_with_machine(&mut txn, new_machine.id())
        .await;

    txn.commit().await.unwrap();

    assert!(matches!(output, Err(CarbideError::OnePrimaryInterface)));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn many_non_primary_interfaces_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    txn.commit().await.unwrap();
    let mut txn = pool.begin().await?;

    let should_be_ok_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        false,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(should_be_ok_interface.is_ok());

    Ok(())
}
