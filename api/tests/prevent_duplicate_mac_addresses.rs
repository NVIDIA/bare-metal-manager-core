use log::LevelFilter;

use carbide::db::{
    address_selection_strategy::AddressSelectionStrategy, machine::Machine,
    machine_interface::MachineInterface, network_segment::NetworkSegment,
};
use carbide::CarbideError;

const FIXTURE_NETWORK_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn prevent_duplicate_mac_addresses(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
    )
    .await?
    .pop()
    .unwrap();

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let _new_machine = Machine::create(&mut txn, new_interface).await?;

    let duplicate_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await?;

    assert!(matches!(
        duplicate_interface,
        Err(CarbideError::NetworkSegmentDuplicateMacAddress(_))
    ));

    Ok(())
}
