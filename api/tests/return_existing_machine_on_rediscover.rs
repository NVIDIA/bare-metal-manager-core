use log::LevelFilter;

use carbide::db::machine_interface::MachineInterface;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn return_existing_machine_on_rediscover(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        "192.0.2.1".parse().unwrap(),
    )
    .await?;

    let existing_machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        "192.0.2.1".parse().unwrap(),
    )
    .await?;

    assert_eq!(new_machine.id(), existing_machine.id());

    Ok(())
}
