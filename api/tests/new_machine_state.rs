use log::LevelFilter;

use carbide::db::machine::Machine;
use carbide::db::machine_state::MachineState;

const FIXTURE_CREATED_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_new_machine_state(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(&mut txn, FIXTURE_CREATED_MACHINE_ID).await?;

    assert!(matches!(
        machine,
        Some(x) if x.current_state(&mut txn).await? == MachineState::Init));

    txn.commit().await?;

    Ok(())
}
