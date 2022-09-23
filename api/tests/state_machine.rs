use carbide::db::{machine::Machine, machine_state::MachineState};
use carbide::CarbideError;
use log::LevelFilter;

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
async fn state_machine_advance_from_db_events(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(&mut txn, FIXTURE_CREATED_MACHINE_ID)
        .await?
        .unwrap();

    // Insert some valid state changes into the db
    machine
        .advance(&mut txn, &rpc::MachineStateMachineInput::Discover)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &rpc::MachineStateMachineInput::Adopt)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &rpc::MachineStateMachineInput::Test)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &rpc::MachineStateMachineInput::Commission)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &rpc::MachineStateMachineInput::Assign)
        .await
        .unwrap();

    let state = machine.current_state(&mut txn).await.unwrap();
    assert!(matches!(state, MachineState::Assigned));

    Ok(())
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_fsm_invalid_advance(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine = Machine::find_one(&mut txn, FIXTURE_CREATED_MACHINE_ID)
        .await?
        .unwrap();

    let state = machine.current_state(&mut txn).await.unwrap();
    assert!(matches!(state, MachineState::Init));

    assert!(matches!(
        machine
            .advance(&mut txn, &rpc::MachineStateMachineInput::Commission)
            .await
            .unwrap_err(),
        CarbideError::InvalidState { .. }
    ));

    Ok(())
}
