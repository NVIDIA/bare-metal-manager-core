use carbide::db::machine::Machine;
use log::LevelFilter;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test]
async fn test_find_all_machines_when_there_arent_any(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Could create a transaction on database pool");

    let machines = Machine::find(&mut txn, carbide::db::UuidKeyedObjectFilter::All)
        .await
        .unwrap();

    assert!(machines.is_empty());
}
