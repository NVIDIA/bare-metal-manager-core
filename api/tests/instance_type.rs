use log::LevelFilter;

use carbide::db::instance_type::{
    DeactivateInstanceType, InstanceType, NewInstanceType, UpdateInstanceType,
};
use carbide::CarbideResult;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test]
async fn test_instance_type_crud(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: CarbideResult<InstanceType> = NewInstanceType {
        short_name: "integration_test".to_string(),
        description: "integration_test_description".to_string(),
        active: true,
    }
    .persist(&mut txn)
    .await;

    let unwrapped = &segment.unwrap();

    let _updated_type = UpdateInstanceType {
        id: unwrapped.id,
        short_name: format!("{0}_updated", unwrapped.short_name).to_string(),
        description: format!("{0}_updated", unwrapped.description).to_string(),
        active: true,
    }
    .update(&mut txn)
    .await;

    let _deleted_type = DeactivateInstanceType { id: unwrapped.id }
        .deactivate(&mut txn)
        .await;

    txn.commit().await.unwrap();
}
