pub mod common;

use carbide::{
    db::dpu_machine_update::DpuMachineUpdate, model::machine::machine_id::try_parse_machine_id,
};
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine, host::create_host_machine};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_outdated_dpus(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in [0..10] {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let mut txn = pool.begin().await?;

    let dpus = DpuMachineUpdate::find_outdated_dpus(&mut txn, "9", None).await?;

    assert_eq!(dpus.len(), dpu_machine_ids.len());
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_outdated_dpus_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let mut host_sims = Vec::default();
    let mut dpu_machine_ids = Vec::default();
    let mut host_machine_ids = Vec::default();
    for _ in [0..10] {
        let host_sim = env.start_managed_host_sim();
        let dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
        dpu_machine_ids.push(dpu_machine_id.clone());
        host_machine_ids.push(
            try_parse_machine_id(
                &create_host_machine(&env, &host_sim.config, &dpu_machine_id).await,
            )
            .unwrap(),
        );
        host_sims.push(host_sim);
    }

    let mut txn = pool.begin().await?;

    let dpus = DpuMachineUpdate::find_outdated_dpus(&mut txn, "9", Some(1)).await?;

    assert_eq!(dpus.len(), 1);
    Ok(())
}
