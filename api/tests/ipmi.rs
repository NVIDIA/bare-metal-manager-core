use sqlx::PgPool;
use uuid::Uuid;

use carbide::db::ipmi::{BmcMetaData, BmcMetaDataRequest, BmcMetadataItem, UserRoles};
use log::LevelFilter;

const DATA: [(UserRoles, &str, &str); 3] = [
    (UserRoles::Administrator, "forge_admin", "randompassword"),
    (UserRoles::User, "forge_user", "randompassword"),
    (UserRoles::Operator, "forge_operator", "randompassword"),
];

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Debug)
        .init();
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_ipmi_cred(pool: PgPool) {
    let mut txn = pool.begin().await.unwrap();

    let machine_id: Uuid = "52dfecb4-8070-4f4b-ba95-f66d0f51fd98".parse().unwrap();

    BmcMetaData {
        machine_id,
        ip: "127.0.0.2".to_string(),
        data: DATA
            .iter()
            .map(|x| BmcMetadataItem {
                role: x.0.clone(),
                username: x.1.to_string(),
                password: x.2.to_string(),
            })
            .collect::<Vec<BmcMetadataItem>>(),
    }
    .update_bmc_meta_data(&mut txn)
    .await
    .unwrap();

    let _result = txn.commit().await;

    let mut txn = pool.begin().await.unwrap();

    for d in &DATA {
        let ipmi_req = BmcMetaDataRequest {
            machine_id,
            role: d.0.clone(),
        };

        let response = ipmi_req.get_bmc_meta_data(&mut txn).await.unwrap();
        assert_eq!(response.ip, "127.0.0.2".to_string());
        assert_eq!(response.user, d.1.to_string());
        assert_eq!(response.password, d.2.to_string());
    }
}
