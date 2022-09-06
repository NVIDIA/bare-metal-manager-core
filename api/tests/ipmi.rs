use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::domain::{Domain, NewDomain};
use carbide::db::ipmi::{BmcMetaData, BmcMetaDataRequest, BmcMetadataItem, UserRoles};
use carbide::db::machine::Machine;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;
use carbide::CarbideResult;

mod common;

const DATA: [(UserRoles, &str, &str); 3] = [
    (UserRoles::Administrator, "forge_admin", "randompassword"),
    (UserRoles::User, "forge_user", "randompassword"),
    (UserRoles::Operator, "forge_operator", "randompassword"),
];

async fn create_machine(txn: &mut sqlx::Transaction<'_, Postgres>) -> Machine {
    let my_domain = "dwrt.com";

    let _new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(txn)
    .await;

    let domain = Domain::find_by_name(txn, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(txn)
    .await
    .expect("Unable to create VPC");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain).unwrap().map(|d| d.id().to_owned()),
        mtu: 1500i32,
        vpc_id: Some(vpc.id),

        prefixes: vec![
            NewNetworkPrefix {
                prefix: "2001:db8:f::/64".parse().unwrap(),
                gateway: None,
                num_reserved: 100,
            },
            NewNetworkPrefix {
                prefix: "192.0.2.0/24".parse().unwrap(),
                gateway: "192.0.2.1".parse().ok(),
                num_reserved: 2,
            },
        ],
    }
    .persist(txn)
    .await
    .expect("Unable to create network segment");

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_interface = MachineInterface::create(
        txn,
        &segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create interface");

    Machine::create(txn, new_interface)
        .await
        .expect("Unable to create machine")
}

async fn create_empty_entry(id: Uuid, pool: PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let query = r#"INSERT INTO machine_topologies (machine_id, topology)
                           VALUES ($1, '{}') 
                           ON CONFLICT DO NOTHING 
                           RETURNING machine_id"#;
    let _: Option<(Uuid,)> = sqlx::query_as(query)
        .bind(&id)
        .fetch_optional(&mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

async fn update_bmc_data(id: Uuid, pool: PgPool) {
    let meta_data = BmcMetaData {
        machine_id: id,
        ip: "127.0.0.2".to_string(),
        data: DATA
            .iter()
            .map(|x| BmcMetadataItem {
                role: x.0.clone(),
                username: x.1.to_string(),
                password: x.2.to_string(),
            })
            .collect::<Vec<BmcMetadataItem>>(),
    };

    create_empty_entry(id, pool.clone()).await;

    let mut txn = pool.begin().await.unwrap();
    meta_data.update_bmc_meta_data(&mut txn).await.unwrap();
    txn.commit().await.unwrap();
}

#[tokio::test]
async fn test_ipmi_cred() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    // Create tag first to delete.
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let machine = create_machine(&mut txn).await;
    txn.commit().await.unwrap();

    update_bmc_data(*machine.id(), pool.clone()).await;

    let mut txn = pool.begin().await.unwrap();

    for d in &DATA {
        let ipmi_req = BmcMetaDataRequest {
            machine_id: *machine.id(),
            role: d.0.clone(),
        };

        let response = ipmi_req.get_bmc_meta_data(&mut txn).await.unwrap();
        assert_eq!(response.ip, "127.0.0.2".to_string());
        assert_eq!(response.user, d.1.to_string());
        assert_eq!(response.password, d.2.to_string());
    }
}
