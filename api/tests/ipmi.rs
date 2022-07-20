use carbide::db::UserRoles;
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use carbide::{
    db::{
        AddressSelectionStrategy, BmcMetaDataRequest, Domain, Machine, MachineInterface,
        NetworkSegment, NewDomain, NewNetworkPrefix, NewNetworkSegment, NewVpc,
    },
    CarbideResult,
};

mod common;

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
        organization: Some(uuid::Uuid::new_v4()),
    }
    .persist(txn)
    .await
    .expect("Unable to create VPC");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain).unwrap().map(|d| d.id().to_owned()),
        mtu: Some(1500i32),
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

    let new_machine = Machine::create(txn, new_interface)
        .await
        .expect("Unable to create machine");

    new_machine
}

async fn create_user_entry(id: Uuid, pool: PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let _: (Uuid,) = sqlx::query_as(
        r#"INSERT INTO machine_topologies (machine_id, topology)
            VALUES($1, '{"ipmi_ip": "127.0.0.2"}') 
            returning machine_id"#,
    )
    .bind(id)
    .fetch_one(&mut txn)
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let _: (String,) = sqlx::query_as(
        r#"INSERT INTO machine_console_metadata (machine_id, username, role, password)
            VALUES($1, 'testuser', 'administrator', 'password') 
            returning username"#,
    )
    .bind(id)
    .fetch_one(&mut txn)
    .await
    .unwrap();
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

    create_user_entry(machine.id().clone(), pool.clone()).await;

    let mut txn = pool.begin().await.unwrap();

    let ipmi_req = BmcMetaDataRequest {
        machine_id: machine.id().clone(),
        role: UserRoles::Administrator,
    };

    let response = ipmi_req.get_bmc_meta_data(&mut txn).await.unwrap();
    assert_eq!(response.ip, "127.0.0.2".to_string());
    assert_eq!(response.user, "testuser".to_string());
    assert_eq!(response.password, "password".to_string());
}
