mod common;

use std::net::IpAddr;

use carbide::{
    db::{Domain, NetworkSegment, NewDomain, NewNetworkPrefix, NewNetworkSegment},
    CarbideResult,
};

use carbide::db::NewVpc;
use log::LevelFilter;
use std::sync::Once;

fn setup() {
    Once::new().call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
async fn test_create_segment_with_domain() {
    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");

    let mut txn3 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: Some(uuid::Uuid::new_v4()),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create VPC");

    txn.commit().await.unwrap();

    let my_domain = "dwrt.com";

    let _new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn2)
    .await;

    txn2.commit().await.unwrap();

    let domain = Domain::find_by_name(&mut txn3, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    // TODO - Find a domain based on UUID and use that on subdomain_id
    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain.unwrap().id().to_owned()),
        mtu: Some(1500i32),
        vpc_id: Some(vpc.id),

        prefixes: vec![
            NewNetworkPrefix {
                prefix: "192.0.2.1/24".parse().expect("can't parse network"),
                gateway: "192.0.2.1".parse().ok(),
                num_reserved: 1,
            },
            NewNetworkPrefix {
                prefix: "2001:db8:f::/64".parse().expect("can't parse network"),
                gateway: None,
                num_reserved: 100,
            },
        ],
    }
    .persist(&mut txn3)
    .await
    .expect("Unable to create network segment");

    let next_address = segment.next_address(&mut txn3).await.expect("no query?");

    txn3.commit().await.unwrap();

    let _next_ipv4: IpAddr = "192.0.2.2".parse().unwrap();
    let _next_ipv6: IpAddr = "2001:db8:f::64".parse().unwrap();

    assert!(matches!(
        next_address.as_slice(),
        [Ok(_next_ipv4), Ok(_next_ipv6)]
    ));

    assert_eq!(next_address.len(), 2);
}

#[tokio::test]
async fn test_create_segment_no_domain() {
    let db = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager");

    let mut txn = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: Some(uuid::Uuid::new_v4()),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create VPC");

    txn.commit().await.unwrap();

    let mut txn2 = db
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: None,
        mtu: Some(1500i32),
        vpc_id: Some(vpc.id),

        prefixes: vec![
            NewNetworkPrefix {
                prefix: "192.0.2.1/24".parse().expect("can't parse network"),
                gateway: "192.0.2.1".parse().ok(),
                num_reserved: 1,
            },
            NewNetworkPrefix {
                prefix: "2001:db8:f::/64".parse().expect("can't parse network"),
                gateway: None,
                num_reserved: 100,
            },
        ],
    }
    .persist(&mut txn2)
    .await
    .expect("Unable to create network segment");

    let next_address = segment.next_address(&mut txn2).await.expect("no query?");
    txn2.commit().await.unwrap();

    assert_eq!(next_address.len(), 2);
}
