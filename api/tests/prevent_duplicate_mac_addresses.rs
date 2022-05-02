use log::LevelFilter;
use std::sync::Once;

use carbide::db::Domain;
use carbide::db::Machine;
use carbide::db::MachineInterface;
use carbide::db::NetworkSegment;
use carbide::db::NewDomain;
use carbide::db::NewNetworkPrefix;
use carbide::db::NewNetworkSegment;
use carbide::db::{AddressSelectionStrategy, NewVpc};

mod common;

use carbide::{CarbideError, CarbideResult};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
async fn prevent_duplicate_mac_addresses() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let my_domain = "dwrt.com";

    let _new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn)
    .await;

    let domain = Domain::find_by_name(&mut txn, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: Some(uuid::Uuid::new_v4()),
    }
    .persist(&mut txn)
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
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let mut new_interface = MachineInterface::create(
        &mut txn,
        &segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create interface");

    let new_machine = Machine::create(&mut txn, "{}".to_string(), new_interface)
        .await
        .expect("Unable to create machine");

    let duplicate_interface = MachineInterface::create(
        &mut txn,
        &segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await.unwrap();
    assert!(matches!(
        duplicate_interface,
        Err(CarbideError::NetworkSegmentDuplicateMacAddress(_))
    ));
}
