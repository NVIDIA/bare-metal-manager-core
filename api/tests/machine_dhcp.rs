use std::str::FromStr;
use std::sync::Once;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::domain::{Domain, NewDomain};
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;
use carbide::CarbideResult;

mod common;

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
async fn test_machine_dhcp() {
    setup();

    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = common::TestDatabaseManager::new()
        .await
        .expect("Could not create second database manager")
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");

    let my_domain = "dwrt.com";

    let _new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn)
    .await;

    let domain = Domain::find_by_name(&mut txn2, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn2)
    .await
    .expect("Unable to create VPC");

    // txn.commit().await.unwrap();

    let _segment: NetworkSegment = NewNetworkSegment {
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
    .persist(&mut txn2)
    .await
    .expect("Unable to create network segment");

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = "192.0.2.1".parse().unwrap();

    let _machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn2,
        test_mac_address,
        test_gateway_address,
    )
    .await
    .expect("Unable to create machine");

    txn.commit().await.unwrap();

    //    let dhcp = DhcpRecord::find_by_id_ipv4(&mut txn, &test_mac_address, segment.id()).await;
    //
    //    assert_eq!(dhcp.address_ipv4().unwrap(), &test_ipv4_prefix);
}
