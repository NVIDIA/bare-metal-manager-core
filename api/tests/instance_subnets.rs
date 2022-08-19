use std::str::FromStr;
use std::sync::Once;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::{
    AddressSelectionStrategy, Instance, InstanceSubnet, Machine, MachineInterface, NetworkSegment,
    NewInstance, NewNetworkPrefix, NewNetworkSegment, NewVpc, VpcResourceState,
};
use carbide::CarbideError;

use crate::common::TestDatabaseManager;

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
async fn new_instance_subnet_matches_machine_interface() {
    setup();

    let pool = TestDatabaseManager::new()
        .await
        .expect("Unable to create database pool")
        .pool;

    let mut txn = pool.begin().await.expect("Unable to create txn");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create VPC");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: None,
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

    txn.commit().await.unwrap();

    let new_interface = MachineInterface::create(
        &mut txn2,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    let new_machine = Machine::create(&mut txn2, new_interface.clone())
        .await
        .expect("Unable to create machine");

    let new_instance = NewInstance::new(new_machine.id().to_owned())
        .persist(&mut txn2)
        .await
        .unwrap();

    txn2.commit().await.unwrap();

    let instance_subnet =
        InstanceSubnet::create(&mut txn3, &new_interface, &new_segment, &new_instance, None)
            .await
            .unwrap();

    txn3.commit().await.unwrap();

    assert_eq!(instance_subnet.machine_interface_id(), new_interface.id())
}

#[tokio::test]
async fn new_instance_in_init_state() {
    setup();

    let pool = TestDatabaseManager::new()
        .await
        .expect("Unable to create database pool")
        .pool;

    let mut txn = pool.begin().await.expect("Unable to create txn");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create VPC");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: None,
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

    txn.commit().await.unwrap();

    let new_interface = MachineInterface::create(
        &mut txn2,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    let new_machine = Machine::create(&mut txn2, new_interface.clone())
        .await
        .expect("Unable to create machine");

    let new_instance = NewInstance::new(new_machine.id().to_owned())
        .persist(&mut txn2)
        .await
        .unwrap();

    txn2.commit().await.unwrap();

    let instance_subnet =
        InstanceSubnet::create(&mut txn3, &new_interface, &new_segment, &new_instance, None)
            .await
            .unwrap();

    let current_state = instance_subnet.current_state(&mut txn3).await.unwrap();

    txn3.commit().await.unwrap();

    assert_eq!(current_state, VpcResourceState::New)
}

#[tokio::test]
async fn instance_subnet_state_machine_advance() {
    setup();

    let pool = TestDatabaseManager::new()
        .await
        .expect("Unable to create database pool")
        .pool;

    let mut txn = pool.begin().await.expect("Unable to create txn");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create VPC");

    let new_segment: NetworkSegment = NewNetworkSegment {
        name: "test-network".to_string(),
        subdomain_id: None,
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

    txn.commit().await.unwrap();

    let new_interface = MachineInterface::create(
        &mut txn2,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    let new_machine = Machine::create(&mut txn2, new_interface.clone())
        .await
        .expect("Unable to create machine");

    let new_instance = NewInstance::new(new_machine.id().to_owned())
        .persist(&mut txn2)
        .await
        .unwrap();

    txn2.commit().await.unwrap();

    let instance_subnet =
        InstanceSubnet::create(&mut txn3, &new_interface, &new_segment, &new_instance, None)
            .await
            .unwrap();

    instance_subnet
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::Submit)
        .await
        .unwrap();
    instance_subnet
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::Accept)
        .await
        .unwrap();
    instance_subnet
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::Wait)
        .await
        .unwrap();
    instance_subnet
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::VpcSuccess)
        .await
        .unwrap();

    let current_state = instance_subnet.current_state(&mut txn3).await.unwrap();

    txn3.commit().await.unwrap();

    assert_eq!(current_state, VpcResourceState::Ready)
}
