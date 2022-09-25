use std::str::FromStr;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::instance::NewInstance;
use carbide::db::instance_subnet::InstanceSubnet;
use carbide::db::machine::Machine;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;
use carbide::db::vpc_resource_state::VpcResourceState;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test]
async fn new_instance_subnet_matches_machine_interface(pool: sqlx::PgPool) {
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

    let new_instance = NewInstance {
        machine_id: new_machine.id().to_owned(),
        segment_id: *new_segment.id(),
        user_data: Some("".to_string()),
        custom_ipxe: "".to_string(),
        ssh_keys: vec![],
    }
    .persist(&mut txn2)
    .await
    .unwrap();

    txn2.commit().await.unwrap();

    let instance_subnet = InstanceSubnet::create(
        &mut txn3,
        &new_interface,
        *new_segment.id(),
        *new_instance.id(),
        None,
    )
    .await
    .unwrap();

    txn3.commit().await.unwrap();

    assert_eq!(instance_subnet.machine_interface_id(), new_interface.id())
}

#[sqlx::test]
async fn new_instance_in_init_state(pool: sqlx::PgPool) {
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

    let new_instance = NewInstance {
        machine_id: new_machine.id().to_owned(),
        segment_id: *new_segment.id(),
        user_data: Some("".to_string()),
        custom_ipxe: "".to_string(),
        ssh_keys: vec![],
    }
    .persist(&mut txn2)
    .await
    .unwrap();

    txn2.commit().await.unwrap();

    let instance_subnet = InstanceSubnet::create(
        &mut txn3,
        &new_interface,
        *new_segment.id(),
        *new_instance.id(),
        None,
    )
    .await
    .unwrap();

    let current_state = instance_subnet.current_state(&mut txn3).await.unwrap();

    txn3.commit().await.unwrap();

    assert_eq!(current_state, VpcResourceState::New)
}

#[sqlx::test]
async fn instance_subnet_state_machine_advance(pool: sqlx::PgPool) {
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

    let new_instance = NewInstance {
        machine_id: new_machine.id().to_owned(),
        segment_id: *new_segment.id(),
        user_data: Some("".to_string()),
        custom_ipxe: "".to_string(),
        ssh_keys: vec![],
    }
    .persist(&mut txn2)
    .await
    .unwrap();

    txn2.commit().await.unwrap();

    let instance_subnet = InstanceSubnet::create(
        &mut txn3,
        &new_interface,
        *new_segment.id(),
        *new_instance.id(),
        None,
    )
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
