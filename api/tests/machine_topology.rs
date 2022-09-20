use std::str::FromStr;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::machine::Machine;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::machine_topology::MachineTopology;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;

mod common;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
async fn test_crud_machine_topology() {
    let mut txn = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool
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

    let new_interface = MachineInterface::create(
        &mut txn,
        &new_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    let machine = Machine::create(&mut txn, new_interface)
        .await
        .expect("Unable to create machine");

    let json = r#"{"machine_id": {"value": "1685191a-50f2-49da-a75e-81b8d8dfbc2c"}, "discovery_data": {"InfoV0": {"cpus": [{"core": 0, "node": 0, "model": "Intel(R) Core(TM) i9-10920X CPU @ 3.50GHz", "number": 0, "socket": 0, "vendor": "GenuineIntel", "frequency": "3503.998"}], "machine_type": "x86_64", "block_devices": [{"model": "QEMU_DVD-ROM", "serial": "QM00003", "revision": "2.5+"}, {"model": "NO_MODEL", "serial": "NO_SERIAL", "revision": "NO_REVISION"}], "network_interfaces": [{"mac_address": "52:54:00:12:34:56", "pci_properties": {"path": "/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4", "device": "0x1000", "vendor": "0x1af4", "numa_node": 2147483647, "description": "Virtio network device"}}]}}}"#;
    MachineTopology::create(&mut txn, machine.id(), json.to_string())
        .await
        .expect("Unable to create topology");

    txn.commit().await.unwrap();
}
