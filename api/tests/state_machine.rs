use std::sync::Once;

use std::str::FromStr;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::{
    AddressSelectionStrategy, Machine, MachineInterface, MachineState, NetworkSegment,
    NewNetworkPrefix, NewNetworkSegment, NewVpc,
};
use carbide::CarbideError;

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

// #[tokio::test]
// async fn state_machine_advance_from_db_events() {
//     setup();
//
//     let mut txn = common::TestDatabaseManager::new()
//         .await
//         .expect("Could not create database manager")
//         .pool
//         .begin()
//         .await
//         .expect("Unable to create transaction on database pool");
//
//     let vpc = NewVpc {
//         name: "Test VPC".to_string(),
//         organization: Some(uuid::Uuid::new_v4()),
//     }
//     .persist(&mut txn)
//     .await
//     .expect("Unable to create VPC");
//
//     let new_segment: NetworkSegment = NewNetworkSegment {
//         name: "test-network".to_string(),
//         subdomain_id: None,
//         mtu: Some(1500i32),
//         vpc_id: Some(vpc.id),
//
//         prefixes: vec![
//             NewNetworkPrefix {
//                 prefix: "2001:db8:f::/64".parse().unwrap(),
//                 gateway: None,
//                 num_reserved: 100,
//             },
//             NewNetworkPrefix {
//                 prefix: "192.0.2.0/24".parse().unwrap(),
//                 gateway: "192.0.2.1".parse().ok(),
//                 num_reserved: 2,
//             },
//         ],
//     }
//     .persist(&mut txn)
//     .await
//     .expect("Unable to create network segment");
//
//     let new_interface = MachineInterface::create(
//         &mut txn,
//         &new_segment,
//         MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
//         None,
//         "peppersmacker2".to_string(),
//         true,
//         AddressSelectionStrategy::Automatic,
//     )
//     .await
//     .expect("Unable to create machine interface");
//
//     let machine = Machine::create(&mut txn, new_interface)
//         .await
//         .expect("Unable to create machine");
//
//     // Insert some valid state changes into the db
//     machine
//         .advance(&mut txn, &rpc::MachineStateMachineInput::Adopt)
//         .await
//         .unwrap();
//     machine
//         .advance(&mut txn, &rpc::MachineStateMachineInput::Test)
//         .await
//         .unwrap();
//     machine
//         .advance(&mut txn, &rpc::MachineStateMachineInput::Commission)
//         .await
//         .unwrap();
//     machine
//         .advance(&mut txn, &rpc::MachineStateMachineInput::Assign)
//         .await
//         .unwrap();
//
//     let state = machine.current_state(&mut txn).await.unwrap();
//     assert!(matches!(state, MachineState::Assigned));
// }
//
// #[tokio::test]
// async fn test_fsm_invalid_advance() {
//     setup();
//
//     let mut txn = common::TestDatabaseManager::new()
//         .await
//         .expect("Could not create database manager")
//         .pool
//         .begin()
//         .await
//         .expect("Unable to create transaction on database pool");
//
//     let vpc = NewVpc {
//         name: "Test VPC".to_string(),
//         organization: Some(uuid::Uuid::new_v4()),
//     }
//     .persist(&mut txn)
//     .await
//     .expect("Unable to create VPC");
//
//     let new_segment: NetworkSegment = NewNetworkSegment {
//         name: "test-network".to_string(),
//         subdomain_id: None,
//         mtu: Some(1500i32),
//         vpc_id: Some(vpc.id),
//
//         prefixes: vec![
//             NewNetworkPrefix {
//                 prefix: "2001:db8:f::/64".parse().unwrap(),
//                 gateway: None,
//                 num_reserved: 100,
//             },
//             NewNetworkPrefix {
//                 prefix: "192.0.2.0/24".parse().unwrap(),
//                 gateway: "192.0.2.1".parse().ok(),
//                 num_reserved: 2,
//             },
//         ],
//     }
//     .persist(&mut txn)
//     .await
//     .expect("Unable to create network segment");
//
//     let new_interface = MachineInterface::create(
//         &mut txn,
//         &new_segment,
//         MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
//         None,
//         "peppersmacker2".to_string(),
//         true,
//         AddressSelectionStrategy::Automatic,
//     )
//     .await
//     .expect("Unable to create machine interface");
//
//     let machine = Machine::create(&mut txn, new_interface)
//         .await
//         .expect("Unable to create machine");
//
//     let state = machine.current_state(&mut txn).await.unwrap();
//     assert!(matches!(state, MachineState::New));
//
//     assert!(matches!(
//         machine
//             .advance(&mut txn, &rpc::MachineStateMachineInput::Commission)
//             .await
//             .unwrap_err(),
//         CarbideError::InvalidState { .. }
//     ));
// }
