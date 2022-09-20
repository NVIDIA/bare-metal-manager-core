use std::net::IpAddr;
use std::str::FromStr;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::domain::{Domain, NewDomain};
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;
use carbide::db::vpc_resource_state::VpcResourceState;
use carbide::{CarbideError, CarbideResult};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test]
async fn test_create_segment_with_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on db pool");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
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
        mtu: 1500i32,
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

#[sqlx::test]
async fn test_create_segment_init_state(pool: sqlx::PgPool) {
    let mut txn = pool
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

    txn.commit().await.unwrap();

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: None,
        mtu: 1500i32,
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

    let new_prefix: NetworkPrefix = NetworkPrefix::find(&mut txn2, segment.prefixes[0].id)
        .await
        .expect("Could not get network prefix id");

    txn2.commit().await.unwrap();

    let current_state = new_prefix
        .current_state(&mut txn3)
        .await
        .expect("Unable to get current state for prefix");

    assert_eq!(current_state, VpcResourceState::New)
}

#[sqlx::test]
async fn test_advance_network_prefix_state(pool: sqlx::PgPool) {
    let mut txn = pool
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

    txn.commit().await.unwrap();

    let mut txn2 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let mut txn3 = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: None,
        mtu: 1500i32,
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

    txn2.commit().await.unwrap();

    let new_prefix: NetworkPrefix = NetworkPrefix::find(&mut txn3, segment.prefixes[0].id)
        .await
        .expect("Could not get network prefix id");

    new_prefix
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::Submit)
        .await
        .expect("Unable to advance state machine");

    new_prefix
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::Accept)
        .await
        .expect("Unable to advance state machine");

    new_prefix
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::Wait)
        .await
        .expect("Unable to advance state machine");

    new_prefix
        .advance(&mut txn3, &rpc::VpcResourceStateMachineInput::VpcSuccess)
        .await
        .expect("Unable to advance state machine");

    let current_state = new_prefix
        .current_state(&mut txn3)
        .await
        .expect("Unable to get current state for prefix");

    txn3.commit().await.unwrap();

    println!("Current -----  {}", current_state);

    assert_eq!(current_state, VpcResourceState::Ready);
}

#[sqlx::test]
async fn test_network_segment_delete(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // Simple test of a segment with nothing associated
    let segment: NetworkSegment = NewNetworkSegment {
        name: "delete_test".to_string(),
        subdomain_id: None,
        mtu: 1500i32,
        vpc_id: None,

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
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let delete_result = segment.delete(&mut txn).await;

    txn.commit().await.unwrap();
    assert!(matches!(delete_result, Ok(_)));
}

#[sqlx::test]
async fn test_network_segment_delete_fails(pool: sqlx::PgPool) {
    let mut txn = pool
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

    let my_domain = "dwrt.com";

    let domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn)
    .await;

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain.unwrap().id().to_owned()),
        mtu: 1500i32,
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
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let delete_result = segment.delete(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(
        delete_result,
        Err(CarbideError::NetworkSegmentDelete(_))
    ));
}

#[sqlx::test]
async fn test_network_segment_delete_fails_with_associated_mi(pool: sqlx::PgPool) {
    let mut txn = pool
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

    let my_domain = "dwrt.com";

    let domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn)
    .await;

    let segment: NetworkSegment = NewNetworkSegment {
        name: "mideletetest".to_string(),
        subdomain_id: Some(domain.unwrap().id().to_owned()),
        mtu: 1500i32,
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
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let _new_interface = MachineInterface::create(
        &mut txn,
        &segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "colklink".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    let delete_result = segment.delete(&mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(
        delete_result,
        Err(CarbideError::NetworkSegmentDelete(_))
    ));
}
