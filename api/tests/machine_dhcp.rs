use log::LevelFilter;
use sqlx::prelude::*;

use mac_address::MacAddress;
use std::str::FromStr;

use carbide::db::domain::{Domain, NewDomain};
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::NewNetworkPrefix;
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::NewVpc;
use carbide::CarbideResult;

#[sqlx::test]
async fn test_machine_dhcp(pool: sqlx::PgPool) -> sqlx::Result<()> {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let mut connection = pool.acquire().await?;

    let mut txn = connection.begin().await?;

    let my_domain = "dwrt.com";

    let _new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(&mut txn)
    .await;

    txn.commit().await?;

    let mut txn = connection.begin().await?;

    let domain = Domain::find_by_name(&mut txn, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: String::new(),
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create VPC");

    // txn.commit().await.unwrap();

    let _segment: NetworkSegment = NewNetworkSegment {
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
    .persist(&mut txn)
    .await
    .expect("Unable to create network segment");

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = "192.0.2.1".parse().unwrap();

    let _machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
    )
    .await
    .expect("Unable to create machine");

    txn.commit().await.unwrap();

    Ok(())
}
