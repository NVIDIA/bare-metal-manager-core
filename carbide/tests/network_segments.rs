mod common;

use ip_network::{Ipv4Network, Ipv6Network};
use log::info;

use eui48::MacAddress;
use std::net::{IpAddr, SocketAddr};

use log::LevelFilter;

#[tokio::test]
async fn test_create_segment() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let db = common::TestDatabaseManager::new().await.unwrap();

    let mut connection = db.pool.get().await.unwrap();

    let txn = connection.transaction().await.unwrap();

    let segment = carbide::models::NetworkSegment::create(
        &txn,
        String::from("integration_test"),
        String::from("m.nvmetal.net"),
        Some(Ipv4Network::from_str_truncate("192.0.2.1/24").expect("can't parse network")),
        Some(Ipv6Network::from_str_truncate("2001:db8:f::/64").expect("can't parse network")),
    )
    .await
    .expect("Unable to create segment");

    // Discovered a machine with Mac address 0-0-0-0-0-0 by relay 192.0.2.0/24
    let machine = carbide::models::Machine::discover(
        &txn,
        "00:00:00:00:00:00".parse::<MacAddress>().unwrap(),
        "2001:db8:f::".parse::<std::net::IpAddr>().unwrap(),
    )
    .await;

    txn.commit().await;

    info!("Segment {:?}, machine: {:?}", segment, machine);
}
