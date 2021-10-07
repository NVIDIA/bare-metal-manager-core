mod common;

use ip_network::{Ipv4Network, Ipv6Network};

use carbide::db::NetworkSegment;

use log::LevelFilter;

#[tokio::test]
async fn test_create_segment() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let db = common::TestDatabaseManager::new().await.unwrap();

    let mut connection = db.pool.get().await.unwrap();

    let txn = connection.transaction().await.unwrap();

    let segment = NetworkSegment::create(
        &txn,
        "integration_test",
        "m.nvmetal.net",
        &1500i32,
        Some(Ipv4Network::from_str_truncate("192.0.2.1/24").expect("can't parse network")),
        Some(Ipv6Network::from_str_truncate("2001:db8:f::/64").expect("can't parse network")),
        &3,
        &0,
    )
    .await;

    assert!(segment.is_ok());
}
