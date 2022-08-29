mod common;

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Once;

    use log::LevelFilter;

    use carbide::db::domain::{Domain, NewDomain};
    use carbide::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
    use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
    use carbide::db::vpc::NewVpc;
    use carbide::db::vpc_resource_state::VpcResourceState;
    use carbide::CarbideResult;

    use crate::common::TestDatabaseManager;

    const TEMP_DB_NAME: &str = "network_segmens_tests";
    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(init_logger);
    }

    fn init_logger() {
        pretty_env_logger::formatted_timed_builder()
            .filter_level(LevelFilter::Error)
            .init();
    }

    fn get_base_uri() -> String {
        if std::env::var("TESTDB_HOST").is_ok()
            && std::env::var("TESTDB_USER").is_ok()
            && std::env::var("TESTDB_PASSWORD").is_ok()
        {
            format!(
                "postgres://{0}:{1}@{2}",
                std::env::var("TESTDB_USER").unwrap(),
                std::env::var("TESTDB_PASSWORD").unwrap(),
                std::env::var("TESTDB_HOST").unwrap(),
            )
        } else {
            "postgres://%2Fvar%2Frun%2Fpostgresql".to_string()
        }
    }

    async fn get_database_connection() -> Result<sqlx::PgPool, sqlx::Error> {
        setup();

        let base_uri = get_base_uri();
        let full_uri_template = [base_uri.clone(), "/template1".to_string()].concat();

        let template_pool = sqlx::PgPool::connect(&full_uri_template).await?;
        let pool = template_pool.clone();
        let _x = sqlx::query(format!("DROP DATABASE {0}", TEMP_DB_NAME).as_str())
            .execute(&(pool.clone()))
            .await;
        sqlx::query(format!("CREATE DATABASE {0} TEMPLATE template0", TEMP_DB_NAME).as_str())
            .execute(&pool)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "Database creation failed: {} - {}.",
                    error,
                    base_uri
                )
            });

        let full_uri_db = [base_uri, "/".to_string(), TEMP_DB_NAME.to_string()].concat();

        let real_pool = sqlx::PgPool::connect(&full_uri_db).await?;

        sqlx::migrate!().run(&(real_pool.clone())).await.unwrap();

        Ok(real_pool)
    }

    #[tokio::test]
    async fn test_create_segment_with_domain() {
        let db = TestDatabaseManager::new()
            .await
            .expect("Could not create database manager");

        let mut txn = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let mut txn2 = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on db pool");

        let mut txn3 = db
            .pool
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
            mtu: Some(1500i32),
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

    #[tokio::test]
    async fn test_create_segment_init_state() {
        let db = TestDatabaseManager::new()
            .await
            .expect("Could not create database manager");

        let mut txn = db
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

        txn.commit().await.unwrap();

        let mut txn2 = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let mut txn3 = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let segment: NetworkSegment = NewNetworkSegment {
            name: "integration_test".to_string(),
            subdomain_id: None,
            mtu: Some(1500i32),
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

    #[tokio::test]
    async fn test_advance_network_prefix_state() {
        let db = get_database_connection()
            .await
            .expect("Could not create database manager");

        let mut txn = db
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

        let mut txn2 = db
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let mut txn3 = db
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let segment: NetworkSegment = NewNetworkSegment {
            name: "integration_test".to_string(),
            subdomain_id: None,
            mtu: Some(1500i32),
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
}
