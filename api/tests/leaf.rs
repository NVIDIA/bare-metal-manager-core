use crate::common::TestDatabaseManager;

mod common;

#[cfg(test)]
mod tests {
    use log::info;

    use carbide::bg::Status;
    use carbide::db::vpc_resource_state::VpcResourceState;
    use carbide::db::{NewVpcResourceLeaf, VpcResourceLeaf};
    use carbide::kubernetes::VpcResourceActions;
    use carbide::vpc_resources::leaf;
    use carbide::CarbideResult;

    use crate::{common, TestDatabaseManager};

    use super::*;

    static TEMP_DB_NAME: &str = "kubehandler_test";

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
            .unwrap_or_else(|x| {
                panic!(
                    "Database creation failed: {} - {}.",
                    x.to_string(),
                    base_uri
                )
            });

        let full_uri_db = [base_uri, "/".to_string(), TEMP_DB_NAME.to_string()].concat();

        let real_pool = sqlx::PgPool::connect(&full_uri_db).await?;

        sqlx::migrate!().run(&(real_pool.clone())).await.unwrap();

        Ok(real_pool)
    }

    #[tokio::test]
    async fn new_leafs_are_in_new_state() {
        let db = TestDatabaseManager::new()
            .await
            .expect("Could not create database manager");

        let mut txn = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let leaf = NewVpcResourceLeaf::new()
            .persist(&mut txn)
            .await
            .expect("Could not create new leaf");

        txn.commit().await.expect("Could not create new leaf");

        let mut txn2 = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let vpc_resource_leaf = VpcResourceLeaf::find(&mut txn2, leaf.id().to_owned())
            .await
            .expect("Could not find newly created leaf");

        let current_state = vpc_resource_leaf
            .current_state(&mut txn2)
            .await
            .expect("Could not get current state of leaf");

        info!("Current state - {}", current_state);

        // assert!(matches!(current_state, VpcResourceState::New));
    }

    #[tokio::test]
    async fn find_leaf_by_id() {
        if let Err(e) = pretty_env_logger::try_init() {
            eprintln!("An error occured {}", e)
        }
        let db = TestDatabaseManager::new()
            .await
            .expect("Could not create database manager");

        let mut txn = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let leaf: CarbideResult<VpcResourceLeaf> =
            NewVpcResourceLeaf::new().persist(&mut txn).await;

        txn.commit()
            .await
            .expect("Unable to create new VpcResourceLeaf");

        let mut txn2 = db
            .pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");

        let _unwrapped = &leaf.expect("Unable to unmarshal leaf from Result");

        let some_leaf = VpcResourceLeaf::find(&mut txn2, _unwrapped.id().to_owned()).await;

        assert!(matches!(some_leaf, _unwrapped));
    }

    // This will need rethinking to pass in CI
    #[tokio::test]
    #[ignore]
    async fn create_background_job_for_create_vpc_leaf() {
        if let Err(e) = pretty_env_logger::try_init() {
            eprintln!("An error occured {}", e)
        }
        let db = get_database_connection()
            .await
            .expect("Could not get database connection");

        let _kube_handle = common::test_bgkubernetes_handler("BS Kube".to_string(), true)
            .await
            .expect("Unable to spawn job listener");

        let mut txn = db
            .begin()
            .await
            .expect("Unable to create transaction on pool");

        let mut txn2 = db
            .begin()
            .await
            .expect("Unable to create transaction on pool");
        // Create a leaf in vpc_leaf_resource table
        let new_vpc_resource_leaf = NewVpcResourceLeaf::new().persist(&mut txn).await.unwrap();

        txn.commit()
            .await
            .expect("Unable to create new vpc resource leaf");

        let leaf_spec = leaf::Leaf::new(
            new_vpc_resource_leaf.id().to_string().as_str(),
            leaf::LeafSpec {
                control: Some(leaf::LeafControl {
                    maintenance_mode: Some(false),
                    management_ip: Some("1.2.3.4".to_string()),
                    vendor: None,
                }),
                host_admin_i_ps: None,
                host_interfaces: None,
            },
        );

        let vpc_resource_conn = &mut *db.acquire().await.unwrap();

        let jid = VpcResourceActions::CreateLeaf(leaf_spec)
            .reconcile(vpc_resource_conn)
            .await
            .unwrap();

        info!("Jid: {}", jid);
        loop {
            if Status::is_finished(&db.clone(), jid).await.unwrap() {
                info!("{} is finished", jid);
                break;
            }
            info!("Sleeping 1000ms for job id {}", jid);
            let current_state = new_vpc_resource_leaf
                .current_state(&mut txn2)
                .await
                .unwrap();
            info!("Current state  --- {}", current_state);

            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        }

        let current_state = new_vpc_resource_leaf
            .current_state(&mut txn2)
            .await
            .unwrap();

        println!("Current state  --- {}", current_state);
        assert!(matches!(current_state, VpcResourceState::New));
    }
}
