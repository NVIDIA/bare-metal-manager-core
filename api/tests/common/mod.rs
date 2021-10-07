use carbide::db::{Datastore, Pool};
use carbide::CarbideResult;
use rand::prelude::*;
use std::str::FromStr;

pub struct TestDatabaseManager {
    #[allow(dead_code)]
    template_pool: Pool,
    pub pool: Pool,
}

impl TestDatabaseManager {
    pub(crate) async fn new() -> CarbideResult<Self> {
        let temporary_database_name = format!(
            "{0}_integrationtests_{1}_{2}",
            env!("CARGO_PKG_NAME"),
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(7)
                .map(char::from)
                .collect::<String>()
                .to_lowercase(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros()
        );

        let username = env!("LOGNAME");

        let real_config = tokio_postgres::config::Config::from_str(
            format!(
                "postgres://{0}@%2Fvar%2Frun%2Fpostgresql/{1}",
                username, temporary_database_name
            )
            .as_str(),
        )
        .unwrap();

        let template_config = tokio_postgres::config::Config::from_str(
            format!(
                "postgres://{0}@%2Fvar%2Frun%2Fpostgresql/template1",
                username
            )
            .as_str(),
        )
        .unwrap();

        let real_pool = Datastore::pool_from_config(real_config).await?;
        let template_pool = Datastore::pool_from_config(template_config).await?;

        let p = template_pool.clone();
        let p2 = real_pool.clone();
        let db = temporary_database_name.clone();

        tokio::spawn(async move {
            let connection = p.get().await.unwrap();

            connection
                .query(
                    format!("CREATE DATABASE {0} TEMPLATE template0", db).as_str(),
                    &[],
                )
                .await
                .unwrap();

            Datastore::migrate(p2).await.unwrap();
        })
        .await
        .unwrap();

        Ok(Self {
            template_pool,
            pool: real_pool,
        })
    }
}

// TODO: implement database drop
//
//impl Drop for TestDatabaseManager {
//    fn drop(&mut self) {
//
//
//    }
//}
