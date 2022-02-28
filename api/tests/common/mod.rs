use carbide::CarbideResult;
use rand::prelude::*;
use sqlx::PgPool;
use std::env;

pub struct TestDatabaseManager {
    #[allow(dead_code)]
    template_pool: PgPool,
    pub pool: PgPool,
}

impl TestDatabaseManager {
    pub(crate) async fn new() -> CarbideResult<Self> {
        let temporary_database_name = format!(
            "{0}_integrationtests_{1}_{2}",
            env!("CARGO_CRATE_NAME"),
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

        let username = std::env::var("TESTDB_USER").unwrap_or(env!("LOGNAME").to_string());
        let password = std::env::var("TESTDB_PASSWORD").unwrap_or("".to_string());
        let db_host = std::env::var("TESTDB_HOST")
            .unwrap_or("%2Fvar%2Frun%2Fpostgresql/template1".to_string());

        // Not pretty, but if there is no password specified as an env var, assume its connecting over UDS
        let uri: String = match password.is_empty() {
            true => "%2Fvar%2Frun%2Fpostgresql".to_string(),
            false => format!("postgres://{0}:{1}@{2}", username, password, db_host),
        };

        let template_name = "template1";
        let full_uri_template: String = [&uri[..], "/", &template_name[..]].concat();

        let template_pool = sqlx::PgPool::connect(&full_uri_template).await?;

        let pool = template_pool.clone();

        sqlx::query(
            format!(
                "CREATE DATABASE {0} TEMPLATE template0",
                temporary_database_name
            )
            .as_str(),
        )
        .execute(&pool)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Failed to create test database: {0}",
                temporary_database_name
            )
        });

        let full_uri_db: String = [&uri[..], "/", &temporary_database_name[..]].concat();

        let mut real_pool = sqlx::PgPool::connect(&full_uri_db).await?;

        carbide::db::migrations::migrate(&mut real_pool)
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
