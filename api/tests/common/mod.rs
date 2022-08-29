use std::env;

use rand::prelude::*;
use sqlx::PgPool;

use carbide::CarbideResult;

pub struct TestDatabaseManager {
    _template_pool: PgPool,
    pub pool: PgPool,
}

impl TestDatabaseManager {
    pub(crate) async fn new() -> CarbideResult<Self> {
        if env::var("TESTDB_HOST").is_ok()
            || env::var("TESTDB_USER").is_ok()
            || env::var("TESTDB_PASSWORD").is_ok()
        {
            Self::_new(&format!(
                "postgres://{0}:{1}@{2}",
                env::var("TESTDB_USER").unwrap(),
                env::var("TESTDB_PASSWORD").unwrap(),
                env::var("TESTDB_HOST").unwrap(),
            ))
            .await
        } else {
            Self::_new("postgres://%2Fvar%2Frun%2Fpostgresql").await
        }
    }

    pub(crate) async fn _new(base_uri: &str) -> CarbideResult<Self> {
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

        let full_uri_template = [base_uri, "/template1"].concat();

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

        let full_uri_db = [base_uri, "/", &temporary_database_name[..]].concat();

        let real_pool = sqlx::PgPool::connect(&full_uri_db).await?;

        carbide::db::migrations::migrate(&real_pool).await.unwrap();

        Ok(Self {
            _template_pool: template_pool,
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
