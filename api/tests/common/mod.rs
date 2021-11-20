use carbide::CarbideResult;
use rand::prelude::*;
use sqlx::PgPool;

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

        let username = env!("LOGNAME");
        let template_pool = sqlx::PgPool::connect(
            format!(
                "postgres://{0}@%2Fvar%2Frun%2Fpostgresql/template1",
                username
            )
            .as_str(),
        ).await?;

        let pool = template_pool.clone();

        sqlx::query(format!("CREATE DATABASE {0} TEMPLATE template0", temporary_database_name).as_str())
            .execute(&pool).await.expect(format!("Failed to create test database: {0}", temporary_database_name).as_str());

        let mut real_pool = sqlx::PgPool::connect(
            format!(
                "postgres://{0}@%2Fvar%2Frun%2Fpostgresql/{1}",
                username, temporary_database_name
            )
            .as_str(),
        ).await?;

        carbide::db::migrations::migrate(&mut real_pool).await.unwrap();

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
