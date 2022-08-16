use carbide::bg::{job, CurrentJob, CurrentState, JobRegistry, OwnedHandle, Status, TaskState};
use carbide::kubernetes::vpc_reconcile_handler;
use carbide::{CarbideError, CarbideResult};
use color_eyre::owo_colors::OwoColorize;
use kube::Client;
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
        if std::env::var("TESTDB_HOST").is_ok()
            || std::env::var("TESTDB_USER").is_ok()
            || std::env::var("TESTDB_PASSWORD").is_ok()
        {
            Self::_new(&format!(
                "postgres://{0}:{1}@{2}",
                std::env::var("TESTDB_USER").unwrap(),
                std::env::var("TESTDB_PASSWORD").unwrap(),
                std::env::var("TESTDB_HOST").unwrap(),
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
pub async fn test_bgkubernetes_handler(
    url: String,
    kube_enabled: bool,
) -> CarbideResult<OwnedHandle> {
    log::info!("Starting Kubernetes handler.");
    let mut registry = JobRegistry::new(&[vpc_reconcile_handler]);
    let new_pool = TestDatabaseManager::new()
        .await
        .expect("Cannot create test database manager")
        .pool;

    // To keep callpath happy, use bogus URL and false for now
    registry.set_context(url.clone());
    registry.set_context(kube_enabled);

    // This function should return ownedhandle. If ownedhandle is dropped, it will stop main event loop also.
    registry
        .runner(&new_pool)
        .set_concurrency(10, 20)
        .run()
        .await
        .map_err(CarbideError::from)
}
// TODO: implement database drop
//
//impl Drop for TestDatabaseManager {
//    fn drop(&mut self) {
//
//
//    }
//}
