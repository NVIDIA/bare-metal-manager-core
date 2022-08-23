use std::sync::RwLock;

use log::LevelFilter;
use once_cell::sync::Lazy;
use sqlx::PgPool;

use cfg::{Command, Options};

mod auth;
mod cfg;
mod commands;
mod ipmi;
mod server;

static CONFIG: Lazy<RwLock<ConsoleContext>> = Lazy::new(|| {
    RwLock::new(ConsoleContext {
        api_endpoint: "http://[::1]:1079".to_string(),
    })
});

#[derive(Debug)]
struct ConsoleContext {
    api_endpoint: String,
}

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let config = Options::load();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
                // command line overrides config file
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Debug
            }
            _ => {
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Trace
            }
        })
        .init();

    match config.subcmd {
        Command::Run(ref config) => {
            CONFIG.write().unwrap().api_endpoint = config.api_endpoint.clone();
            let pool = PgPool::connect(&config.datastore[..]).await?;
            server::run(pool, config.listen[0]).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    static TEMP_DB_NAME: &str = "console_test";

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

    async fn insert_dummy_vals(pool: sqlx::PgPool) {
        println!("Inserting dummy data");
        let row: (Uuid, ) = sqlx::query_as("INSERT INTO machines DEFAULT VALUES returning id")
            .fetch_one(&pool)
            .await
            .unwrap();
        let id = row.0;
        println!("{}", id);
        let _: (Uuid, ) = sqlx::query_as(
            "INSERT INTO network_segments (id, name) VALUES ($1, 'test_network') returning id",
        )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let _: (Uuid, ) =
            sqlx::query_as("INSERT INTO domains (id, name) VALUES ($1, 'test.com') returning id")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let _: (Uuid, ) = sqlx::query_as(r#"INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, domain_id, hostname,primary_interface)
                               VALUES ($1, $1, 'de:af:de:ad:be:ed', $1, 'myhost', true) returning machine_id"#)
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let _: (Uuid, ) =
            sqlx::query_as(r#"INSERT INTO machine_topologies VALUES ($1, '{"ipmi_ip": "127.0.0.1", "ipmi_user": "admin"}') returning machine_id"#)
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
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
            .unwrap_or_else(|_| panic!("Database creation failed."));

        pool.close().await;
        let full_uri_db = [base_uri, "/".to_string(), TEMP_DB_NAME.to_string()].concat();

        let real_pool = sqlx::PgPool::connect(&full_uri_db).await?;

        sqlx::migrate!("../../api/migrations")
            .run(&(real_pool.clone()))
            .await
            .unwrap();

        // Insert some dummy data here.
        insert_dummy_vals(real_pool.clone()).await;

        Ok(real_pool)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_thrussh() {
        let pool = get_database_connection().await.unwrap();
        use std::env;
        match env::var("SSH_PROXY_MT_ENV") {
            Ok(_) => {
                tokio::time::timeout(
                    std::time::Duration::from_secs(20000),
                    server::run(pool, "127.0.0.1:2224".parse().unwrap()),
                )
                    .await
                    .unwrap_or(());
            }
            Err(_) => (),
        }
    }
}
