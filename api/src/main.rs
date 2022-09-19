use log::LevelFilter;
use sqlx::PgPool;

use cfg::{Command, Options};

mod api;
mod auth;
mod cfg;
mod dhcp_discover;

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
        .filter_module("sqlx::query", LevelFilter::Warn)
        .init();

    match config.sub_cmd {
        Command::Migrate(ref m) => {
            let pool = PgPool::connect(&m.datastore[..]).await?;

            carbide::db::migrations::migrate(&pool).await?;
        }
        Command::Run(ref config) => api::Api::run(config).await?,
    }
    Ok(())
}
