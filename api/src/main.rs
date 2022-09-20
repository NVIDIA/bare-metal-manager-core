use cfg::{Command, Options};
use sqlx::PgPool;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};

mod api;
mod auth;
mod cfg;
mod dhcp_discover;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let config = Options::load();

    let env_filter = EnvFilter::from_default_env()
        .add_directive(
            match config.debug {
                0 => LevelFilter::INFO,
                1 => {
                    // command line overrides config file
                    std::env::set_var("RUST_BACKTRACE", "1");
                    LevelFilter::DEBUG
                }
                _ => {
                    std::env::set_var("RUST_BACKTRACE", "1");
                    LevelFilter::TRACE
                }
            }
            .into(),
        )
        .add_directive("sqlx::query=warn".parse()?)
        .add_directive("h2::codec=warn".parse()?);

    tracing_subscriber::registry()
        .with(fmt::Layer::default().pretty())
        .with(env_filter)
        .try_init()?;

    match config.sub_cmd {
        Command::Migrate(ref m) => {
            log::debug!("Running migrations");
            let pool = PgPool::connect(&m.datastore[..]).await?;
            carbide::db::migrations::migrate(&pool).await?;
        }
        Command::Run(ref config) => api::Api::run(config).await?,
    }
    Ok(())
}
