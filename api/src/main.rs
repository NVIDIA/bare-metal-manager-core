mod api;
mod cfg;

use carbide::db;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use cfg::{Command, Options};

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
        Command::Migrate(ref m) => {
            let pool = db::Datastore::pool_from_url(&m.datastore[..]).await?;

            // Clone an instance of the database pool
            let pool_instance = pool.clone();

            let report = db::Datastore::migrate(pool_instance).await?;

            for migration in report.applied_migrations() {
                info!("Migration applied {0}", migration)
            }
        }
        Command::Run(ref config) => api::Api::run(&config).await?,
    }
    Ok(())
}
