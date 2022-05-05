#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, LevelFilter};

use cfg::{Command, Options};

mod cfg;
mod dns;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let config = Options::load();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
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
        Command::Run(ref config) => dns::DnsServer::run(config).await?,
    }

    Ok(())
}
