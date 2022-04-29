// extern crate core;

mod cfg;
mod discovery;

use cfg::{Command, Options};
use log::LevelFilter;

fn main() -> Result<(), color_eyre::Report> {
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
        Command::Discovery(d) => {
            discovery::Discovery::run(config.listen, &d.uuid)?;
        }
    }
    Ok(())
}
