extern crate clap;

use clap::Parser;

// TODO(ajf): always look at crate root
static DEFAULT_CONFIG_PATH: &str = ".config.toml";
static DEFAULT_DATASTORE: &str = "postgres://carbide_development@localhost";

#[derive(Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,

    #[clap(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Performs database migrations")]
    Migrate(Migrate),

    #[clap(about = "Run the API service")]
    Run(Daemon),
}

#[derive(Parser)]
pub struct Daemon {
    #[clap(
        short,
        long,
        multiple_values(true),
        require_equals(true),
        default_value = "[::]:1079"
    )]
    pub listen: Vec<std::net::SocketAddr>,

    #[clap(long, require_equals(true), default_value = DEFAULT_DATASTORE)]
    pub datastore: String,
}

#[derive(Parser)]
pub struct Migrate {
    #[clap(long, require_equals(true), default_value = DEFAULT_DATASTORE)]
    pub datastore: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
