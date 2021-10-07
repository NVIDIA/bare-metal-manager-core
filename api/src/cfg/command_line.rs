use clap::{AppSettings, Clap};

// TODO(ajf): always look at crate root
static DEFAULT_CONFIG_PATH: &str = ".config.toml";
static DEFAULT_DATASTORE: &str = "postgres://carbide_development@localhost";

#[derive(Clap)]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(setting = AppSettings::ColoredHelp)]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences), about = "Increase debug level")]
    pub debug: u8,

    #[clap(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub(crate) enum Command {
    #[clap(about = "Performs database migrations")]
    Migrate(Migrate),

    #[clap(about = "Run the API service")]
    Run(Daemon),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Daemon {
    #[clap(
        short,
        long,
        multiple_values(true),
        require_equals(true),
        about = "List of listening endpoints",
        default_value = "[::]:8080"
    )]
    pub listen: Vec<std::net::SocketAddr>,

    #[clap(long, require_equals(true), default_value = DEFAULT_DATASTORE)]
    pub datastore: String,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Migrate {
    #[clap(long, require_equals(true), default_value = DEFAULT_DATASTORE)]
    pub datastore: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
