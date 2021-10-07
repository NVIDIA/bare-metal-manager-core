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
    pub subcmd: TopLevelSubCommand,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub(crate) enum TopLevelSubCommand {
    #[clap(about = "Performs database migrations")]
    Migrate(Migrate),

    #[clap(about = "Run an Carbide service")]
    Run(Service),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct ApiService {
    #[clap(long, require_equals(true), default_value = DEFAULT_DATASTORE)]
    pub datastore: String,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct DhcpService;

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct IpmiService;

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct DnsService;

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct PxeService;

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum ServiceSubCommand {
    #[clap(about = "Run the API service")]
    Api(ApiService),

    #[clap(about = "Run the DHCP service")]
    Dhcp(DhcpService),

    #[clap(about = "Run the DNS service")]
    Dns(DnsService),

    #[clap(about = "Run the IPMI service")]
    Ipmi(IpmiService),

    #[clap(about = "Run the PXE service")]
    Pxe(PxeService),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct Service {
    #[clap(
        short,
        long,
        multiple_values(true),
        require_equals(true),
        about = "List of listening endpoints",
        default_value = "[::]:8080"
    )]
    pub listen: Vec<std::net::SocketAddr>,

    #[clap(subcommand)]
    pub service: ServiceSubCommand,
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
