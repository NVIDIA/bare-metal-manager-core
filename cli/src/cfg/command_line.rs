use clap::Parser;

#[derive(Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,

    #[clap(
        short,
        long,
        multiple_values(false),
        require_equals(true),
        default_value = "https://[::1]:1079"
    )]
    pub listen: String,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Run discovery")]
    Discovery(Discovery),
}

#[derive(Parser)]
pub struct Discovery {
    #[clap(short, long, multiple_values(false), require_equals(true))]
    pub uuid: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
