extern crate clap;

use clap::Parser;

#[derive(Parser)]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Start DNS Service")]
    Run(Daemon),
}

#[derive(Parser)]
pub struct Daemon {
    #[clap(
    short,
    long,
    multiple_values(true),
    require_equals(true),
    default_value = "[::]:53"
    )
    ]

    pub listen: Vec<std::net::SocketAddr>,

    #[clap(
    short,
    long,
    default_value = "http://[::1]:1079"
    )]
    pub carbide_url: String,

}

impl Options {
    pub fn load() -> Self { Self::parse() }
}
