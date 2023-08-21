use clap::Parser;

#[derive(Clone, Parser, Debug)]
pub struct Args {
    /// Should manage qemu vm
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    pub use_qemu: bool,

    #[clap(short, long)]
    pub cert_path: Option<String>,

    #[clap(short, long)]
    pub port: Option<u16>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
