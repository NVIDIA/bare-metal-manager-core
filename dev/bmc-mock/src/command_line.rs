use clap::Parser;

#[derive(Clone, Parser, Debug)]
pub struct Args {
    /// Should manage qemu vm
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    pub use_qemu: bool,
}

pub fn parse_args() -> Args {
    Args::parse()
}
