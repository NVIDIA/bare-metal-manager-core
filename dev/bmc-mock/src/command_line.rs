use std::{path::PathBuf, str::FromStr};

use clap::Parser;

#[derive(Clone, Parser, Debug)]
pub struct MacRouterPair {
    pub mac_address: String,
    pub targz: std::path::PathBuf,
}

impl From<String> for MacRouterPair {
    fn from(value: String) -> Self {
        let mut parts = value.split(',');
        let mac_address = parts.next().unwrap();
        let targz = parts.next().unwrap();
        let targz = PathBuf::from_str(targz).unwrap();

        MacRouterPair {
            mac_address: mac_address.to_owned(),
            targz,
        }
    }
}

#[derive(Clone, Parser, Debug)]
pub struct Args {
    /// Should manage qemu vm
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    pub use_qemu: bool,

    #[clap(short, long)]
    pub cert_path: Option<String>,

    #[clap(short, long)]
    pub port: Option<u16>,

    #[clap(
        long,
        help = "Path to .tar.gz file of redfish data to output. Create it from libredfish tests/mockups/<vendor>"
    )]
    pub targz: Option<std::path::PathBuf>,

    #[clap(
        long,
        help = "A mac_address and .tar.gz file pair (comma separated).\nThe file is an archive of redfish data when the request is for the specific mac address\nRepeat for different machines"
    )]
    pub mac_router: Option<Vec<MacRouterPair>>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
