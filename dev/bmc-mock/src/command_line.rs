use std::{path::PathBuf, str::FromStr};

use clap::Parser;

#[derive(Clone, Parser, Debug)]
pub struct IpRouterPair {
    pub ip_address: String,
    pub targz: std::path::PathBuf,
}

impl From<String> for IpRouterPair {
    fn from(value: String) -> Self {
        let mut parts = value.split(',');
        let ip_address = parts.next().unwrap();
        let targz = parts.next().unwrap();
        let targz = PathBuf::from_str(targz).unwrap();

        IpRouterPair {
            ip_address: ip_address.to_owned(),
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
        help = "An ip_address and .tar.gz file pair (comma separated).\nThe file is an archive of redfish data when the request is forwarded to a specific IP address.\nRepeat for different machines"
    )]
    pub ip_router: Option<Vec<IpRouterPair>>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
