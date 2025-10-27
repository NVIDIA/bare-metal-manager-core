use clap::Parser;
use mlxconfig_device::cmd::{dispatch_command, Cli};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    dispatch_command(cli)
}
